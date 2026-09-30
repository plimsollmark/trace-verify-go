// Package schema evaluates a JSON Schema (draft 2020-12) restricted to the keywords
// TRACE's schema/trace-claim.json uses. The schema stays data: this package carries no
// TRACE field rules of its own.
//
// Compile refuses a schema that uses any keyword outside the supported set, so a new
// revision that adds one fails loudly instead of having that keyword silently ignored.
//
// One deliberate difference from 2020-12's default: "format": "uri" is an assertion
// here (RFC 3986 absolute URI), not an annotation. TRACE's suite reads it that way
// (TR-APR-002: "the schema asks for format: uri, and a reader cannot dereference a name
// with no scheme"), and it is the only format the schema uses.
package schema

import (
	"bytes"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/plimsollmark/trace-verify-go/internal/uri"
	"github.com/plimsollmark/trace-verify-go/jcs"
)

// Supported assertion and applicator keywords.
var keywords = []string{
	"$ref", "type", "enum", "const", "required", "properties", "additionalProperties",
	"pattern", "minLength", "minimum", "maximum", "items", "allOf", "anyOf", "not",
	"if", "then", "else", "format",
}

// Annotation keywords, accepted and ignored.
var annotations = []string{"$schema", "$id", "$defs", "$comment", "description", "title", "default", "examples"}

// Schema is a compiled schema.
type Schema struct {
	root     any
	patterns map[string]*regexp.Regexp
}

// Violation is one failed assertion.
type Violation struct {
	Path    string // instance location, e.g. "$.runtime.platform"
	Keyword string
	Message string
}

func (v Violation) String() string { return v.Path + ": " + v.Keyword + ": " + v.Message }

// Compile parses and checks a schema document.
func Compile(doc []byte) (*Schema, error) {
	root, err := jcs.Parse(doc)
	if err != nil {
		return nil, err
	}
	s := &Schema{root: root, patterns: map[string]*regexp.Regexp{}}
	if err := s.check(root, "#"); err != nil {
		return nil, err
	}
	return s, nil
}

// check walks every subschema, refusing unknown keywords, compiling patterns, and
// resolving every $ref once so a dangling one fails at compile time.
func (s *Schema) check(node any, at string) error {
	if _, ok := node.(bool); ok {
		return nil
	}
	o, ok := node.(*jcs.Object)
	if !ok {
		return fmt.Errorf("schema: %s is not a schema", at)
	}
	for _, m := range o.Members {
		sub := at + "/" + m.Name
		switch {
		case slices.Contains(annotations, m.Name):
			if m.Name == "$defs" {
				defs, ok := m.Value.(*jcs.Object)
				if !ok {
					return fmt.Errorf("schema: %s is not an object", sub)
				}
				for _, d := range defs.Members {
					if err := s.check(d.Value, sub+"/"+d.Name); err != nil {
						return err
					}
				}
			}
		case !slices.Contains(keywords, m.Name):
			return fmt.Errorf("schema: unsupported keyword %s", sub)
		case m.Name == "properties":
			props, ok := m.Value.(*jcs.Object)
			if !ok {
				return fmt.Errorf("schema: %s is not an object", sub)
			}
			for _, p := range props.Members {
				if err := s.check(p.Value, sub+"/"+p.Name); err != nil {
					return err
				}
			}
		case m.Name == "allOf" || m.Name == "anyOf":
			list, ok := m.Value.([]any)
			if !ok || len(list) == 0 {
				return fmt.Errorf("schema: %s is not a nonempty array", sub)
			}
			for i, e := range list {
				if err := s.check(e, fmt.Sprintf("%s/%d", sub, i)); err != nil {
					return err
				}
			}
		case slices.Contains([]string{"additionalProperties", "items", "not", "if", "then", "else"}, m.Name):
			if err := s.check(m.Value, sub); err != nil {
				return err
			}
		case m.Name == "pattern":
			p, ok := m.Value.(string)
			if !ok {
				return fmt.Errorf("schema: %s is not a string", sub)
			}
			// ECMA-262 and RE2 agree on the constructs a pattern without lookaround or
			// backreferences uses; one RE2 cannot compile is refused here.
			re, err := regexp.Compile(p)
			if err != nil {
				return fmt.Errorf("schema: %s: %v", sub, err)
			}
			s.patterns[p] = re
		case m.Name == "format":
			if m.Value != "uri" {
				return fmt.Errorf("schema: unsupported format %v at %s", m.Value, sub)
			}
		case m.Name == "$ref":
			ref, ok := m.Value.(string)
			if !ok {
				return fmt.Errorf("schema: %s is not a string", sub)
			}
			if _, err := s.resolve(ref); err != nil {
				return err
			}
		}
	}
	return nil
}

// resolve follows a same-document JSON Pointer reference ("#/$defs/name").
func (s *Schema) resolve(ref string) (any, error) {
	if !strings.HasPrefix(ref, "#") {
		return nil, fmt.Errorf("schema: only same-document references are supported: %q", ref)
	}
	node := s.root
	for _, tok := range strings.Split(strings.TrimPrefix(ref, "#"), "/")[1:] {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		o, ok := node.(*jcs.Object)
		if !ok {
			return nil, fmt.Errorf("schema: reference %q does not resolve", ref)
		}
		if node, ok = o.Get(tok); !ok {
			return nil, fmt.Errorf("schema: reference %q does not resolve", ref)
		}
	}
	return node, nil
}

// Validate returns every violation of the schema by a parsed instance.
func (s *Schema) Validate(instance any) []Violation {
	return s.eval(s.root, instance, "$", 0)
}

func (s *Schema) valid(node, inst any, depth int) bool {
	return len(s.eval(node, inst, "$", depth)) == 0
}

func (s *Schema) eval(node, inst any, path string, depth int) []Violation {
	if depth > 64 {
		return []Violation{{path, "$ref", "reference depth exceeded"}}
	}
	if b, ok := node.(bool); ok {
		if !b {
			return []Violation{{path, "false", "no value is allowed here"}}
		}
		return nil
	}
	o := node.(*jcs.Object)
	var out []Violation
	add := func(kw, f string, a ...any) { out = append(out, Violation{path, kw, fmt.Sprintf(f, a...)}) }
	for _, m := range o.Members {
		switch m.Name {
		case "$ref":
			target, _ := s.resolve(m.Value.(string)) // resolved at compile time
			out = append(out, s.eval(target, inst, path, depth+1)...)
		case "type":
			var names []string
			switch t := m.Value.(type) {
			case string:
				names = []string{t}
			case []any:
				for _, e := range t {
					if str, ok := e.(string); ok {
						names = append(names, str)
					}
				}
			}
			if !slices.ContainsFunc(names, func(n string) bool { return hasType(inst, n) }) {
				add("type", "%s is not %s", typeName(inst), strings.Join(names, " or "))
			}
		case "enum":
			if !slices.ContainsFunc(m.Value.([]any), func(e any) bool { return equal(e, inst) }) {
				add("enum", "value is not one of the enumerated values")
			}
		case "const":
			if !equal(m.Value, inst) {
				add("const", "value is not %s", show(m.Value))
			}
		case "required":
			if io, ok := inst.(*jcs.Object); ok {
				for _, r := range m.Value.([]any) {
					if _, has := io.Get(r.(string)); !has {
						add("required", "%q is missing", r)
					}
				}
			}
		case "properties":
			if io, ok := inst.(*jcs.Object); ok {
				for _, p := range m.Value.(*jcs.Object).Members {
					if v, has := io.Get(p.Name); has {
						out = append(out, s.eval(p.Value, v, path+"."+p.Name, depth)...)
					}
				}
			}
		case "additionalProperties":
			if io, ok := inst.(*jcs.Object); ok {
				props, _ := o.Get("properties")
				po, _ := props.(*jcs.Object)
				for _, im := range io.Members {
					if _, declared := po.Get(im.Name); !declared {
						out = append(out, s.eval(m.Value, im.Value, path+"."+im.Name, depth)...)
					}
				}
			}
		case "items":
			if arr, ok := inst.([]any); ok {
				for i, e := range arr {
					out = append(out, s.eval(m.Value, e, fmt.Sprintf("%s[%d]", path, i), depth)...)
				}
			}
		case "pattern":
			if str, ok := inst.(string); ok && !s.patterns[m.Value.(string)].MatchString(str) {
				add("pattern", "%q does not match %s", str, m.Value)
			}
		case "minLength":
			if str, ok := inst.(string); ok && float64(utf8.RuneCountInString(str)) < m.Value.(jcs.Number).Float {
				add("minLength", "shorter than %s characters", m.Value.(jcs.Number).Literal)
			}
		case "minimum":
			if n, ok := inst.(jcs.Number); ok && n.Float < m.Value.(jcs.Number).Float {
				add("minimum", "%s is below %s", n.Literal, m.Value.(jcs.Number).Literal)
			}
		case "maximum":
			if n, ok := inst.(jcs.Number); ok && n.Float > m.Value.(jcs.Number).Float {
				add("maximum", "%s is above %s", n.Literal, m.Value.(jcs.Number).Literal)
			}
		case "format":
			if str, ok := inst.(string); ok {
				if err := uri.Absolute(str); err != nil {
					add("format", "%v", err)
				}
			}
		case "allOf":
			for _, sub := range m.Value.([]any) {
				out = append(out, s.eval(sub, inst, path, depth+1)...)
			}
		case "anyOf":
			if !slices.ContainsFunc(m.Value.([]any), func(sub any) bool { return s.valid(sub, inst, depth+1) }) {
				add("anyOf", "value matches none of the alternatives")
			}
		case "not":
			if s.valid(m.Value, inst, depth+1) {
				add("not", "value matches a schema it must not match")
			}
		case "if":
			if s.valid(m.Value, inst, depth+1) {
				if then, ok := o.Get("then"); ok {
					out = append(out, s.eval(then, inst, path, depth+1)...)
				}
			} else if els, ok := o.Get("else"); ok {
				out = append(out, s.eval(els, inst, path, depth+1)...)
			}
		}
	}
	return out
}

func hasType(v any, name string) bool {
	switch name {
	case "null":
		return v == nil
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "object":
		_, ok := v.(*jcs.Object)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "number":
		_, ok := v.(jcs.Number)
		return ok
	case "integer": // 2020-12: a number with a zero fractional part
		n, ok := v.(jcs.Number)
		return ok && n.Float == math.Trunc(n.Float)
	}
	return false
}

func typeName(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case *jcs.Object:
		return "object"
	case []any:
		return "array"
	}
	return "number"
}

// equal is JSON equality: two values are equal if their canonical forms are, which
// makes 1 and 1.0 equal and member order irrelevant, as 2020-12 requires.
func equal(a, b any) bool {
	ea, err1 := jcs.Encode(a)
	eb, err2 := jcs.Encode(b)
	return err1 == nil && err2 == nil && bytes.Equal(ea, eb)
}

func show(v any) string {
	b, err := jcs.Encode(v)
	if err != nil {
		return "?"
	}
	return string(b)
}
