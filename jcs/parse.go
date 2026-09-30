// Package jcs parses JSON strictly and serializes it in the RFC 8785 canonical form
// (the JSON Canonicalization Scheme) that TRACE signs and digests (spec section 3.2.2).
//
// The parser refuses what a general-purpose JSON library quietly repairs, because each
// repair lets two different byte strings stand for one signed object: a duplicated
// member name (RFC 8785 requires I-JSON, RFC 7493 section 2.3), a lone surrogate (RFC
// 8785 section 3.2.2.2), invalid UTF-8 (RFC 8259 section 8.1), and a number with no
// IEEE 754 double (RFC 8785 section 3.2.2.3).
package jcs

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// A parsed value is one of: nil, bool, string, Number, []any, *Object.

// Object is a JSON object with its members in input order. Names are unique.
type Object struct {
	Members []Member
}

// Member is one name and value of an Object.
type Member struct {
	Name  string
	Value any
}

// Get returns the value of the named member.
func (o *Object) Get(name string) (any, bool) {
	for _, m := range o.Members {
		if m.Name == name {
			return m.Value, true
		}
	}
	return nil, false
}

// Without returns a shallow copy of o with the named member removed.
func (o *Object) Without(name string) *Object {
	c := &Object{Members: make([]Member, 0, len(o.Members))}
	for _, m := range o.Members {
		if m.Name != name {
			c.Members = append(c.Members, m)
		}
	}
	return c
}

// Number is a JSON number: the literal as written and the IEEE 754 double it denotes.
type Number struct {
	Literal string
	Float   float64
}

// MaxDepth bounds nesting, so a hostile document cannot exhaust the stack.
const MaxDepth = 512

// Errors a caller may need to tell apart. Every parse error wraps exactly one of them.
var (
	ErrSyntax        = errors.New("jcs: invalid JSON")
	ErrDuplicateName = errors.New("jcs: duplicate member name")
	ErrLoneSurrogate = errors.New("jcs: lone surrogate")
	ErrInvalidUTF8   = errors.New("jcs: invalid UTF-8")
	ErrNonFinite     = errors.New("jcs: number has no finite IEEE 754 double")
	ErrTooDeep       = errors.New("jcs: nesting deeper than MaxDepth")
)

// Parse parses exactly one JSON value, surrounded only by JSON whitespace.
func Parse(data []byte) (any, error) {
	p := &parser{data: data}
	p.space()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.space()
	if p.pos != len(p.data) {
		return nil, p.fail(ErrSyntax, "data after the value")
	}
	return v, nil
}

type parser struct {
	data []byte
	pos  int
}

func (p *parser) fail(kind error, msg string) error {
	return fmt.Errorf("%w at byte %d: %s", kind, p.pos, msg)
}

// space skips the four whitespace characters RFC 8259 section 2 allows.
func (p *parser) space() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (any, error) {
	if depth > MaxDepth {
		return nil, p.fail(ErrTooDeep, "")
	}
	if p.pos >= len(p.data) {
		return nil, p.fail(ErrSyntax, "unexpected end of input")
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		return p.string()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	case p.literal("true"):
		return true, nil
	case p.literal("false"):
		return false, nil
	case p.literal("null"):
		return nil, nil
	default:
		return nil, p.fail(ErrSyntax, fmt.Sprintf("unexpected byte %q", c))
	}
}

func (p *parser) literal(word string) bool {
	if len(p.data)-p.pos >= len(word) && string(p.data[p.pos:p.pos+len(word)]) == word {
		p.pos += len(word)
		return true
	}
	return false
}

func (p *parser) object(depth int) (any, error) {
	p.pos++ // '{'
	o := &Object{}
	seen := map[string]struct{}{}
	p.space()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return o, nil
	}
	for {
		p.space()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, p.fail(ErrSyntax, "expected a member name")
		}
		start := p.pos
		name, err := p.string()
		if err != nil {
			return nil, err
		}
		// Names compare after unescaping: "a" and "\u0061" are the same name.
		if _, dup := seen[name]; dup {
			p.pos = start
			return nil, p.fail(ErrDuplicateName, strconv.Quote(name))
		}
		seen[name] = struct{}{}
		p.space()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, p.fail(ErrSyntax, "expected ':'")
		}
		p.pos++
		p.space()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		o.Members = append(o.Members, Member{Name: name, Value: v})
		p.space()
		if p.pos >= len(p.data) {
			return nil, p.fail(ErrSyntax, "unterminated object")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return o, nil
		default:
			return nil, p.fail(ErrSyntax, "expected ',' or '}'")
		}
	}
}

func (p *parser) array(depth int) (any, error) {
	p.pos++ // '['
	a := []any{}
	p.space()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return a, nil
	}
	for {
		p.space()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		a = append(a, v)
		p.space()
		if p.pos >= len(p.data) {
			return nil, p.fail(ErrSyntax, "unterminated array")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return a, nil
		default:
			return nil, p.fail(ErrSyntax, "expected ',' or ']'")
		}
	}
}

// string decodes a JSON string (RFC 8259 section 7). Surrogate escapes must pair.
func (p *parser) string() (string, error) {
	p.pos++ // opening quote
	var out []byte
	for {
		if p.pos >= len(p.data) {
			return "", p.fail(ErrSyntax, "unterminated string")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.pos++
			return string(out), nil
		case c < 0x20:
			return "", p.fail(ErrSyntax, "unescaped control character in string")
		case c == '\\':
			r, err := p.escape()
			if err != nil {
				return "", err
			}
			out = utf8.AppendRune(out, r)
		case c < utf8.RuneSelf:
			out = append(out, c)
			p.pos++
		default:
			// utf8.DecodeRune rejects overlong forms and encoded surrogates.
			r, size := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && size <= 1 {
				return "", p.fail(ErrInvalidUTF8, "")
			}
			out = append(out, p.data[p.pos:p.pos+size]...)
			p.pos += size
		}
	}
}

func (p *parser) escape() (rune, error) {
	p.pos++ // backslash
	if p.pos >= len(p.data) {
		return 0, p.fail(ErrSyntax, "unterminated escape")
	}
	c := p.data[p.pos]
	p.pos++
	switch c {
	case '"', '\\', '/':
		return rune(c), nil
	case 'b':
		return '\b', nil
	case 'f':
		return '\f', nil
	case 'n':
		return '\n', nil
	case 'r':
		return '\r', nil
	case 't':
		return '\t', nil
	case 'u':
	default:
		p.pos--
		return 0, p.fail(ErrSyntax, fmt.Sprintf("invalid escape \\%c", c))
	}
	u, err := p.hex4()
	if err != nil {
		return 0, err
	}
	switch {
	case utf16.IsSurrogate(u) && u < 0xDC00: // high surrogate: a low one must follow
		if len(p.data)-p.pos < 6 || p.data[p.pos] != '\\' || p.data[p.pos+1] != 'u' {
			return 0, p.fail(ErrLoneSurrogate, fmt.Sprintf("\\u%04x not followed by a low surrogate", u))
		}
		p.pos += 2
		lo, err := p.hex4()
		if err != nil {
			return 0, err
		}
		if lo < 0xDC00 || lo > 0xDFFF {
			return 0, p.fail(ErrLoneSurrogate, fmt.Sprintf("\\u%04x followed by \\u%04x", u, lo))
		}
		return utf16.DecodeRune(u, lo), nil
	case utf16.IsSurrogate(u): // low surrogate with no high one before it
		return 0, p.fail(ErrLoneSurrogate, fmt.Sprintf("\\u%04x", u))
	}
	return u, nil
}

func (p *parser) hex4() (rune, error) {
	if len(p.data)-p.pos < 4 {
		return 0, p.fail(ErrSyntax, "short \\u escape")
	}
	var r rune
	for _, c := range p.data[p.pos : p.pos+4] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			r |= rune(c - 'A' + 10)
		default:
			return 0, p.fail(ErrSyntax, "invalid hex digit in \\u escape")
		}
	}
	p.pos += 4
	return r, nil
}

// number scans the RFC 8259 section 6 grammar:
// -? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?
func (p *parser) number() (any, error) {
	start := p.pos
	digits := func() int {
		n := 0
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
			n++
		}
		return n
	}
	if p.data[p.pos] == '-' {
		p.pos++
	}
	switch {
	case p.pos < len(p.data) && p.data[p.pos] == '0':
		p.pos++
	case digits() == 0:
		return nil, p.fail(ErrSyntax, "number without digits")
	}
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		p.pos++
		if digits() == 0 {
			return nil, p.fail(ErrSyntax, "no digits after the decimal point")
		}
	}
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if digits() == 0 {
			return nil, p.fail(ErrSyntax, "no digits in the exponent")
		}
	}
	lit := string(p.data[start:p.pos])
	f, err := strconv.ParseFloat(lit, 64)
	if math.IsInf(f, 0) {
		p.pos = start
		return nil, p.fail(ErrNonFinite, lit)
	}
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		p.pos = start
		return nil, p.fail(ErrSyntax, err.Error())
	}
	return Number{Literal: lit, Float: f}, nil
}
