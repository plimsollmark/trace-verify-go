// Package chain verifies a delegation chain of TRACE records: from a leaf, through each
// record's delegation.parent_record_hash, to a root with no delegation block.
//
// The link digest is normative (spec 3.1.3): SHA-256 or SHA-384 over the RFC 8785 form
// of the complete parent record, signature included. The rules for judging a chain are
// not yet normative; they are the ten of trace-spec docs/rfcs/a2a-delegation-profile.md,
// a draft proposal, each an entry in Rules with the proposal's code and classification.
package chain

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/record"
)

// Classification is the verdict on a chain. Provenance outranks authorization, and an
// unreadable link is not a finding against the chain (the proposal, sections 3 and 4.3).
type Classification string

const (
	Verified             Classification = "verified"
	ProvenanceInvalid    Classification = "provenance-invalid"
	AuthorizationInvalid Classification = "authorization-invalid"
	Unverifiable         Classification = "unverifiable"
)

// rank orders the classes for reporting: the first present wins.
var rank = []Classification{ProvenanceInvalid, AuthorizationInvalid, Unverifiable}

// Credential is one entry of the out-of-band delegation credential registry.
type Credential struct {
	Issuer, Holder      string
	NotBefore, NotAfter int64
}

// Context is what a verifier knows that no record can tell it (the proposal, section 2).
type Context struct {
	Leaf             string   // digest of the record under appraisal
	TrustedRootKeys  []string // RFC 7638 thumbprints
	Credentials      map[string]Credential
	DataClassLattice []string // least sensitive first
	MaxDepth         int      // links the verifier will follow
	SupportedDigests []string // "sha256", "sha384"
}

// Finding is one rule's failure on one record or link.
type Finding struct {
	Code   string
	Class  Classification
	Detail string
}

// Result is the chain's classification, the codes found (each once, in walk order), and
// the findings behind them.
type Result struct {
	Classification Classification
	Codes          []string
	Findings       []Finding
	Walked         int // records visited, leaf included
}

// Scope says where a rule is applied during the walk.
type Scope int

const (
	OnRecord Scope = iota // every record the walk reaches
	OnRoot                // the record with no delegation block
	OnLink                // a delegation link, before its parent is used
	OnHop                 // a resolved hop: the child, its parent, the credential
)

// Rule is one check.
type Rule struct {
	Code    string
	Class   Classification
	Scope   Scope
	Section string
	// Check returns "" if the rule holds, or a detail describing the failure.
	Check func(c *Context, h *Hop) string
}

// Hop is what the rules see. For OnRecord and OnRoot rules only Child is set.
type Hop struct {
	Child, Parent *jcs.Object
	Link          string // the child's parent_record_hash
	Depth         int    // 1 for the leaf's link
	Credential    string // the child's credential_id
}

// Verify walks the chain from ctx.Leaf through records.
func Verify(records [][]byte, ctx Context) Result {
	return VerifyWith(Rules, records, ctx)
}

// VerifyWith runs the given rules instead of the registry, for the mutation check.
func VerifyWith(rules []Rule, records [][]byte, ctx Context) Result {
	var res Result
	add := func(code string, class Classification, detail string) {
		res.Findings = append(res.Findings, Finding{code, class, detail})
		if !slices.Contains(res.Codes, code) {
			res.Codes = append(res.Codes, code)
		}
	}
	index := map[string]*jcs.Object{}
	for i, b := range records {
		v, err := jcs.Parse(b)
		o, isObj := v.(*jcs.Object)
		if err != nil || !isObj {
			add("record_unreadable", ProvenanceInvalid, fmt.Sprintf("record %d does not parse as an object: %v", i, err))
			continue
		}
		for _, alg := range ctx.SupportedDigests {
			if d, err := Digest(alg, o); err == nil {
				index[d] = o
			}
		}
	}
	cur := index[ctx.Leaf]
	if cur == nil {
		add("leaf_not_found", ProvenanceInvalid, "no record in the set has the leaf digest "+ctx.Leaf)
	}
	apply := func(scope Scope, h *Hop) (failed bool) {
		for _, r := range rules {
			if r.Scope != scope {
				continue
			}
			if d := r.Check(&ctx, h); d != "" {
				add(r.Code, r.Class, d)
				failed = true
			}
		}
		return failed
	}
	for depth := 1; cur != nil; depth++ {
		res.Walked++
		apply(OnRecord, &Hop{Child: cur})
		link, cred, isRoot := delegation(cur)
		if isRoot {
			apply(OnRoot, &Hop{Child: cur})
			break
		}
		h := &Hop{Child: cur, Link: link, Depth: depth, Credential: cred}
		if alg, _, ok := strings.Cut(link, ":"); ok && slices.Contains(ctx.SupportedDigests, alg) {
			h.Parent = index[link]
		}
		// A link rule that fails ends the walk: past it there is no established
		// parent for the next hop's rules to be judged against.
		if apply(OnLink, h) || h.Parent == nil || depth > len(records) {
			break
		}
		apply(OnHop, h)
		cur = h.Parent
	}
	res.Classification = Verified
	for _, c := range rank {
		if slices.ContainsFunc(res.Findings, func(f Finding) bool { return f.Class == c }) {
			res.Classification = c
			break
		}
	}
	return res
}

// Digest is a record's link digest (spec 3.1.3): alg + ":" + hex of the digest of the
// RFC 8785 form of the complete record, signature included.
func Digest(alg string, rec *jcs.Object) (string, error) {
	b, err := jcs.Encode(rec)
	if err != nil {
		return "", err
	}
	switch alg {
	case "sha256":
		d := sha256.Sum256(b)
		return "sha256:" + hex.EncodeToString(d[:]), nil
	case "sha384":
		d := sha512.Sum384(b)
		return "sha384:" + hex.EncodeToString(d[:]), nil
	}
	return "", fmt.Errorf("chain: unsupported digest algorithm %q", alg)
}

// delegation reads a record's link. A record whose delegation is absent or null is a
// root.
func delegation(rec *jcs.Object) (link, credential string, root bool) {
	v, ok := rec.Get("delegation")
	d, isObj := v.(*jcs.Object)
	if !ok || !isObj {
		return "", "", true
	}
	l, _ := d.Get("parent_record_hash")
	c, _ := d.Get("credential_id")
	link, _ = l.(string)
	credential, _ = c.(string)
	return link, credential, false
}

func str(o *jcs.Object, name string) string {
	v, _ := o.Get(name)
	s, _ := v.(string)
	return s
}

func integer(o *jcs.Object, name string) (int64, bool) {
	v, _ := o.Get(name)
	n, ok := v.(jcs.Number)
	return int64(n.Float), ok && float64(int64(n.Float)) == n.Float
}

// Rules is the registry: the proposal's D-1 to D-10.
var Rules = []Rule{
	{Code: "record_signature_invalid", Class: ProvenanceInvalid, Scope: OnRecord, Section: "D-1",
		Check: func(_ *Context, h *Hop) string {
			// Every record on the walk, not only the leaf: an ancestor with an invalid
			// signature is reachable if it was built that way before its child signed.
			if _, err := record.CheckBinding(h.Child); err != nil {
				return err.Error()
			}
			return ""
		}},
	{Code: "root_key_untrusted", Class: ProvenanceInvalid, Scope: OnRoot, Section: "D-2",
		Check: func(c *Context, h *Hop) string {
			k, err := record.CheckBinding(h.Child)
			if err != nil {
				return "the root's key is unusable" // D-1 reports the signature itself
			}
			if !slices.Contains(c.TrustedRootKeys, k.Thumbprint()) {
				return "the root's cnf key " + k.Thumbprint() + " is not a trusted root key"
			}
			return ""
		}},
	{Code: "depth_exceeded", Class: AuthorizationInvalid, Scope: OnLink, Section: "D-4",
		Check: func(c *Context, h *Hop) string {
			if h.Depth > c.MaxDepth {
				return fmt.Sprintf("link %d is past the bound of %d", h.Depth, c.MaxDepth)
			}
			return ""
		}},
	{Code: "digest_algorithm_unsupported", Class: Unverifiable, Scope: OnLink, Section: "D-10",
		Check: func(c *Context, h *Hop) string {
			if alg, _, _ := strings.Cut(h.Link, ":"); !slices.Contains(c.SupportedDigests, alg) {
				return fmt.Sprintf("link %d names %q, which this verifier does not compute", h.Depth, alg)
			}
			return ""
		}},
	{Code: "parent_not_found", Class: ProvenanceInvalid, Scope: OnLink, Section: "D-3",
		Check: func(c *Context, h *Hop) string {
			// Guarded on algorithm support, so this and D-10 never fire for one link.
			if alg, _, _ := strings.Cut(h.Link, ":"); !slices.Contains(c.SupportedDigests, alg) {
				return ""
			}
			if h.Parent == nil {
				return fmt.Sprintf("no record in the set has digest %s", h.Link)
			}
			return ""
		}},
	{Code: "credential_unknown", Class: AuthorizationInvalid, Scope: OnHop, Section: "D-5",
		Check: func(c *Context, h *Hop) string {
			if _, ok := c.Credentials[h.Credential]; !ok { // exact octet string, no folding
				return fmt.Sprintf("credential %q is not in the registry", h.Credential)
			}
			return ""
		}},
	{Code: "credential_issuer_mismatch", Class: AuthorizationInvalid, Scope: OnHop, Section: "D-6",
		Check: func(c *Context, h *Hop) string {
			cr, ok := c.Credentials[h.Credential]
			if ok && cr.Issuer != str(h.Parent, "subject") {
				return fmt.Sprintf("credential issuer %q is not the parent's subject %q", cr.Issuer, str(h.Parent, "subject"))
			}
			return ""
		}},
	{Code: "credential_holder_mismatch", Class: AuthorizationInvalid, Scope: OnHop, Section: "D-7",
		Check: func(c *Context, h *Hop) string {
			cr, ok := c.Credentials[h.Credential]
			if ok && cr.Holder != str(h.Child, "subject") {
				return fmt.Sprintf("credential holder %q is not this record's subject %q", cr.Holder, str(h.Child, "subject"))
			}
			return ""
		}},
	{Code: "credential_window", Class: AuthorizationInvalid, Scope: OnHop, Section: "D-8",
		Check: func(c *Context, h *Hop) string {
			// Judged against the hop's own iat, never the verifier's clock (section 4.3).
			cr, ok := c.Credentials[h.Credential]
			if !ok {
				return ""
			}
			iat, isInt := integer(h.Child, "iat")
			if !isInt || iat < cr.NotBefore || iat > cr.NotAfter {
				return fmt.Sprintf("iat %d is outside the credential's window %d to %d", iat, cr.NotBefore, cr.NotAfter)
			}
			return ""
		}},
	{Code: "data_class_widened", Class: AuthorizationInvalid, Scope: OnHop, Section: "D-9",
		Check: func(c *Context, h *Hop) string {
			child, parent := str(h.Child, "data_class"), str(h.Parent, "data_class")
			ci, pi := slices.Index(c.DataClassLattice, child), slices.Index(c.DataClassLattice, parent)
			if ci < 0 || pi < 0 {
				return fmt.Sprintf("data_class %q or %q is not in the supplied lattice, so narrowing cannot be shown", child, parent)
			}
			if ci > pi {
				return fmt.Sprintf("data_class %q is more sensitive than the parent's %q", child, parent)
			}
			return ""
		}},
}
