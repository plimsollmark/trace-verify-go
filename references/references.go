// Package references checks what a record's references entry points at (spec 3.1.2),
// for the two relations whose referenced object TRACE describes: condition-appraisal
// (docs/references-registry.md) and approval-outcome as a CHAP review decision
// (docs/crosswalks/chap-review-decisions.md).
//
// Nothing here reaches the record. Under 3.1.2 rule 3 a record verifies the same whether
// its reference resolves or not, and a resolved object is not attested evidence. What a
// relying party learns is bounded to the object: that the resolved bytes are the cited
// bytes, and whatever the object's own integrity check establishes.
package references

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/jwk"
)

// Findings is what the steps established; a nil field was not checked.
type Findings struct {
	Resolves      *bool
	DigestMatches *bool
	// condition-appraisal
	KeyConfigured     *bool
	SignatureVerifies *bool
	Outcome           string // the issuer's finding, reported and never promoted
	// approval-outcome (CHAP)
	ChainReplays *bool
	Decision     string
}

// Input is one reference with the caller's copy of what it points at.
type Input struct {
	Reference *jcs.Object
	// condition-appraisal: the resolver's retained objects and the issuer keys the
	// relying party holds, by RFC 7638 thumbprint.
	Store      map[string]*jcs.Object
	IssuerKeys map[string]*jwk.Key
	// approval-outcome: the exported CHAP log.
	Log       []*jcs.Object
	ChainHead string
	// AcceptOverride treats decide.override as an approval (the crosswalk's step 5
	// leaves it to the relying party).
	AcceptOverride bool

	target *jcs.Object
}

// Step is one check.
type Step struct {
	ID, Rel, Section string
	Run              func(*Input, *Findings)
}

func yes(b bool) *bool { return &b }

// Steps is the registry.
var Steps = []Step{
	{ID: "appraisal_resolves", Rel: "condition-appraisal", Section: "references-registry: resolve id",
		Run: func(in *Input, f *Findings) {
			in.target = in.Store[str(in.Reference, "id")]
			f.Resolves = yes(in.target != nil)
			// What the object says is reported once it resolves; whether its issuer said
			// it is the signature step's question (vector 05 reports "pass" unverified).
			if o, ok := in.target.Get("outcome"); ok {
				oo, _ := o.(*jcs.Object)
				f.Outcome = str(oo, "status")
			}
		}},
	{ID: "appraisal_digest", Rel: "condition-appraisal", Section: "3.1.2 digest: SHA-256 of the RFC 8785 form of the object as retained",
		Run: func(in *Input, f *Findings) {
			if in.target != nil {
				f.DigestMatches = matches(in.Reference, in.target)
			}
		}},
	{ID: "appraisal_issuer_key", Rel: "condition-appraisal", Section: "references-registry: an issuer key the relying party holds",
		Run: func(in *Input, f *Findings) {
			if in.target != nil {
				f.KeyConfigured = yes(in.IssuerKeys[str(in.target, "issuer_key_id")] != nil)
			}
		}},
	{ID: "appraisal_signature", Rel: "condition-appraisal", Section: "the object's signature: Ed25519 over RFC 8785 without signature",
		Run: func(in *Input, f *Findings) {
			if in.target == nil {
				return
			}
			k := in.IssuerKeys[str(in.target, "issuer_key_id")]
			if k == nil {
				return // not checked: unverified, not invalid
			}
			sig, err := jwk.B64.DecodeString(str(in.target, "signature"))
			pre, err2 := jcs.Encode(in.target.Without("signature"))
			f.SignatureVerifies = yes(err == nil && err2 == nil && k.Verify(pre, sig) == nil)
		}},
	{ID: "approval_resolves", Rel: "approval-outcome", Section: "crosswalk step 2: resolve id to a log entry",
		Run: func(in *Input, f *Findings) {
			// The id names the entry's seq as "audit/<seq>": the vectors' convention,
			// which the crosswalk does not state (REPORT.md finding 13).
			seq, ok := strings.CutPrefix(str(in.Reference, "id"), "audit/")
			n, err := strconv.Atoi(seq)
			for _, e := range in.Log {
				// The log comes from the resolver, not the signed record, so a seq of the
				// wrong type is a non-match, never a crash (3.1.2 rule 3: a reference
				// never rejects the record).
				if s, found := e.Get("seq"); ok && err == nil && found {
					if num, isNum := s.(jcs.Number); isNum && num.Float == float64(n) {
						in.target = e
					}
				}
			}
			f.Resolves = yes(in.target != nil)
		}},
	{ID: "approval_digest", Rel: "approval-outcome", Section: "crosswalk step 3: RFC 8785 SHA-256 of the entry's envelope",
		Run: func(in *Input, f *Findings) {
			if in.target != nil {
				env, _ := in.target.Get("envelope")
				f.DigestMatches = matches(in.Reference, env)
			}
		}},
	{ID: "approval_chain", Rel: "approval-outcome", Section: "crosswalk step 4: replay the chain and compare the head",
		Run: func(in *Input, f *Findings) {
			f.ChainReplays = yes(ReplayChain(in.Log) == in.ChainHead)
		}},
	{ID: "approval_decision", Rel: "approval-outcome", Section: "crosswalk step 5: method is decide.approve",
		Run: func(in *Input, f *Findings) {
			if in.target == nil {
				return
			}
			env, _ := in.target.Get("envelope")
			o, _ := env.(*jcs.Object) // absent or not an object: no method, so not an approval
			f.Decision = str(o, "method")
		}},
}

// Check runs the registry's steps for the reference's relation and returns the findings
// and the verdict.
func Check(in Input) (Findings, string) { return CheckWith(Steps, in) }

// CheckWith runs the given steps instead, for the mutation check.
func CheckWith(steps []Step, in Input) (Findings, string) {
	var f Findings
	rel := str(in.Reference, "rel")
	for _, s := range steps {
		if s.Rel == rel {
			s.Run(&in, &f)
		}
	}
	return f, verdict(rel, f, in.AcceptOverride)
}

func verdict(rel string, f Findings, acceptOverride bool) string {
	no := func(b *bool) bool { return b != nil && !*b }
	switch rel {
	case "condition-appraisal":
		switch {
		case f.Resolves == nil || !*f.Resolves:
			return "appraisal-unconfirmed"
		case no(f.DigestMatches) || no(f.SignatureVerifies):
			return "appraisal-contradicted"
		case no(f.KeyConfigured):
			return "appraisal-unverified"
		}
		return "appraisal-confirmed"
	case "approval-outcome":
		switch {
		case f.Resolves == nil || !*f.Resolves:
			return "approval-unconfirmed"
		case no(f.DigestMatches) || no(f.ChainReplays):
			return "approval-contradicted"
		case f.Decision != "decide.approve" && !(acceptOverride && f.Decision == "decide.override"):
			return "not-an-approval"
		}
		return "approval-confirmed"
	}
	return "relation-not-checked"
}

// ReplayChain recomputes a CHAP audit-scitt/1.0 chain head: each link is
// sha256(JCS(envelope) || prev_hash). prev_hash is concatenated as the ASCII of its
// "sha256:<hex>" form; the crosswalk's formula does not say, and only the exported
// head decides it (REPORT.md finding 13). An entry whose prev_hash is not the previous
// link breaks the replay.
func ReplayChain(entries []*jcs.Object) string {
	prev := "sha256:" + strings.Repeat("0", 64)
	for _, e := range entries {
		if str(e, "prev_hash") != prev {
			return fmt.Sprintf("broken at seq %v", mustGet(e, "seq"))
		}
		env, _ := e.Get("envelope")
		b, err := jcs.Encode(env)
		if err != nil {
			return "unencodable"
		}
		d := sha256.Sum256(append(b, prev...))
		prev = "sha256:" + hex.EncodeToString(d[:])
	}
	return prev
}

// matches compares a reference's digest with the RFC 8785 form of v, in the algorithm
// the digest names. The schema makes digest optional ("when the producer holds it at
// issue time") and admits sha256 and sha384: with none, or with an algorithm this
// verifier does not compute, nothing is checked (nil), which is neither a match nor a
// contradiction (3.1.3 rule 3 on unsupported algorithms, read the same way here).
func matches(ref *jcs.Object, v any) *bool {
	want := str(ref, "digest")
	var b []byte
	switch {
	case strings.HasPrefix(want, "sha256:"), strings.HasPrefix(want, "sha384:"):
		var err error
		if b, err = jcs.Encode(v); err != nil {
			return yes(false)
		}
	default:
		return nil
	}
	if strings.HasPrefix(want, "sha384:") {
		d := sha512.Sum384(b)
		return yes(want == "sha384:"+hex.EncodeToString(d[:]))
	}
	d := sha256.Sum256(b)
	return yes(want == "sha256:"+hex.EncodeToString(d[:]))
}

func str(o *jcs.Object, name string) string {
	v, _ := o.Get(name)
	s, _ := v.(string)
	return s
}

func mustGet(o *jcs.Object, name string) any {
	v, _ := o.Get(name)
	if n, ok := v.(jcs.Number); ok {
		return n.Literal
	}
	return v
}
