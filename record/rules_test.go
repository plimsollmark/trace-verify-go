package record

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/trace-verify-go/anchor"
	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/jwk"
)

var testNow = time.Unix(1785000000, 0)

// base is a record meant to pass every check through level 2; TR-ANC-002 also needs the
// anchor evidence anchorFor builds.
func base(pub ed25519.PublicKey) map[string]any {
	return map[string]any{
		"eat_profile": ProfileV02,
		"iat":         testNow.Unix() - 60,
		"subject":     "spiffe://trust.example/agent/x",
		"model":       map[string]any{"provider": "example", "model_id": "m-1"},
		"runtime": map[string]any{"platform": "intel-tdx", "nonce": "n-1",
			"measurement": "sha256:" + strings.Repeat("ab", 32),
			"rim_uri":     "https://rim.example/tdx"},
		"policy":           map[string]any{"bundle_hash": "sha256:" + strings.Repeat("cd", 32), "enforcement_mode": "enforce"},
		"data_class":       "internal",
		"build_provenance": map[string]any{"slsa_level": 2, "digest": "sha256:" + strings.Repeat("ef", 32)},
		"appraisal":        map[string]any{"status": "affirming", "verifier": "https://verifier.example.org"},
		"tool_transcript":  map[string]any{"hash": "sha256:" + strings.Repeat("01", 32), "call_count": 3},
		"transparency":     "https://transparency.example/entries/abc123",
		"cnf":              map[string]any{"jwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": jwk.B64.EncodeToString(pub)}},
	}
}

// build applies edit to a fresh base record and signs the result (unless edit removed
// or replaced the signature), returning the bytes.
func build(t *testing.T, edit func(r map[string]any)) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	r := base(pub)
	r["signature"] = "SIGN"
	if edit != nil {
		edit(r)
	}
	if r["signature"] == "SIGN" {
		delete(r, "signature")
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		pre, err := jcs.Canonicalize(b)
		if err != nil {
			t.Fatal(err)
		}
		r["signature"] = jwk.B64.EncodeToString(ed25519.Sign(priv, pre))
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sub(r map[string]any, k string) map[string]any { return r[k].(map[string]any) }

func TestBaseRecordPassesThroughLevel2(t *testing.T) {
	rec := build(t, nil)
	res := CheckLevel(rec, 2, Options{Now: testNow, Nonce: "n-1", Anchor: anchorFor(t, rec)})
	for _, f := range res.Findings {
		if f.Status == Fail || f.Status == Unverified {
			t.Errorf("%s: %s %s %s", f.Rule, f.Status, f.Code, f.Detail)
		}
	}
	if v := Verify(build(t, nil), Options{Now: testNow, AcceptedProfiles: []string{ProfileV02}}); v.Outcome != Verified {
		t.Fatalf("ModeVerify: %s %s", v.Outcome, v.Code)
	}
}

// The positive and negative cases in trace-tests docs/modules/*.md, one row per case.
func TestSuiteDocCases(t *testing.T) {
	type c struct {
		rule  string
		level int
		want  Status
		edit  func(r map[string]any)
	}
	set := func(path string, v any) func(map[string]any) {
		return func(r map[string]any) {
			keys := strings.Split(path, ".")
			m := r
			for _, k := range keys[:len(keys)-1] {
				m = sub(m, k)
			}
			if v == nil {
				delete(m, keys[len(keys)-1])
			} else {
				m[keys[len(keys)-1]] = v
			}
		}
	}
	del := func(path string) func(map[string]any) { return set(path, nil) }
	cases := []c{
		{"profile_accepted", 0, Fail, set("eat_profile", "tag:example.com,2024:wrong-profile")},
		{"profile_present", 0, Fail, del("eat_profile")},
		{"freshness", 0, Fail, set("iat", "1785000000")},
		{"freshness", 0, Fail, set("iat", testNow.Unix()+3600)},
		{"freshness", 0, Fail, set("iat", testNow.Unix()-25*3600)},
		{"TR-ENV-003", 0, Pass, set("subject", "did:key:z6Mkexample")},
		{"TR-ENV-003", 0, Fail, set("subject", "agent-x")},
		{"cnf_structure", 0, Fail, del("cnf")},
		{"cnf_structure", 0, Fail, set("cnf.jwk", "not an object")},
		{"cnf_structure", 0, Fail, del("cnf.jwk.kty")},
		{"cnf_public_only", 0, Fail, set("cnf.jwk.d", "AAAA")},
		{"cnf_public_only", 0, Fail, set("cnf.jwk.k", "AAAA")},
		{"cnf_public_only", 0, Fail, set("cnf.jwk.qi", "AAAA")},
		{"cnf_key_type", 0, Fail, set("cnf.jwk.kty", "RSA")},
		{"cnf_key_type", 0, Pass, set("cnf.jwk.crv", "X25519")}, // supported type, unusable key
		{"signature", 0, Unverified, set("cnf.jwk.crv", "X25519")},
		{"signature", 0, Unverified, del("signature")},
		{"signature", 1, Unverified, del("signature")},
		{"signature", 0, Fail, set("signature", strings.Repeat("A", 86))},
		{"TR-POL-001", 0, Pass, set("policy.bundle_hash", "sha384:"+strings.Repeat("a", 96))},
		{"TR-POL-001", 0, Fail, set("policy.bundle_hash", "md5:"+strings.Repeat("a", 32))},
		{"TR-POL-001", 0, Fail, set("policy.bundle_hash", "sha256:"+strings.Repeat("a", 63))},
		{"TR-POL-001", 0, Fail, del("policy.bundle_hash")},
		{"TR-POL-002", 0, Pass, set("policy.enforcement_mode", "declared")},
		{"TR-POL-002", 0, Fail, set("policy.enforcement_mode", "strict")},
		{"TR-POL-002", 0, Fail, set("policy.enforcement_mode", "monitor")},
		{"TR-POL-002", 0, Fail, del("policy.enforcement_mode")},
		{"TR-POL-003", 0, Skip, nil},
		{"TR-POL-003", 0, Fail, set("policy.policy_uri", "./bundles/p.json")},
		{"TR-POL-003", 0, Fail, set("policy.policy_uri", "https://p.example/a b.json")},
		{"TR-APR-001", 0, Fail, set("appraisal.status", "verified")},
		{"TR-APR-001", 0, Fail, set("appraisal.status", "AFFIRMING")},
		{"TR-APR-001", 0, Fail, set("appraisal.status", 7)},
		{"TR-APR-001", 0, Fail, del("appraisal.status")},
		{"TR-APR-001", 0, Fail, set("appraisal", "affirming")},
		{"TR-APR-002", 0, Fail, set("appraisal.verifier", "nvidia-openshell/0.3.0")},
		{"TR-APR-002", 0, Fail, set("appraisal.verifier", "https://v.example/a b")},
		{"TR-APR-002", 0, Fail, set("appraisal.verifier", "https://v.example/\x07")},
		{"TR-APR-002", 0, Fail, del("appraisal.verifier")},
		{"TR-APR-003", 0, Skip, nil},
		{"TR-APR-003", 0, Pass, set("appraisal.policy_ref", "https://policies.example.org/appraisal/v3")},
		{"TR-APR-003", 0, Fail, set("appraisal.policy_ref", "./policies/v1")},
		{"TR-APR-003", 0, Fail, set("appraisal.policy_ref", "ht tp://x")},
		{"TR-APR-004", 0, Skip, nil},
		{"TR-APR-004", 0, Pass, set("appraisal.timestamp", testNow.Unix()-10)},
		{"TR-APR-004", 0, Fail, set("appraisal.timestamp", "1748000042")},
		{"TR-APR-004", 0, Fail, set("appraisal.timestamp", 1748000042.5)},
		{"TR-APR-004", 0, Fail, set("appraisal.timestamp", true)},
		{"TR-APR-004", 0, Fail, set("appraisal.timestamp", testNow.Unix()+10)},
		{"TR-APR-005", 0, Skip, set("appraisal.status", "none")},
		{"TR-APR-005", 1, Fail, set("appraisal.status", "none")},
		{"TR-APR-005", 1, Fail, set("appraisal.status", "contraindicated")},
		{"TR-RTE-001", 0, Skip, set("runtime.platform", "software-only")},
		{"TR-RTE-001", 1, Fail, set("runtime.platform", "software-only")},
		{"TR-RTE-001", 1, Fail, set("runtime.platform", "sgx")},
		{"TR-RTE-001", 1, Fail, del("runtime")},
		{"TR-RTE-002", 1, Fail, set("runtime.measurement", "sha256:"+strings.Repeat("AB", 32))},
		{"TR-RTE-002", 1, Fail, set("runtime.measurement", "sha256:"+strings.Repeat("a", 60))},
		{"TR-RTE-003", 1, Skip, del("runtime.rim_uri")},
		{"TR-RTE-003", 1, Fail, set("runtime.rim_uri", "http://rim.example/tdx")},
		{"nonce", 1, Fail, set("runtime.nonce", "other")},
		{"TR-SCA-001", 1, Pass, set("build_provenance.slsa_level", 0)},
		{"TR-SCA-001", 1, Fail, set("build_provenance.slsa_level", 4)},
		{"TR-SCA-001", 1, Fail, set("build_provenance.slsa_level", -1)},
		{"TR-SCA-001", 1, Fail, set("build_provenance.slsa_level", "high")},
		{"TR-SCA-001", 1, Fail, del("build_provenance.slsa_level")},
		{"TR-SCA-001", 1, Fail, del("build_provenance")},
		{"TR-SCA-002", 1, Fail, set("build_provenance.digest", "sha1:"+strings.Repeat("a", 40))},
		{"TR-SCA-002", 1, Fail, del("build_provenance.digest")},
		{"TR-TXN-001", 2, Fail, del("tool_transcript.hash")},
		{"TR-TXN-001", 2, Fail, set("tool_transcript.hash", "sha256:xyz")},
		{"TR-TXN-002", 2, Pass, set("tool_transcript.call_count", 0)},
		{"TR-TXN-002", 2, Fail, set("tool_transcript.call_count", -1)},
		{"TR-TXN-002", 2, Fail, set("tool_transcript.call_count", "three")},
		{"TR-TXN-002", 2, Fail, del("tool_transcript.call_count")},
		{"TR-ANC-001", 2, Fail, del("transparency")},
		{"TR-ANC-001", 2, Fail, set("transparency", "")},
		{"TR-ANC-001", 2, Fail, set("transparency", 5)},
		{"TR-ANC-001", 2, Fail, set("transparency", "http://transparency.example/e/1")},
		{"TR-ANC-001", 2, Fail, set("transparency", "/entries/abc")},
		{"TR-ANC-001", 2, Fail, set("transparency", "ipfs://bafy")},
		{"TR-ANC-001", 1, Skip, del("transparency")},
	}
	for i, c := range cases {
		res := CheckLevel(build(t, c.edit), c.level, Options{Now: testNow, Nonce: "n-1"})
		f, ok := res.Finding(c.rule)
		if !ok {
			t.Fatalf("case %d: no rule %s", i, c.rule)
		}
		if f.Status != c.want {
			t.Errorf("case %d %s at level %d: %s (%s %s), want %s", i, c.rule, c.level, f.Status, f.Code, f.Detail, c.want)
		}
	}
}

func TestVerifyModeGatesClaimsBehindTheSignature(t *testing.T) {
	opts := Options{Now: testNow, AcceptedProfiles: []string{ProfileV02}}
	// A bad appraisal and a bad signature: only the signature is reported.
	b := build(t, func(r map[string]any) {
		sub(r, "appraisal")["status"] = "verified"
		r["signature"] = strings.Repeat("A", 86)
	})
	res := Verify(b, opts)
	if res.Outcome != Rejected || res.Code != "signature_invalid" {
		t.Fatalf("got %s %s", res.Outcome, res.Code)
	}
	if f, _ := res.Finding("TR-APR-001"); f.Status != Skip || f.Detail != "not reached" {
		t.Fatalf("TR-APR-001 read before the binding held: %+v", f)
	}
	// ModeLevel reports both.
	lv := CheckLevel(b, 0, Options{Now: testNow})
	if f, _ := lv.Finding("TR-APR-001"); f.Status != Fail {
		t.Fatalf("ModeLevel TR-APR-001: %+v", f)
	}
}

func TestVerifyModeOutcomes(t *testing.T) {
	opts := func() Options { return Options{Now: testNow, AcceptedProfiles: []string{ProfileV02}} }
	if r := Verify(build(t, func(r map[string]any) { delete(r, "signature") }), opts()); r.Outcome != Rejected || r.Code != "signature_absent" {
		t.Errorf("unsigned: %s %s", r.Outcome, r.Code)
	}
	if r := Verify(build(t, func(r map[string]any) { r["eat_profile"] = "tag:agentrust.io,2026:trace-v0.1" }), opts()); r.Outcome != Refused {
		t.Errorf("v0.1 profile: %s %s", r.Outcome, r.Code)
	}
	o := opts()
	o.PinnedKeys = []string{"not-this-key"}
	if r := Verify(build(t, nil), o); r.Outcome != Rejected || r.Code != "key_not_pinned" {
		t.Errorf("unpinned key: %s %s", r.Outcome, r.Code)
	}
	o = opts()
	o.ResolvePolicy = func(string) ([]byte, error) { return nil, errors.New("offline") }
	r := Verify(build(t, func(r map[string]any) { sub(r, "policy")["policy_uri"] = "https://p.example/b.json" }), o)
	if r.Outcome != OutcomeUnverified || r.Code != "policy_unresolvable" {
		t.Errorf("unresolvable policy: %s %s", r.Outcome, r.Code)
	}
	// Spec 3.1.1: an imported record must say software-only.
	r = Verify(build(t, func(r map[string]any) {
		r["origin"] = map[string]any{"kind": "log-import", "producer": "siem"}
	}), opts())
	if f, _ := r.Finding("origin_platform"); r.Outcome != Rejected || f.Code != "origin_platform_not_software_only" {
		t.Errorf("imported with a hardware platform: %s %s, origin_platform %+v", r.Outcome, r.Code, f)
	}
	r = Verify(build(t, func(r map[string]any) {
		r["origin"] = map[string]any{"kind": "log-import", "producer": "siem"}
		sub(r, "runtime")["platform"] = "software-only"
	}), opts())
	if r.Outcome != Verified {
		t.Errorf("imported, software-only: %s %s", r.Outcome, r.Code)
	}
}

// anchorFor anchors rec as the middle leaf of a three-leaf batch and returns the proof
// and the entry, built by the anchor package's own section 3 tree.
func anchorFor(t *testing.T, rec []byte) *Anchor {
	t.Helper()
	c, err := anchor.CanonicalClaimBytes(rec)
	if err != nil {
		t.Fatal(err)
	}
	a, b := anchor.LeafHash([]byte("a")), anchor.LeafHash([]byte("b"))
	leaf := anchor.LeafHash(c)
	root, err := anchor.Root([]anchor.Hash{a, leaf, b})
	if err != nil {
		t.Fatal(err)
	}
	// Leaf 1 of 3: its sibling is leaf 0, then the promoted leaf 2.
	proof := fmt.Sprintf(`{"leaf_index":1,"audit_path":[%q,%q]}`, a, b)
	entry := fmt.Sprintf(`{"ts":"2026-09-30T00:00:00Z","merkle_root":%q,"leaf_count":3,"producer":"test","batch_id":"b1"}`, root)
	return &Anchor{Proof: []byte(proof), Entry: []byte(entry)}
}

func TestAnchorRule(t *testing.T) {
	rec := build(t, nil)
	good := anchorFor(t, rec)
	finding := func(data []byte, a *Anchor) Finding {
		t.Helper()
		f, ok := CheckLevel(data, 2, Options{Now: testNow, Nonce: "n-1", Anchor: a}).Finding("TR-ANC-002")
		if !ok {
			t.Fatal("no TR-ANC-002 finding")
		}
		return f
	}
	if f := finding(rec, good); f.Status != Pass {
		t.Fatalf("anchored record: %+v", f)
	}
	if f := finding(rec, nil); f.Status != Unverified || f.Code != "anchor_receipt_absent" {
		t.Errorf("no receipt: %+v", f)
	}
	// A different, validly signed record against the same proof: anchored bytes differ.
	if f := finding(build(t, nil), good); f.Status != Fail || f.Code != "anchor_inclusion_failed" {
		t.Errorf("proof for a different record: %+v", f)
	}
	for what, a := range map[string]*Anchor{
		"missing leaf_index":  {Proof: []byte(`{"audit_path":[]}`), Entry: good.Entry},
		"non-hex audit node":  {Proof: []byte(`{"leaf_index":1,"audit_path":["sha256:zz"]}`), Entry: good.Entry},
		"missing merkle_root": {Proof: good.Proof, Entry: []byte(`{"ts":"t","leaf_count":3,"producer":"p","batch_id":"b"}`)},
		"missing leaf_count":  {Proof: good.Proof, Entry: bytes.Replace(good.Entry, []byte(`"leaf_count":3,`), nil, 1)},
	} {
		if f := finding(rec, a); f.Status != Fail || f.Code != "anchor_receipt_malformed" {
			t.Errorf("%s: %+v", what, f)
		}
	}
	out := &Anchor{Proof: bytes.Replace(good.Proof, []byte(`"leaf_index":1`), []byte(`"leaf_index":3`), 1), Entry: good.Entry}
	if f := finding(rec, out); f.Status != Fail || f.Code != "anchor_inclusion_failed" {
		t.Errorf("out-of-range leaf_index: %+v", f)
	}
}
