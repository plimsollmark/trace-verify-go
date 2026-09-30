package references

import (
	"crypto/sha512"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/plimsollmark/trace-verify-go/jcs"
)

func obj(t *testing.T, s string) *jcs.Object {
	t.Helper()
	v, err := jcs.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v.(*jcs.Object)
}

// The CHAP log comes from the resolver, not the signed record: a log entry of the wrong
// shape is a finding about the log, never a crash (spec 3.1.2 rule 3).
func TestMalformedLogEntriesDoNotPanic(t *testing.T) {
	ref := obj(t, `{"rel":"approval-outcome","id":"audit/1","digest":"sha256:00"}`)
	for _, c := range []struct{ name, entry, want string }{
		{"seq is a string", `{"seq":"1","envelope":{"method":"decide.approve"}}`, "approval-unconfirmed"},
		{"envelope absent", `{"seq":1}`, "approval-contradicted"},
		{"envelope is an array", `{"seq":1,"envelope":[]}`, "approval-contradicted"},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: panic: %v", c.name, r)
				}
			}()
			if _, got := Check(Input{Reference: ref, Log: []*jcs.Object{obj(t, c.entry)}}); got != c.want {
				t.Errorf("%s: %s, want %s", c.name, got, c.want)
			}
		}()
	}
}

// The schema makes a reference's digest optional and admits sha256 and sha384.
func TestReferenceDigestIsOptionalAndAlgorithmAware(t *testing.T) {
	entry := obj(t, `{"seq":1,"envelope":{"method":"decide.approve"},"prev_hash":"sha256:`+strings.Repeat("0", 64)+`"}`)
	log := []*jcs.Object{entry}
	env, _ := entry.Get("envelope")
	b, _ := jcs.Encode(env)
	d := sha512.Sum384(b)
	sha384 := "sha384:" + hex.EncodeToString(d[:])
	for _, c := range []struct{ name, ref, want string }{
		{"no digest", `{"rel":"approval-outcome","id":"audit/1"}`, "approval-confirmed"},
		{"sha384 that matches", `{"rel":"approval-outcome","id":"audit/1","digest":"` + sha384 + `"}`, "approval-confirmed"},
		{"sha384 that does not", `{"rel":"approval-outcome","id":"audit/1","digest":"sha384:` + strings.Repeat("0", 96) + `"}`, "approval-contradicted"},
	} {
		f, got := Check(Input{Reference: obj(t, c.ref), Log: log, ChainHead: ReplayChain(log)})
		if got != c.want {
			t.Errorf("%s: %s, want %s (%+v)", c.name, got, c.want, f)
		}
	}
}
