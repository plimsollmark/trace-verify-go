package references

import (
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
