package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const vectors = "../../testdata/vectors"

func runCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(""), &out, &errb)
	return code, out.String() + errb.String()
}

// extract writes a vector envelope's record (and trusted key) to files.
func extract(t *testing.T, vector string) (rec, key string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectors, vector))
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Record     json.RawMessage `json:"record"`
		TrustedKey json.RawMessage `json:"trusted_key"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, key = filepath.Join(dir, "record.json"), filepath.Join(dir, "key.json")
	if err := os.WriteFile(rec, env.Record, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, env.TrustedKey, 0o644); err != nil {
		t.Fatal(err)
	}
	return rec, key
}

func TestVerifiedWithPinnedKey(t *testing.T) {
	rec, key := extract(t, "trace-spec/examples/canonicalization-boundary/03-utf16-key-order.json")
	code, out := runCLI(t, "-archived", "-pin-jwk", key, rec)
	if code != 0 || !strings.Contains(out, "VERIFIED") || !strings.Contains(out, "pass    key_pinned") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestWrongPreimageRejected(t *testing.T) {
	rec, _ := extract(t, "trace-spec/examples/canonicalization-boundary/06-codepoint-order-signature.json")
	code, out := runCLI(t, "-archived", rec)
	if code != 1 || !strings.Contains(out, "REJECTED (signature_invalid)") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// With no key pinned the issuer is not authenticated, so the record is not VERIFIED
// unless the caller says to trust its embedded key.
func TestUnpinnedKeyIsUnverified(t *testing.T) {
	rec, _ := extract(t, "trace-spec/examples/canonicalization-boundary/01-non-ascii-values.json")
	code, out := runCLI(t, "-archived", rec)
	if code != 1 || !strings.Contains(out, "UNVERIFIED (issuer_not_authenticated)") ||
		!strings.Contains(out, "no keys pinned: the signature authenticates only the record's own cnf key") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	code, out = runCLI(t, "-archived", "-trust-embedded-key", rec)
	if code != 0 || !strings.Contains(out, "VERIFIED") {
		t.Fatalf("-trust-embedded-key: exit %d\n%s", code, out)
	}
}

func TestLevelCheckAndPolicyDir(t *testing.T) {
	dir := filepath.Join(vectors, "trace-tests/tests/vectors/policy-resolution")
	b, _ := os.ReadFile(filepath.Join(dir, "03-digest-mismatch-minimal-mutation.json"))
	var env struct {
		Record json.RawMessage `json:"record"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	rec := filepath.Join(t.TempDir(), "r.json")
	os.WriteFile(rec, env.Record, 0o644)
	code, out := runCLI(t, "-level", "0", "-archived", "-policy-dir", dir, "-json", rec)
	if code != 1 || !strings.Contains(out, `"Code": "policy_digest_mismatch"`) || !strings.Contains(out, `"Mode": "level"`) {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestUsageErrors(t *testing.T) {
	if code, _ := runCLI(t); code != 2 {
		t.Errorf("no argument: exit %d", code)
	}
	if code, _ := runCLI(t, "-level", "3", "x"); code != 2 {
		t.Errorf("bad level: exit %d", code)
	}
	if code, _ := runCLI(t, "/nonexistent/record.json"); code != 2 {
		t.Errorf("missing file: exit %d", code)
	}
}
