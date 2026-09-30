package schema

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plimsollmark/trace-verify-go/jcs"
)

const vectors = "../testdata/vectors/trace-spec"

func compile(t *testing.T) *Schema {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectors, "schema/trace-claim.json"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func parse(t *testing.T, b []byte) any {
	t.Helper()
	v, err := jcs.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// examples/README.md: "Each file in this directory is a canonical TRACE v0.2 Trust
// Record that validates as-is against schema/trace-claim.json".
func TestExamplesValidate(t *testing.T) {
	s := compile(t)
	paths, _ := filepath.Glob(filepath.Join(vectors, "examples/*.json"))
	if len(paths) != 5 {
		t.Fatalf("found %d example records, want 5", len(paths))
	}
	for _, p := range paths {
		b, _ := os.ReadFile(p)
		if v := s.Validate(parse(t, b)); len(v) > 0 {
			t.Errorf("%s: %v", filepath.Base(p), v)
		}
	}
}

// canonicalization-boundary/README.md: each record "validates against the schema".
func TestBoundaryRecordsValidate(t *testing.T) {
	s := compile(t)
	paths, _ := filepath.Glob(filepath.Join(vectors, "examples/canonicalization-boundary/*.json"))
	for _, p := range paths {
		var env struct{ Record json.RawMessage }
		b, _ := os.ReadFile(p)
		if err := json.Unmarshal(b, &env); err != nil {
			t.Fatal(err)
		}
		if v := s.Validate(parse(t, env.Record)); len(v) > 0 {
			t.Errorf("%s: %v", filepath.Base(p), v)
		}
	}
}

func TestViolations(t *testing.T) {
	s := compile(t)
	b, _ := os.ReadFile(filepath.Join(vectors, "examples/sandbox-runtime.json"))
	base := string(b)
	cases := []struct{ name, from, to, keyword string }{
		{"wrong profile", `"tag:agentrust-io.com,2026:trace-v0.2"`, `"tag:agentrust.io,2026:trace-v0.1"`, "const"},
		{"subject not SPIFFE or DID", `"subject": "`, `"subject": "x`, "pattern"},
		{"iat below the floor", `"iat": 1785936000`, `"iat": 1699999999`, "minimum"},
		{"unknown top-level member", `"eat_profile"`, `"surprise": 1, "eat_profile"`, "false"},
	}
	for _, c := range cases {
		if !strings.Contains(base, c.from) {
			t.Fatalf("%s: fixture lacks %q", c.name, c.from)
		}
		v := s.Validate(parse(t, []byte(strings.Replace(base, c.from, c.to, 1))))
		found := false
		for _, x := range v {
			found = found || x.Keyword == c.keyword
		}
		if !found {
			t.Errorf("%s: violations %v, want one for %s", c.name, v, c.keyword)
		}
	}
}

func TestCompileRefusesUnknownKeywords(t *testing.T) {
	for _, doc := range []string{
		`{"type":"object","dependentRequired":{}}`,
		`{"properties":{"a":{"uniqueItems":true}}}`,
		`{"format":"email"}`,
		`{"$ref":"#/$defs/missing"}`,
		`{"$ref":"https://example.org/other.json"}`, // no loaded document has that $id
		`{"pattern":"(?=a)"}`,
	} {
		if _, err := Compile([]byte(doc)); err == nil {
			t.Errorf("%s compiled", doc)
		}
	}
}

func TestEmbeddedSchemaIsThePinnedOne(t *testing.T) {
	sum := sha256.Sum256(TraceClaimV02)
	if got := hex.EncodeToString(sum[:]); got != TraceClaimV02SHA256 {
		t.Fatalf("embedded schema SHA-256 %s, want %s", got, TraceClaimV02SHA256)
	}
	vendored, err := os.ReadFile(filepath.Join(vectors, "schema/trace-claim.json"))
	if err != nil || !bytes.Equal(vendored, TraceClaimV02) {
		t.Fatalf("embedded schema differs from the vendored copy (%v)", err)
	}
	if _, err := TraceClaim(); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		b   []byte
		sum string
	}{
		"trace-revocation.json":        {TraceRevocationV1, TraceRevocationV1SHA256},
		"trace-revocation-bundle.json": {TraceRevocationBundleV1, TraceRevocationBundleV1SHA256},
	} {
		d := sha256.Sum256(c.b)
		v, _ := os.ReadFile(filepath.Join(vectors, "schema", name))
		if hex.EncodeToString(d[:]) != c.sum || !bytes.Equal(v, c.b) {
			t.Errorf("%s: embedded copy is not the vendored, pinned one", name)
		}
	}
	if _, err := RevocationBundle(); err != nil {
		t.Fatal(err)
	}
}
