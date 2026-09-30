package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The committed page must be what the code produces now; regenerate it with
// go run ./cmd/trace-conformance -out docs/conformance.html
func TestCommittedPageIsCurrent(t *testing.T) {
	out := filepath.Join(t.TempDir(), "page.html")
	disagree, err := run("../../testdata/vectors", "../../PLAN.md", out)
	if err != nil {
		t.Fatal(err)
	}
	if disagree != 0 {
		t.Errorf("%d vectors disagree", disagree)
	}
	got, _ := os.ReadFile(out)
	want, err := os.ReadFile("../../docs/conformance.html")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("docs/conformance.html is stale (%v); regenerate it", err)
	}
}
