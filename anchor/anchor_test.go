package anchor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/plimsollmark/trace-verify-go/jcs"
)

func golden(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(goldenSource)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Section 1's bytes, byte for byte, on a claim built to hit every divergence section 0
// lists: non-ASCII in both planes, control characters, U+007F, and a key order that
// differs between code points and UTF-16 code units.
func TestCanonicalClaimBytesGolden(t *testing.T) {
	got, err := CanonicalClaimBytes(golden(t))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != goldenCanonical {
		t.Fatalf("canonical bytes differ\n got %s\nwant %s", got, goldenCanonical)
	}
	if h := LeafHash(got).String(); h != goldenLeaf {
		t.Fatalf("leaf %s, want %s", h, goldenLeaf)
	}
}

// The test section 0 asks for: anchor a record containing non-ASCII and verify it, and
// show that the signing canonicalizer at the leaf gives a root that never matches.
func TestSigningCanonicalizerIsNotTheLeaf(t *testing.T) {
	claim := golden(t)
	signing, err := jcs.Canonicalize(claim)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(signing, []byte(goldenCanonical)) {
		t.Fatal("RFC 8785 and the anchor form agree on this claim; it no longer tests the trap")
	}
	c, _ := CanonicalClaimBytes(claim)
	leaves := []Hash{LeafHash([]byte("x")), LeafHash(c), LeafHash([]byte("y"))}
	root, _ := Root(leaves)
	e := Entry{MerkleRoot: root, LeafCount: 3}
	p := Proof{LeafIndex: 1, AuditPath: path(leaves, 1)}
	if err := Verify(claim, p, e); err != nil {
		t.Fatalf("the anchor form does not verify: %v", err)
	}
	if err := VerifyLeaf(LeafHash(signing), p, e); !errors.Is(err, ErrNotIncluded) {
		t.Fatalf("a JCS leaf verified: %v", err)
	}
}

func TestOutsideProfile(t *testing.T) {
	for _, claim := range []string{
		`{"a":1.5}`, `{"a":1e3}`, `{"a":1.0}`,
		`{"a":9007199254740992}`, `{"a":-9007199254740992}`,
		`[1,2]`, `"a string"`,
	} {
		if _, err := CanonicalClaimBytes([]byte(claim)); !errors.Is(err, ErrOutsideProfile) {
			t.Errorf("%s: %v", claim, err)
		}
	}
	// The strict parser still refuses what no canonical form can carry.
	for _, claim := range []string{`{"a":1,"a":2}`, `{"a":"\ud800"}`} {
		if _, err := CanonicalClaimBytes([]byte(claim)); err == nil {
			t.Errorf("%s accepted", claim)
		}
	}
	got, err := CanonicalClaimBytes([]byte(`{"z":-0,"a":[]}`))
	if err != nil || string(got) != `{"a":[],"z":0}` {
		t.Errorf("-0: %s %v", got, err)
	}
}

// The three claims the published registry anchored by the pinned commit, each against
// its own entry and proof, and each refused once modified.
func TestPublishedRegistry(t *testing.T) {
	const dir = "../testdata/registry/"
	for _, c := range []struct {
		claim, proof, entry string
		extra               []string
	}{
		{"samples/example-trust-record.json", "samples/inclusion-proof.json", "registry/2026/06/12.ndjson", nil},
		{"staging/processed/summit-demo-record.json", "proofs/2026/09/01/summit-demo-record.proof.json", "registry/2026/09/01.ndjson", []string{"canonicalization_id", "mmr_checkpoint"}},
		{"staging/processed/ac05cb84fd956684/bernstein-3.20.0-20260920-165918-backend-99365805.json", "proofs/2026/09/25/ac05cb84fd956684/bernstein-3.20.0-20260920-165918-backend-99365805.proof.json", "registry/2026/09/25.ndjson", []string{"canonicalization_id", "mmr_checkpoint"}},
	} {
		read := func(p string) []byte {
			b, err := os.ReadFile(dir + p)
			if err != nil {
				t.Fatal(err)
			}
			return bytes.TrimSpace(b) // an .ndjson file holds one entry and its newline
		}
		e, err := ParseEntry(read(c.entry))
		if err != nil {
			t.Fatalf("%s: %v", c.entry, err)
		}
		if !slices.Equal(e.Extra, c.extra) {
			t.Errorf("%s: extra members %q, want %q", c.entry, e.Extra, c.extra)
		}
		p, err := ParseProof(read(c.proof))
		if err != nil {
			t.Fatalf("%s: %v", c.proof, err)
		}
		claim := read(c.claim)
		if err := Verify(claim, p, e); err != nil {
			t.Errorf("%s: %v", c.claim, err)
		}
		// Record modified after anchoring: one byte of the signature.
		i := bytes.Index(claim, []byte(`"signature"`)) + len(`"signature": "`) + 4
		mod := slices.Clone(claim)
		mod[i] ^= 1
		if err := Verify(mod, p, e); !errors.Is(err, ErrNotIncluded) {
			t.Errorf("%s modified: %v", c.claim, err)
		}
	}
}

// mth and path are RFC 6962 section 2.1's recursive definitions, written independently of
// Root and VerifyLeaf so each checks the other; section 3 says the level-by-level tree
// "yields the same tree as the RFC 6962 recursive split".
func mth(leaves []Hash) Hash {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := split(len(leaves))
	return node(mth(leaves[:k]), mth(leaves[k:]))
}

func path(leaves []Hash, m int) []Hash {
	if len(leaves) == 1 {
		return []Hash{}
	}
	k := split(len(leaves))
	if m < k {
		return append(path(leaves[:k], m), mth(leaves[k:]))
	}
	return append(path(leaves[k:], m-k), mth(leaves[:k]))
}

// split is the largest power of two smaller than n.
func split(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

func leavesOf(n int) []Hash {
	out := make([]Hash, n)
	for i := range out {
		out[i] = LeafHash([]byte(fmt.Sprint(i)))
	}
	return out
}

func TestTreeAgainstRFC6962(t *testing.T) {
	if _, err := Root(nil); !errors.Is(err, ErrMalformed) {
		t.Fatalf("empty batch: %v", err)
	}
	for n := 1; n <= 70; n++ {
		leaves := leavesOf(n)
		root, err := Root(leaves)
		if err != nil || root != mth(leaves) {
			t.Fatalf("n=%d: level-by-level root differs from RFC 6962", n)
		}
		e := Entry{MerkleRoot: root, LeafCount: int64(n)}
		for m := range n {
			p := Proof{LeafIndex: int64(m), AuditPath: path(leaves, m)}
			if err := VerifyLeaf(leaves[m], p, e); err != nil {
				t.Fatalf("n=%d m=%d: %v", n, m, err)
			}
			// The negative cases trace-tests docs/modules/tr-anc.md lists for TR-ANC-002,
			// plus the path-length checks of section 5.1.
			bad := map[string]Proof{
				"too long":           {LeafIndex: int64(m), AuditPath: append(slices.Clone(p.AuditPath), leaves[0])},
				"index out of range": {LeafIndex: int64(n), AuditPath: p.AuditPath},
			}
			if len(p.AuditPath) > 0 {
				bad["too short"] = Proof{LeafIndex: int64(m), AuditPath: p.AuditPath[:len(p.AuditPath)-1]}
				flipped := slices.Clone(p.AuditPath)
				flipped[0][0] ^= 1
				bad["node flipped"] = Proof{LeafIndex: int64(m), AuditPath: flipped}
				bad["another index"] = Proof{LeafIndex: int64((m + 1) % n), AuditPath: p.AuditPath}
			}
			for what, bp := range bad {
				if err := VerifyLeaf(leaves[m], bp, e); !errors.Is(err, ErrNotIncluded) {
					t.Fatalf("n=%d m=%d %s: %v", n, m, what, err)
				}
			}
			other := LeafHash([]byte("another record"))
			if err := VerifyLeaf(other, p, e); !errors.Is(err, ErrNotIncluded) {
				t.Fatalf("n=%d m=%d: a proof for another record verified", n, m)
			}
		}
	}
}

func TestParse(t *testing.T) {
	zero := "sha256:" + hex.EncodeToString(make([]byte, 32))
	for _, s := range []string{"", "sha256:00", zero[:len(zero)-1] + "A", "sha384:" + zero[7:], zero[7:], zero + "00"} {
		if _, err := ParseHash(s); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, p := range []string{
		`{"audit_path":[]}`, `{"leaf_index":0}`, `{"leaf_index":-1,"audit_path":[]}`,
		`{"leaf_index":0.5,"audit_path":[]}`, `{"leaf_index":0,"audit_path":["zz"]}`,
		`{"leaf_index":0,"audit_path":[1]}`, `[]`,
	} {
		if _, err := ParseProof([]byte(p)); !errors.Is(err, ErrMalformed) {
			t.Errorf("proof %s: %v", p, err)
		}
	}
	entry := func(extra string) string {
		return `{"ts":"t","producer":"p","batch_id":"b","merkle_root":"` + zero + `"` + extra + `}`
	}
	for _, e := range []string{entry(""), entry(`,"leaf_count":0`), entry(`,"leaf_count":"1"`)} {
		if _, err := ParseEntry([]byte(e)); !errors.Is(err, ErrMalformed) {
			t.Errorf("entry %s: %v", e, err)
		}
	}
	e, err := ParseEntry([]byte(entry(`,"leaf_count":1`)))
	if err != nil || e.LeafCount != 1 || e.Extra != nil {
		t.Errorf("valid entry: %+v %v", e, err)
	}
	d := sha256.Sum256([]byte{0})
	if (Hash(d)).String() != "sha256:"+hex.EncodeToString(d[:]) {
		t.Error("Hash.String")
	}
}
