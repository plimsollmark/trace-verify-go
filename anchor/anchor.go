// Package anchor verifies that a signed claim is included in a TRACE registry anchor:
// TRACE Registry Anchor Format v1 (trace-spec spec/registry-anchor-v1.md), the normative
// companion to v0.2 for the transparency claim and Level 2.
//
// The leaf is not the signing pre-image. A record is signed over its RFC 8785 form
// (v0.2 3.2.2) and anchored over a different canonical form, sorted-key JSON with
// non-ASCII escaped (Anchor Format section 1). Reusing the signing canonicalizer here
// yields roots that never match, so this package has its own serializer and the jcs
// package's is never called from it.
package anchor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/plimsollmark/trace-verify-go/jcs"
)

// Errors a caller may need to tell apart.
var (
	ErrOutsideProfile = errors.New("anchor: claim is outside the anchor profile")
	ErrMalformed      = errors.New("anchor: malformed proof or entry")
	ErrNotIncluded    = errors.New("anchor: claim is not proven included in the entry")
)

// maxSafe is 2^53 - 1: section 1 excludes integers outside -maxSafe to maxSafe.
var maxSafe = big.NewInt(1<<53 - 1)

// CanonicalClaimBytes is section 1's canonical_claim_bytes of a claim given as JSON
// bytes. The bytes are parsed strictly (duplicate names, lone surrogates and invalid
// UTF-8 refused) before anything is serialized.
func CanonicalClaimBytes(claim []byte) ([]byte, error) {
	v, err := jcs.Parse(claim)
	if err != nil {
		return nil, err
	}
	return CanonicalValue(v)
}

// CanonicalValue is canonical_claim_bytes of an already parsed claim.
func CanonicalValue(v any) ([]byte, error) {
	if _, ok := v.(*jcs.Object); !ok {
		return nil, fmt.Errorf("%w: claims MUST be JSON objects", ErrOutsideProfile)
	}
	var b bytes.Buffer
	if err := write(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func write(b *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(map[bool]string{true: "true", false: "false"}[t])
	case string:
		writeString(b, t)
	case jcs.Number:
		// Integers only, inside the safe range: section 1 excludes non-integer numbers
		// and integers outside -9007199254740991 to 9007199254740991.
		lit := t.Literal
		if strings.ContainsAny(lit, ".eE") {
			return fmt.Errorf("%w: non-integer number %s", ErrOutsideProfile, lit)
		}
		n, ok := new(big.Int).SetString(lit, 10)
		if !ok {
			return fmt.Errorf("%w: number %s", ErrOutsideProfile, lit)
		}
		if new(big.Int).Abs(n).Cmp(maxSafe) > 0 {
			return fmt.Errorf("%w: integer %s outside the safe range", ErrOutsideProfile, lit)
		}
		// The integer's value, not its spelling: -0 is written 0, as the reference
		// expression in section 1 writes it.
		b.WriteString(n.String())
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := write(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case *jcs.Object:
		// Keys by Unicode code point. Go compares strings as UTF-8 bytes, and UTF-8
		// byte order is code-point order, which is where this differs from RFC 8785's
		// UTF-16 code-unit order once a key leaves the Basic Multilingual Plane.
		ms := slices.Clone(t.Members)
		slices.SortFunc(ms, func(a, c jcs.Member) int { return strings.Compare(a.Name, c.Name) })
		b.WriteByte('{')
		for i, m := range ms {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, m.Name)
			b.WriteByte(':')
			if err := write(b, m.Value); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("%w: unsupported value %T", ErrOutsideProfile, v)
	}
	return nil
}

// writeString escapes as section 1's reference expression does: quote and backslash,
// the five short escapes, every other character outside printable ASCII (U+0020 to
// U+007E) as a lowercase \uXXXX, and a character above the Basic Multilingual Plane as
// its surrogate pair. Section 1's prose says only "non-ASCII characters escaped"; the
// short escapes, the lowercase hex and the escaping of U+007F are the reference
// expression's (PLAN.md finding 19).
func writeString(b *bytes.Buffer, s string) {
	const hexdigits = "0123456789abcdef"
	u := func(r rune) {
		b.WriteString(`\u`)
		b.WriteByte(hexdigits[r>>12&0xf])
		b.WriteByte(hexdigits[r>>8&0xf])
		b.WriteByte(hexdigits[r>>4&0xf])
		b.WriteByte(hexdigits[r&0xf])
	}
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r >= 0x20 && r <= 0x7e:
			b.WriteByte(byte(r))
		case r > 0xffff:
			r -= 0x10000
			u(0xd800 | (r >> 10 & 0x3ff))
			u(0xdc00 | (r & 0x3ff))
		default:
			u(r)
		}
	}
	b.WriteByte('"')
}

// Hash is a SHA-256 node or leaf.
type Hash [32]byte

// String is the section 3 form, "sha256:" and lowercase hex.
func (h Hash) String() string { return "sha256:" + hex.EncodeToString(h[:]) }

// ParseHash reads the section 3 form: "sha256:" and exactly 64 lowercase hex digits.
func ParseHash(s string) (Hash, error) {
	var h Hash
	hx, ok := strings.CutPrefix(s, "sha256:")
	if !ok || len(hx) != 64 || strings.ToLower(hx) != hx {
		return h, fmt.Errorf("%w: %q is not sha256:<64 lowercase hex>", ErrMalformed, s)
	}
	if _, err := hex.Decode(h[:], []byte(hx)); err != nil {
		return h, fmt.Errorf("%w: %q is not hex", ErrMalformed, s)
	}
	return h, nil
}

// LeafHash is section 2: SHA-256(0x00 || canonical_claim_bytes).
func LeafHash(canonical []byte) Hash {
	return sha256.Sum256(append([]byte{0}, canonical...))
}

func node(l, r Hash) Hash {
	return sha256.Sum256(slices.Concat([]byte{1}, l[:], r[:]))
}

// Root is section 3's Merkle Tree Hash, level by level with an odd last node promoted
// unchanged. The empty batch is rejected.
func Root(leaves []Hash) (Hash, error) {
	if len(leaves) == 0 {
		return Hash{}, fmt.Errorf("%w: the empty batch is invalid", ErrMalformed)
	}
	level := slices.Clone(leaves)
	for len(level) > 1 {
		var next []Hash
		for i := 0; i+1 < len(level); i += 2 {
			next = append(next, node(level[i], level[i+1]))
		}
		if len(level)%2 == 1 {
			next = append(next, level[len(level)-1])
		}
		level = next
	}
	return level[0], nil
}

// Entry is a registry entry (section 4). Extra names members beyond section 4's five,
// which section 4 says an entry does not have and the published registry's entries do
// (PLAN.md finding 20); they are reported, never read.
type Entry struct {
	TS, Producer, BatchID string
	MerkleRoot            Hash
	LeafCount             int64
	Extra                 []string
}

// ParseEntry reads one registry entry.
func ParseEntry(data []byte) (Entry, error) {
	var e Entry
	o, err := object(data)
	if err != nil {
		return e, err
	}
	for _, f := range []struct {
		name string
		into *string
	}{{"ts", &e.TS}, {"producer", &e.Producer}, {"batch_id", &e.BatchID}} {
		if *f.into, err = str(o, f.name); err != nil {
			return e, err
		}
	}
	root, err := str(o, "merkle_root")
	if err != nil {
		return e, err
	}
	if e.MerkleRoot, err = ParseHash(root); err != nil {
		return e, err
	}
	if e.LeafCount, err = integer(o, "leaf_count"); err != nil {
		return e, err
	}
	if e.LeafCount < 1 {
		return e, fmt.Errorf("%w: leaf_count %d, must be >= 1", ErrMalformed, e.LeafCount)
	}
	for _, m := range o.Members {
		if !slices.Contains([]string{"ts", "merkle_root", "leaf_count", "producer", "batch_id"}, m.Name) {
			e.Extra = append(e.Extra, m.Name)
		}
	}
	return e, nil
}

// Proof is an inclusion proof (section 5).
type Proof struct {
	LeafIndex int64
	AuditPath []Hash
}

// ParseProof reads one inclusion proof.
func ParseProof(data []byte) (Proof, error) {
	var p Proof
	o, err := object(data)
	if err != nil {
		return p, err
	}
	if p.LeafIndex, err = integer(o, "leaf_index"); err != nil {
		return p, err
	}
	if p.LeafIndex < 0 {
		return p, fmt.Errorf("%w: leaf_index %d", ErrMalformed, p.LeafIndex)
	}
	v, ok := o.Get("audit_path")
	path, isArr := v.([]any)
	if !ok || !isArr {
		return p, fmt.Errorf("%w: audit_path is absent or not an array", ErrMalformed)
	}
	p.AuditPath = []Hash{}
	for _, e := range path {
		s, _ := e.(string)
		h, err := ParseHash(s)
		if err != nil {
			return p, err
		}
		p.AuditPath = append(p.AuditPath, h)
	}
	return p, nil
}

// Verify is section 5.1 over a claim as JSON bytes.
func Verify(claim []byte, p Proof, e Entry) error {
	c, err := CanonicalClaimBytes(claim)
	if err != nil {
		return err
	}
	return VerifyLeaf(LeafHash(c), p, e)
}

// VerifyLeaf is section 5.1 from step 1, given the leaf hash. It either proves inclusion
// or fails: there is no partial success.
func VerifyLeaf(leaf Hash, p Proof, e Entry) error {
	// 1. An index outside the batch.
	if p.LeafIndex < 0 || e.LeafCount < 1 || p.LeafIndex >= e.LeafCount {
		return fmt.Errorf("%w: leaf_index %d outside a batch of %d", ErrNotIncluded, p.LeafIndex, e.LeafCount)
	}
	// 2.
	r, fn, sn := leaf, p.LeafIndex, e.LeafCount-1
	// 3.
	for _, sib := range p.AuditPath {
		if sn == 0 {
			return fmt.Errorf("%w: audit path too long", ErrNotIncluded)
		}
		if fn%2 == 1 || fn == sn {
			r = node(sib, r)
			if fn%2 == 0 {
				// Right-edge promotion: skip the levels at which this node had no sibling.
				for fn%2 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = node(r, sib)
		}
		fn >>= 1
		sn >>= 1
	}
	// 4.
	if sn != 0 {
		return fmt.Errorf("%w: audit path too short", ErrNotIncluded)
	}
	if r != e.MerkleRoot {
		return fmt.Errorf("%w: the recomputed root %s is not the entry's %s", ErrNotIncluded, r, e.MerkleRoot)
	}
	return nil
}

func object(data []byte) (*jcs.Object, error) {
	v, err := jcs.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	o, ok := v.(*jcs.Object)
	if !ok {
		return nil, fmt.Errorf("%w: not a JSON object", ErrMalformed)
	}
	return o, nil
}

func str(o *jcs.Object, name string) (string, error) {
	v, ok := o.Get(name)
	s, isStr := v.(string)
	if !ok || !isStr {
		return "", fmt.Errorf("%w: %s is absent or not a string", ErrMalformed, name)
	}
	return s, nil
}

func integer(o *jcs.Object, name string) (int64, error) {
	v, ok := o.Get(name)
	n, isNum := v.(jcs.Number)
	if !ok || !isNum || strings.ContainsAny(n.Literal, ".eE") {
		return 0, fmt.Errorf("%w: %s is absent or not an integer", ErrMalformed, name)
	}
	i, ok := new(big.Int).SetString(n.Literal, 10)
	if !ok || !i.IsInt64() {
		return 0, fmt.Errorf("%w: %s is out of range", ErrMalformed, name)
	}
	return i.Int64(), nil
}
