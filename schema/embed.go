package schema

import (
	_ "embed"
	"sync"
)

// TraceClaimV02 is schema/trace-claim.json from trace-spec at the commit PLAN.md pins,
// byte for byte (TestEmbeddedSchemaIsThePinnedOne checks the digest).
//
//go:embed trace-claim.json
var TraceClaimV02 []byte

// TraceClaimV02SHA256 is the digest PLAN.md and testdata/vectors/PROVENANCE.md record.
const TraceClaimV02SHA256 = "44778f700dae0216f18eda482457b1a9363aef8e8f92adb33d152c925781eea6"

var (
	once     sync.Once
	compiled *Schema
	compErr  error
)

// TraceClaim returns the compiled v0.2 record schema.
func TraceClaim() (*Schema, error) {
	once.Do(func() { compiled, compErr = Compile(TraceClaimV02) })
	return compiled, compErr
}

// The revocation statement and bundle schemas (spec 3.2.3), from the same commit.
//
//go:embed trace-revocation.json
var TraceRevocationV1 []byte

//go:embed trace-revocation-bundle.json
var TraceRevocationBundleV1 []byte

// Their digests, as testdata/vectors/PROVENANCE.md records them.
const (
	TraceRevocationV1SHA256       = "a25ee0ba7df0098e38dbe4448cd6e6ac22ec723ec5d7d479728aacbbdf81a062"
	TraceRevocationBundleV1SHA256 = "1229dba26b8d4b28deb4c3f052631bf9766183e956ba518ba7ac83c1d023fc5b"
)

var (
	bundleOnce     sync.Once
	bundleCompiled *Schema
	bundleErr      error
)

// RevocationBundle returns the compiled bundle schema, with the statement schema it
// references.
func RevocationBundle() (*Schema, error) {
	bundleOnce.Do(func() { bundleCompiled, bundleErr = Compile(TraceRevocationBundleV1, TraceRevocationV1) })
	return bundleCompiled, bundleErr
}
