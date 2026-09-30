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
