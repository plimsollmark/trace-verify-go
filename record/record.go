// Package record verifies TRACE v0.2 Trust Records (spec/trace-v0.2.md).
//
// Every check is an entry in Rules, and Verify runs exactly those entries in order, so
// the registry is the complete inventory of what this package verifies. A result is
// reported per rule, and each is one of four statuses; a skip and an unverified are
// never rounded to a pass.
package record

import (
	"slices"
	"time"
)

// ProfileV02 is the only profile this verifier implements (spec, "Changes from v0.1").
// The v0.1 identifier is deliberately not implemented: a v0.2 verifier "MUST reject the
// v0.1 identifier" and "MUST NOT accept both".
const ProfileV02 = "tag:agentrust-io.com,2026:trace-v0.2"

// Implemented lists the profiles whose schema and semantics this package carries.
var Implemented = []string{ProfileV02}

// Status is the result of one rule.
type Status string

const (
	Pass       Status = "pass"
	Fail       Status = "fail"
	Skip       Status = "skip"       // not performed: the rule did not apply, or was not reached
	Unverified Status = "unverified" // the rule applied and its evidence could not be checked
)

// Outcome is the verdict on the whole record.
type Outcome string

const (
	// Verified: every rule that applied passed.
	Verified Outcome = "verified"
	// Rejected: the record failed a rule.
	Rejected Outcome = "rejected"
	// Refused: the verifier did not evaluate the record under any semantics, because
	// its own configuration is unusable or the record's profile is outside the declared
	// set (spec 3.3, "Verifier profile compatibility"). The spec's draft text asks that
	// this be reported distinguishably from a verification failure.
	Refused Outcome = "refused"
)

// Finding is one rule's result.
type Finding struct {
	Rule    string // Rule.ID
	Section string // where the rule comes from
	Status  Status
	Code    string // on fail or unverified: which condition, e.g. "signature_invalid"
	Detail  string
}

// Result is the verdict and every rule's finding, in registry order.
type Result struct {
	Outcome  Outcome
	Code     string // the Code of the first finding that decided a refusal or rejection
	Findings []Finding

	// On Verified, the verifier-result fields spec 3.3 requires: the record's signed
	// profile and the complete accepted set configured at verification time.
	Profile          string
	AcceptedProfiles []string
	// The RFC 7638 thumbprint of the key the signature verified under.
	KeyThumbprint string
}

// Finding returns the named rule's finding.
func (r Result) Finding(rule string) (Finding, bool) {
	i := slices.IndexFunc(r.Findings, func(f Finding) bool { return f.Rule == rule })
	if i < 0 {
		return Finding{}, false
	}
	return r.Findings[i], true
}

// Options configure one verification.
type Options struct {
	// AcceptedProfiles is the verifier's declared set (spec 3.3). It must be nonempty
	// and every entry must be in Implemented, or the verifier refuses.
	AcceptedProfiles []string

	// Now is the verification time. Zero means time.Now().
	Now time.Time
	// MaxAge and ClockSkew bound iat (spec 3.2.2); zero means the spec's defaults,
	// 24 hours and 5 minutes. A deployment profile may set others.
	MaxAge, ClockSkew time.Duration
	// SkipFreshness reports the freshness rule as skipped rather than applying it, for
	// checking an archived record. The record is then not claimed fresh.
	SkipFreshness bool

	// Nonce is the challenge nonce the verifier issued, if any (spec 3.2.2); the record
	// must echo it in runtime.nonce.
	Nonce string

	// PinnedKeys, when nonempty, lists RFC 7638 thumbprints of the keys this verifier
	// trusts; a record whose cnf key is not among them is rejected. This is a verifier
	// policy, not a spec rule: the spec binds the signature to the record's own cnf key
	// and roots trust in that key elsewhere (3.3 steps 3 and 8).
	PinnedKeys []string
}

const (
	defaultMaxAge    = 24 * time.Hour
	defaultClockSkew = 5 * time.Minute
)
