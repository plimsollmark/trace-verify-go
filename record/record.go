// Package record verifies TRACE v0.2 Trust Records (spec/trace-v0.2.md).
//
// Every check is an entry in Rules, and evaluation runs exactly those entries in order,
// so the registry is the complete inventory of what this package verifies. A result is
// reported per rule, and each is one of four statuses; a skip and an unverified are
// never rounded to a pass.
//
// Two modes read the same registry:
//
//   - ModeVerify is the specification's verification (spec 3.3): stages are gated, so no
//     claim is read before the signature binding holds, and a record with no verifiable
//     binding is rejected (3.2.2).
//   - ModeLevel is the conformance suite's level check (trace-tests docs/levels.md):
//     every check that applies at the requested level is reported, whatever the others
//     found, and whether an unverified finding fails the run depends on its code and the
//     level.
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
	// Verified: every rule that applied passed. In ModeLevel: the record meets the level.
	Verified Outcome = "verified"
	// Unverified (ModeVerify only): no rule failed, and at least one could not be
	// checked. The spec's rule for revocation (3.2.3) and re-execution (3.1.4): an
	// inability to check is reported as that, never rounded to verified.
	OutcomeUnverified Outcome = "unverified"
	// Rejected: the record failed a rule.
	Rejected Outcome = "rejected"
	// Refused (ModeVerify only): the verifier did not evaluate the record under any
	// semantics, because its own configuration is unusable or the record's profile is
	// outside the declared set (spec 3.3, "Verifier profile compatibility").
	Refused Outcome = "refused"
)

// Mode selects how the registry is evaluated.
type Mode int

const (
	ModeVerify Mode = iota
	ModeLevel
)

// Finding is one rule's result.
type Finding struct {
	Rule    string // Rule.ID
	Suite   string // the suite's code for this check, when it has one (TR-ENV-001, ...)
	Section string // where the rule comes from
	Status  Status
	Code    string // on fail or unverified: which condition, e.g. "signature_invalid"
	Detail  string
}

// Result is the verdict and every rule's finding, in registry order.
type Result struct {
	Mode     Mode
	Level    int
	Outcome  Outcome
	Code     string // the Code of the finding that decided a refusal, rejection or unverified outcome
	Findings []Finding

	// On Verified, the verifier-result fields spec 3.3 requires: the record's signed
	// profile and the complete accepted set configured at verification time.
	Profile          string
	AcceptedProfiles []string
	// The RFC 7638 thumbprint of the key the signature verified under, when it did.
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

// Suite returns the findings carrying a suite code.
func (r Result) Suite(code string) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Suite == code {
			out = append(out, f)
		}
	}
	return out
}

// Options configure one evaluation.
type Options struct {
	Mode Mode
	// Level is the conformance level whose checks apply (0, 1 or 2). Rules that the
	// suite requires only from a higher level are skipped.
	Level int

	// AcceptedProfiles is the verifier's declared set (spec 3.3). It must be nonempty
	// and every entry must be in Implemented. In ModeLevel an empty set means the suite's
	// single profile, v0.2.
	AcceptedProfiles []string

	// Now is the verification time. Zero means time.Now().
	Now time.Time
	// MaxAge and ClockSkew bound iat (spec 3.2.2); zero means the spec's defaults,
	// 24 hours and 5 minutes. A deployment profile may set others.
	MaxAge, ClockSkew time.Duration
	// SkipFreshness reports the age bounds as not applied, for checking an archived
	// record; iat must still be an integer. The record is then not claimed fresh.
	SkipFreshness bool

	// Nonce is the challenge nonce the verifier issued, if any (spec 3.2.2); the record
	// must echo it in runtime.nonce.
	Nonce string

	// PinnedKeys, when nonempty, lists RFC 7638 thumbprints of the keys this verifier
	// trusts; a record whose cnf key is not among them is rejected. With none pinned,
	// the signature authenticates only the record's own key: "the key embedded in an
	// incoming record cannot establish its own authority" (trace-spec
	// docs/trust-levels.md), and the key_pinned finding says so.
	PinnedKeys []string

	// ResolvePolicy, when set, fetches the bundle a record's policy.policy_uri names, for
	// TR-POL-003. It is supplied by the caller and never derived from the record: "a
	// record that named its own resolver could name one that agrees with it"
	// (trace-tests docs/modules/tr-pol.md). Unset, the resolution part is skipped.
	ResolvePolicy func(uri string) ([]byte, error)
}

const (
	defaultMaxAge    = 24 * time.Hour
	defaultClockSkew = 5 * time.Minute
)

// unverifiedFailsFrom is the suite's table of the level from which an unverified
// finding fails a ModeLevel run (trace-tests docs/levels.md, "Unverified findings").
// A code absent from the table fails from level 1.
var unverifiedFailsFrom = map[string]int{
	"TR-SIG-005": 1,
	"TR-POL-003": 2,
}
