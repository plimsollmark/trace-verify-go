package record

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/plimsollmark/trace-verify-go/anchor"
	"github.com/plimsollmark/trace-verify-go/internal/uri"
	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/jwk"
	"github.com/plimsollmark/trace-verify-go/schema"
)

// Stage orders the rules. In ModeVerify, when any rule in a stage fails, every rule in
// later stages is reported as not reached: in particular no claim is read as evidence
// until the signature binding holds (spec 3.3, step 1: "BEFORE any other field is
// trusted"). In ModeLevel only a failed input stage stops evaluation, since nothing can
// be checked in a record that did not parse.
type Stage int

const (
	StageConfig  Stage = iota // the verifier's own configuration: a failure refuses
	StageInput                // the bytes: strict parse and the canonicalization domain
	StageProfile              // eat_profile against the declared set: a failure refuses
	StageBinding              // the cnf key and the signature
	StageClaims               // claims, read only after the binding holds
)

// Rule is one check.
type Rule struct {
	ID      string
	Suite   string // the suite's code, when the suite names this check
	Level   int    // the lowest conformance level at which the rule applies
	Section string
	Stage   Stage
	Check   func(*state) Finding // Rule, Suite and Section are filled in by the evaluator
}

// state is what the rules share within one evaluation.
type state struct {
	opts Options
	now  time.Time
	raw  []byte
	rec  *jcs.Object
	key  *jwk.Key
}

func pass() Finding                          { return Finding{Status: Pass} }
func skip(detail string) Finding             { return Finding{Status: Skip, Detail: detail} }
func fail(code, detail string) Finding       { return Finding{Status: Fail, Code: code, Detail: detail} }
func failf(code, f string, a ...any) Finding { return fail(code, fmt.Sprintf(f, a...)) }
func unverified(code, detail string) Finding {
	return Finding{Status: Unverified, Code: code, Detail: detail}
}

// get walks a path of member names from the record; ok is false if any step is absent
// or not an object.
func (s *state) get(path ...string) (any, bool) {
	var v any = s.rec
	for _, name := range path {
		o, isObj := v.(*jcs.Object)
		if !isObj {
			return nil, false
		}
		var ok bool
		if v, ok = o.Get(name); !ok {
			return nil, false
		}
	}
	return v, true
}

func (s *state) str(path ...string) (string, bool) {
	v, ok := s.get(path...)
	str, isStr := v.(string)
	return str, ok && isStr
}

// Rules is the registry, in evaluation order.
var Rules = []Rule{
	// --- the verifier's configuration (spec 3.3) ---
	{ID: "accepted_profiles_nonempty", Section: "3.3 Verifier profile compatibility", Stage: StageConfig,
		Check: func(s *state) Finding {
			// An empty set means "nothing", never "anything".
			if len(s.opts.AcceptedProfiles) == 0 {
				return fail("no_accepted_profiles", "the declared accepted_profiles set is empty")
			}
			return pass()
		}},
	{ID: "accepted_profiles_implemented", Section: "3.3 Verifier profile compatibility", Stage: StageConfig,
		Check: func(s *state) Finding {
			// Every declared entry is checked, not only the one the record names.
			for _, p := range s.opts.AcceptedProfiles {
				if !slices.Contains(Implemented, p) {
					return failf("unschemaed_profile_in_accepted_set",
						"declared profile %q is not implemented by this verifier", p)
				}
			}
			return pass()
		}},

	// --- the bytes (spec 3.2.2) ---
	{ID: "json", Section: "3.2.2 (RFC 8785, RFC 7493)", Stage: StageInput,
		Check: func(s *state) Finding {
			v, err := jcs.Parse(s.raw)
			if err != nil {
				return fail("input_not_canonicalizable", err.Error())
			}
			o, ok := v.(*jcs.Object)
			if !ok {
				return fail("not_an_object", "a Trust Record is a JSON object")
			}
			s.rec = o
			return pass()
		}},
	{ID: "integer_range", Section: "3.2.2 Canonical form, numbers", Stage: StageInput,
		Check: func(s *state) Finding {
			if s.rec == nil {
				return skip("no parsed record")
			}
			// "No object canonicalized under this section may carry an integer outside
			// that range, and one that does MUST be rejected." Every double of magnitude
			// 2^53 or more is an integer, and every literal whose double is below 2^53 is
			// either not an integer or inside the range, so the double decides it.
			if path, n, bad := outOfRange(s.rec, "$"); bad {
				return failf("integer_out_of_range", "%s is %s, outside -(2^53-1) to 2^53-1", path, n.Literal)
			}
			return pass()
		}},

	// --- the profile (spec 3.3; Changes from v0.1) ---
	{ID: "profile_present", Suite: "TR-ENV-001", Section: "3.3 Verifier profile compatibility", Stage: StageProfile,
		Check: func(s *state) Finding {
			// Read before the signature only to select semantics; nothing else is.
			if p, ok := s.str("eat_profile"); !ok || p == "" {
				return fail("profile_absent", "eat_profile is absent, not a string, or empty")
			}
			return pass()
		}},
	{ID: "profile_accepted", Suite: "TR-ENV-001", Section: "3.3 Verifier profile compatibility; Changes from v0.1", Stage: StageProfile,
		Check: func(s *state) Finding {
			p, _ := s.str("eat_profile")
			if !slices.Contains(s.opts.AcceptedProfiles, p) {
				return failf("profile_not_accepted", "eat_profile %q is outside the declared set", p)
			}
			return pass()
		}},

	// --- the binding (spec 3.2.2; 3.3 step 1) ---
	{ID: "cnf_structure", Suite: "TR-ENV-004", Section: "3.1 cnf", Stage: StageBinding,
		Check: func(s *state) Finding {
			if _, ok := s.str("cnf", "jwk", "kty"); !ok {
				return fail("cnf_absent", "cnf, cnf.jwk or cnf.jwk.kty is absent or of the wrong type")
			}
			return pass()
		}},
	{ID: "cnf_public_only", Suite: "TR-ENV-005", Section: "3.1 cnf (RFC 8747); RFC 7517", Stage: StageBinding,
		Check: func(s *state) Finding {
			j, _ := s.get("cnf", "jwk")
			o, _ := j.(*jcs.Object)
			for _, m := range jwk.PrivateMembers {
				if _, ok := o.Get(m); ok {
					return failf("cnf_key_private", "cnf.jwk carries private key material %q", m)
				}
			}
			return pass()
		}},
	{ID: "cnf_key_type", Suite: "TR-SIG-004", Section: "3.2.1 Signing and key management", Stage: StageBinding,
		Check: func(s *state) Finding {
			j, _ := s.get("cnf", "jwk")
			kty, _ := s.str("cnf", "jwk", "kty")
			if kty != "OKP" && kty != "EC" {
				return failf("cnf_key_unsupported", "cnf.jwk.kty %q is not OKP or EC", kty)
			}
			k, err := jwk.Parse(j)
			switch {
			case errors.Is(err, jwk.ErrPrivate):
				return fail("cnf_key_private", err.Error())
			case err != nil:
				// The key type is supported; this key (its curve, or its coordinates) is
				// not usable, which the signature finding reports. The suite: "a supported
				// key that is not that pair passes this check and fails TR-SIG-005".
				return Finding{Status: Pass, Detail: "supported key type; key unusable: " + err.Error()}
			}
			s.key = k
			return pass()
		}},
	{ID: "signature", Suite: "TR-SIG-005", Section: "3.2.2 Signature binding (embedded); 3.3 step 1", Stage: StageBinding,
		Check: func(s *state) Finding {
			// ModeVerify: "A record with no verifiable signature binding is not a Trust
			// Record: verifiers MUST reject it." ModeLevel: the suite reports an absent or
			// unchecked signature as unverified, which fails from level 1.
			cannot := func(code, detail string) Finding {
				if s.opts.Mode == ModeLevel {
					return unverified(code, detail)
				}
				return fail(code, detail)
			}
			v, ok := s.rec.Get("signature")
			if !ok {
				return cannot("signature_absent", "no embedded signature")
			}
			if s.key == nil {
				return cannot("signature_not_checked", "the cnf key is absent, private, unsupported or malformed")
			}
			str, isStr := v.(string)
			if !isStr {
				return fail("signature_malformed", "signature is not a string")
			}
			sig, err := jwk.B64.DecodeString(str)
			if err != nil {
				return fail("signature_malformed", "signature is not base64url without padding")
			}
			// The pre-image: the record with the signature member absent, cnf included,
			// in RFC 8785 form, as UTF-8.
			pre, err := jcs.Encode(s.rec.Without("signature"))
			if err != nil {
				return fail("input_not_canonicalizable", err.Error())
			}
			if err := s.key.Verify(pre, sig); err != nil {
				return fail("signature_invalid", "the signature does not verify over the RFC 8785 form under the cnf key")
			}
			return pass()
		}},
	{ID: "key_pinned", Section: "verifier policy (Options.PinnedKeys); docs/trust-levels.md", Stage: StageBinding,
		Check: func(s *state) Finding {
			if s.key == nil {
				return skip("no usable cnf key")
			}
			if len(s.opts.PinnedKeys) == 0 {
				return skip("no keys pinned: the signature authenticates only the record's own cnf key, not its issuer")
			}
			if !slices.Contains(s.opts.PinnedKeys, s.key.Thumbprint()) {
				return failf("key_not_pinned", "cnf key %s is not a pinned key", s.key.Thumbprint())
			}
			return pass()
		}},

	// --- claims ---
	// Spec 3.1.4, the reproducibility claim and its re-execution result. The schema holds
	// these shape rules too; they come first so the named cause decides the code.
	{ID: "reproducibility_claim_complete", Section: "3.1.4 reproducibility", Stage: StageClaims,
		Check: func(s *state) Finding {
			r, ok := s.get("reproducibility")
			ro, isObj := r.(*jcs.Object)
			if !ok {
				return skip("no reproducibility claim")
			}
			for _, f := range []string{"function", "code_identity", "input_closure", "transcript_digest"} {
				if _, has := ro.Get(f); !isObj || !has {
					return failf("claim_incomplete", "reproducibility.%s is absent", f)
				}
			}
			return pass()
		}},
	{ID: "reproducibility_closure_entries", Section: "3.1.4 input_closure: {id, digest, resolver}, digest required on every entry", Stage: StageClaims,
		Check: func(s *state) Finding {
			v, ok := s.get("reproducibility", "input_closure")
			if !ok {
				return skip("no input_closure")
			}
			list, _ := v.([]any)
			for i, e := range list {
				eo, _ := e.(*jcs.Object)
				for _, f := range []string{"id", "digest", "resolver"} {
					if _, has := eo.Get(f); !has {
						return failf("closure_entry_incomplete", "input_closure[%d].%s is absent", i, f)
					}
				}
			}
			return pass()
		}},
	{ID: "appraisal_method_known", Section: "3.1.4 appraisal.method: a closed set, one value", Stage: StageClaims,
		Check: func(s *state) Finding {
			m, ok := s.get("appraisal", "method")
			if !ok {
				return skip("no appraisal.method")
			}
			if m != "re-execution" {
				return failf("unknown_method", "appraisal.method %v is not re-execution", m)
			}
			return pass()
		}},
	{ID: "re_execution_has_method", Section: "3.1.4 re_execution MUST be absent unless method is re-execution", Stage: StageClaims,
		Check: func(s *state) Finding {
			_, hasResult := s.get("appraisal", "re_execution")
			_, hasMethod := s.get("appraisal", "method")
			if hasResult && !hasMethod {
				return fail("re_execution_without_method", "appraisal.re_execution is present with no appraisal.method")
			}
			return pass()
		}},
	{ID: "method_has_re_execution", Section: "3.1.4 re_execution MUST be present when method is re-execution", Stage: StageClaims,
		Check: func(s *state) Finding {
			m, _ := s.get("appraisal", "method")
			if _, hasResult := s.get("appraisal", "re_execution"); m == "re-execution" && !hasResult {
				return fail("method_without_re_execution", "appraisal.method is re-execution with no appraisal.re_execution")
			}
			return pass()
		}},
	{ID: "re_execution_outcome_known", Section: "3.1.4 outcome: reproduced, diverged or not-attempted", Stage: StageClaims,
		Check: func(s *state) Finding {
			o, ok := s.get("appraisal", "re_execution", "outcome")
			if _, has := s.get("appraisal", "re_execution"); !has {
				return skip("no re_execution result")
			}
			if !ok || !slices.Contains([]any{"reproduced", "diverged", "not-attempted"}, o) {
				return failf("unknown_outcome", "re_execution.outcome %v is not reproduced, diverged or not-attempted", o)
			}
			return pass()
		}},
	{ID: "diverged_has_observed_digest", Section: "3.1.4 diverged MUST record the verifier's observed digest", Stage: StageClaims,
		Check: func(s *state) Finding {
			if o, _ := s.get("appraisal", "re_execution", "outcome"); o != "diverged" {
				return skip("not diverged")
			}
			if _, ok := s.get("appraisal", "re_execution", "observed_digest"); !ok {
				return fail("diverged_without_observed_digest", "a diverged result carries no observed_digest")
			}
			return pass()
		}},
	{ID: "not_attempted_has_reason", Section: "3.1.4 not-attempted MUST carry the reason", Stage: StageClaims,
		Check: func(s *state) Finding {
			if o, _ := s.get("appraisal", "re_execution", "outcome"); o != "not-attempted" {
				return skip("not not-attempted")
			}
			if _, ok := s.get("appraisal", "re_execution", "reason"); !ok {
				return fail("not_attempted_without_reason", "a not-attempted result carries no reason")
			}
			return pass()
		}},
	{ID: "schema", Section: "Authority and conformance claims: schema/trace-claim.json", Stage: StageClaims,
		Check: func(s *state) Finding {
			sc, err := schema.TraceClaim()
			if err != nil {
				return fail("schema_unavailable", err.Error())
			}
			v := sc.Validate(s.rec)
			if len(v) == 0 {
				return pass()
			}
			msgs := make([]string, 0, 3)
			for _, x := range v[:min(3, len(v))] {
				msgs = append(msgs, x.String())
			}
			return failf("schema_invalid", "%d violation(s): %s", len(v), strings.Join(msgs, "; "))
		}},
	{ID: "freshness", Suite: "TR-ENV-002", Section: "3.2.2 Freshness; 3.3 step 2", Stage: StageClaims,
		Check: func(s *state) Finding {
			iat, err := integer(s.rec, "iat")
			if err != nil {
				return fail("iat_invalid", err.Error())
			}
			if s.opts.SkipFreshness {
				return skip("iat is an integer; age bounds not applied (archived record)")
			}
			maxAge, skew := s.opts.MaxAge, s.opts.ClockSkew
			if maxAge == 0 {
				maxAge = defaultMaxAge
			}
			if skew == 0 {
				skew = defaultClockSkew
			}
			now := s.now.Unix()
			switch {
			case iat < now-int64(maxAge/time.Second):
				return failf("record_stale", "iat %d is older than the maximum age %s at %d", iat, maxAge, now)
			case iat > now+int64(skew/time.Second):
				return failf("record_from_future", "iat %d is later than %d plus the clock skew %s", iat, now, skew)
			}
			return pass()
		}},
	{ID: "nonce", Suite: "TR-RTE-004", Section: "3.2.2 Freshness (challenge nonce)", Stage: StageClaims,
		Check: func(s *state) Finding {
			if s.opts.Nonce == "" {
				// The suite asks for a verifier nonce from level 1 (TR-RTE-004).
				if s.opts.Mode == ModeLevel && s.opts.Level >= 1 {
					return fail("nonce_not_issued", "level 1 and above require the verifier's challenge nonce")
				}
				return skip("no challenge nonce issued")
			}
			if got, _ := s.str("runtime", "nonce"); got != s.opts.Nonce {
				return fail("nonce_mismatch", "runtime.nonce is absent or does not echo the issued nonce")
			}
			return pass()
		}},
	{ID: "origin_platform", Section: "3.1.1 origin", Stage: StageClaims,
		Check: func(s *state) Finding {
			v, ok := s.get("origin")
			if !ok {
				return skip("no origin block: the record is self")
			}
			if _, isObj := v.(*jcs.Object); !isObj {
				return fail("origin_invalid", "origin is not an object")
			}
			kind, _ := s.str("origin", "kind")
			switch kind {
			case "self":
				return pass()
			case "third-party-control-plane", "log-import":
			default:
				return failf("origin_invalid", "origin.kind %q is not in the closed set", kind)
			}
			if p, _ := s.str("runtime", "platform"); p != "software-only" {
				return failf("origin_platform_not_software_only",
					"origin.kind %q requires runtime.platform \"software-only\", found %q", kind, p)
			}
			return pass()
		}},
	{ID: "TR-ENV-003", Suite: "TR-ENV-003", Section: "3.1 subject (SPIFFE SVID or DID URI)", Stage: StageClaims,
		Check: func(s *state) Finding {
			if sub, ok := s.str("subject"); !ok || !subjectPattern.MatchString(sub) {
				return fail("subject_invalid", "subject is not a spiffe:// URI with a path or a did: URI")
			}
			return pass()
		}},
	{ID: "TR-POL-001", Suite: "TR-POL-001", Section: "3.1 policy", Stage: StageClaims,
		Check: func(s *state) Finding {
			if h, ok := s.str("policy", "bundle_hash"); !ok || !digestPattern.MatchString(h) {
				return fail("policy_hash_invalid", "policy.bundle_hash is not sha256:<64 hex> or sha384:<96 hex>")
			}
			return pass()
		}},
	{ID: "TR-POL-002", Suite: "TR-POL-002", Section: "3.1 policy", Stage: StageClaims,
		Check: func(s *state) Finding {
			m, _ := s.str("policy", "enforcement_mode")
			if !slices.Contains([]string{"enforce", "advisory", "silent", "declared"}, m) {
				return failf("enforcement_mode_invalid", "policy.enforcement_mode %q is not enforce, advisory, silent or declared", m)
			}
			return pass()
		}},
	{ID: "TR-POL-003", Suite: "TR-POL-003", Section: "schema: policy.policy_uri (format uri); trace-tests tr-pol.md", Stage: StageClaims,
		Check: func(s *state) Finding {
			v, ok := s.get("policy", "policy_uri")
			if !ok {
				return skip("no policy_uri")
			}
			u, isStr := v.(string)
			if !isStr {
				return fail("policy_uri_malformed", "policy.policy_uri is not a string")
			}
			// A malformed reference is a defect in the record, found with or without a
			// resolver.
			if err := uri.Absolute(u); err != nil {
				return fail("policy_uri_malformed", err.Error())
			}
			if s.opts.ResolvePolicy == nil {
				return skip("no policy resolver supplied")
			}
			want, _ := s.str("policy", "bundle_hash")
			bundle, err := s.opts.ResolvePolicy(u)
			if err != nil {
				return unverified("policy_unresolvable", err.Error())
			}
			got, err := digestOf(want, bundle)
			if err != nil {
				return skip(err.Error()) // TR-POL-001 reports the malformed digest
			}
			if got != want {
				return failf("policy_digest_mismatch", "the bundle at %s has digest %s, the record declares %s", u, got, want)
			}
			return pass()
		}},
	{ID: "TR-APR-001", Suite: "TR-APR-001", Section: "3.1 appraisal (EAR)", Stage: StageClaims,
		Check: func(s *state) Finding {
			st, _ := s.str("appraisal", "status")
			if !slices.Contains([]string{"affirming", "warning", "contraindicated", "none"}, st) {
				return fail("appraisal_status_invalid", "appraisal is absent or not an object, or appraisal.status is not affirming, warning, contraindicated or none")
			}
			return pass()
		}},
	{ID: "TR-APR-002", Suite: "TR-APR-002", Section: "3.1 appraisal; schema: appraisal.verifier (format uri)", Stage: StageClaims,
		Check: func(s *state) Finding {
			v, ok := s.str("appraisal", "verifier")
			if !ok {
				return fail("appraisal_verifier_invalid", "appraisal.verifier is absent or not a string")
			}
			if err := uri.Absolute(v); err != nil {
				return fail("appraisal_verifier_invalid", err.Error())
			}
			return pass()
		}},
	{ID: "TR-APR-003", Suite: "TR-APR-003", Section: "schema: appraisal.policy_ref (format uri)", Stage: StageClaims,
		Check: func(s *state) Finding {
			v, ok := s.get("appraisal", "policy_ref")
			if !ok {
				return skip("no policy_ref")
			}
			str, isStr := v.(string)
			if !isStr {
				return fail("appraisal_policy_ref_invalid", "appraisal.policy_ref is not a string")
			}
			if err := uri.Absolute(str); err != nil {
				return fail("appraisal_policy_ref_invalid", err.Error())
			}
			return pass()
		}},
	{ID: "TR-APR-004", Suite: "TR-APR-004", Section: "schema: appraisal.timestamp", Stage: StageClaims,
		Check: func(s *state) Finding {
			a, _ := s.get("appraisal")
			ao, _ := a.(*jcs.Object)
			if _, ok := ao.Get("timestamp"); !ok {
				return skip("no timestamp")
			}
			ts, err := integer(ao, "timestamp")
			if err != nil {
				return fail("appraisal_timestamp_invalid", err.Error())
			}
			if ts > s.now.Unix() {
				return failf("appraisal_timestamp_invalid", "appraisal.timestamp %d is in the future", ts)
			}
			return pass()
		}},
	{ID: "TR-APR-005", Suite: "TR-APR-005", Level: 1, Section: "trace-tests levels.md, level 1", Stage: StageClaims,
		Check: func(s *state) Finding {
			if st, _ := s.str("appraisal", "status"); st != "affirming" {
				return failf("appraisal_not_affirming", "appraisal.status is %q, not affirming", st)
			}
			return pass()
		}},
	{ID: "TR-RTE-001", Suite: "TR-RTE-001", Level: 1, Section: "3.1 runtime; schema: runtime.platform", Stage: StageClaims,
		Check: func(s *state) Finding {
			p, _ := s.str("runtime", "platform")
			if !slices.Contains(platforms, p) {
				return failf("runtime_platform_invalid", "runtime is absent or runtime.platform %q is not registered", p)
			}
			if p == "software-only" {
				return fail("runtime_platform_software_only", "software-only carries no hardware attestation evidence")
			}
			return pass()
		}},
	{ID: "TR-RTE-002", Suite: "TR-RTE-002", Level: 1, Section: "3.1 runtime; schema: runtime.measurement", Stage: StageClaims,
		Check: func(s *state) Finding {
			if m, ok := s.str("runtime", "measurement"); !ok || !digestPattern.MatchString(m) {
				return fail("runtime_measurement_invalid", "runtime.measurement is not sha256:<64 lowercase hex> or sha384:<96 lowercase hex>")
			}
			return pass()
		}},
	{ID: "TR-RTE-003", Suite: "TR-RTE-003", Level: 1, Section: "schema: runtime.rim_uri", Stage: StageClaims,
		Check: func(s *state) Finding {
			v, ok := s.get("runtime", "rim_uri")
			if !ok {
				return skip("no rim_uri")
			}
			str, _ := v.(string)
			if err := uri.HTTPSWithHost(str); err != nil {
				return fail("rim_uri_invalid", "runtime.rim_uri is not an https:// URI")
			}
			return pass()
		}},
	{ID: "TR-SCA-001", Suite: "TR-SCA-001", Level: 1, Section: "3.1 build_provenance (SLSA)", Stage: StageClaims,
		Check: func(s *state) Finding {
			bp, _ := s.get("build_provenance")
			bo, _ := bp.(*jcs.Object)
			if l, err := integer(bo, "slsa_level"); err != nil || l < 0 || l > 3 {
				return fail("slsa_level_invalid", "build_provenance.slsa_level is absent or not an integer from 0 to 3")
			}
			return pass()
		}},
	{ID: "TR-SCA-002", Suite: "TR-SCA-002", Level: 1, Section: "3.1 build_provenance; schema: build_provenance.digest", Stage: StageClaims,
		Check: func(s *state) Finding {
			// The schema admits sha384 as well; the suite's docs say sha256 (REPORT.md finding 5).
			if d, ok := s.str("build_provenance", "digest"); !ok || !digestPattern.MatchString(d) {
				return fail("build_digest_invalid", "build_provenance.digest is not sha256:<64 hex> or sha384:<96 hex>")
			}
			return pass()
		}},
	{ID: "TR-TXN-001", Suite: "TR-TXN-001", Level: 2, Section: "3.1 tool_transcript; schema: tool_transcript.hash", Stage: StageClaims,
		Check: func(s *state) Finding {
			// As TR-SCA-002: the schema admits sha384 (REPORT.md finding 5).
			if h, ok := s.str("tool_transcript", "hash"); !ok || !digestPattern.MatchString(h) {
				return fail("transcript_hash_invalid", "tool_transcript.hash is absent or not a valid digest")
			}
			return pass()
		}},
	{ID: "TR-TXN-002", Suite: "TR-TXN-002", Level: 2, Section: "3.1 tool_transcript; schema: tool_transcript.call_count", Stage: StageClaims,
		Check: func(s *state) Finding {
			tt, _ := s.get("tool_transcript")
			to, _ := tt.(*jcs.Object)
			if n, err := integer(to, "call_count"); err != nil || n < 0 {
				return fail("transcript_count_invalid", "tool_transcript.call_count is absent or not a non-negative integer")
			}
			return pass()
		}},
	{ID: "TR-ANC-001", Suite: "TR-ANC-001", Level: 2, Section: "3.1 transparency (SCITT receipt URI)", Stage: StageClaims,
		Check: func(s *state) Finding {
			t, _ := s.str("transparency")
			if err := uri.HTTPSWithHost(t); err != nil {
				return fail("transparency_uri_invalid", "transparency is absent, empty, not a string, or not an https:// URI with a host")
			}
			return pass()
		}},
	{ID: "TR-ANC-002", Suite: "TR-ANC-002", Level: 2, Section: "3.3 step 6; spec/registry-anchor-v1.md", Stage: StageClaims,
		Check: func(s *state) Finding {
			a := s.opts.Anchor
			if a == nil {
				return unverified("anchor_receipt_absent", "no inclusion proof and registry entry were supplied")
			}
			p, err := anchor.ParseProof(a.Proof)
			if err != nil {
				return fail("anchor_receipt_malformed", "inclusion proof: "+err.Error())
			}
			e, err := anchor.ParseEntry(a.Entry)
			if err != nil {
				return fail("anchor_receipt_malformed", "registry entry: "+err.Error())
			}
			// The anchored unit is the complete signed record, signature included, in
			// the anchor's own canonical form, not the signing one (Anchor Format v1
			// sections 0 and 1).
			c, err := anchor.CanonicalValue(s.rec)
			if err != nil {
				return fail("anchor_claim_outside_profile", err.Error())
			}
			if err := anchor.VerifyLeaf(anchor.LeafHash(c), p, e); err != nil {
				return fail("anchor_inclusion_failed", err.Error())
			}
			return pass()
		}},
}

var (
	subjectPattern = regexp.MustCompile(`^(spiffe://[^/]+/.+|did:[a-z0-9]+:.+)$`)
	digestPattern  = regexp.MustCompile(`^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$`)
	platforms      = []string{"intel-tdx", "amd-sev-snp", "azure-cvm-sev-snp", "nvidia-h100", "nvidia-blackwell",
		"aws-nitro", "arm-cca", "google-confidential-space", "tpm2", "software-only"}
)

// digestOf computes the digest of b in the algorithm the declared value names.
func digestOf(declared string, b []byte) (string, error) {
	switch {
	case strings.HasPrefix(declared, "sha256:"):
		d := sha256.Sum256(b)
		return "sha256:" + hex.EncodeToString(d[:]), nil
	case strings.HasPrefix(declared, "sha384:"):
		d := sha512.Sum384(b)
		return "sha384:" + hex.EncodeToString(d[:]), nil
	}
	return "", fmt.Errorf("declared digest %q names no supported algorithm", declared)
}

const maxSafe = 1<<53 - 1

func outOfRange(v any, path string) (string, jcs.Number, bool) {
	switch v := v.(type) {
	case jcs.Number:
		if math.Abs(v.Float) > maxSafe {
			return path, v, true
		}
	case []any:
		for i, e := range v {
			if p, n, bad := outOfRange(e, fmt.Sprintf("%s[%d]", path, i)); bad {
				return p, n, true
			}
		}
	case *jcs.Object:
		if v == nil {
			break
		}
		for _, m := range v.Members {
			if p, n, bad := outOfRange(m.Value, path+"."+m.Name); bad {
				return p, n, true
			}
		}
	}
	return "", jcs.Number{}, false
}

// integer reads a member that must be a JSON integer (a number with no fractional part).
func integer(o *jcs.Object, name string) (int64, error) {
	v, ok := o.Get(name)
	if !ok {
		return 0, fmt.Errorf("%s is absent", name)
	}
	n, isNum := v.(jcs.Number)
	if !isNum || n.Float != math.Trunc(n.Float) || math.Abs(n.Float) > maxSafe {
		return 0, fmt.Errorf("%s is not an integer in the safe range", name)
	}
	return int64(n.Float), nil
}
