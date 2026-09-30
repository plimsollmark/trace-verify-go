package record

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/jwk"
)

// Stage orders the rules. When any rule in a stage fails, every rule in later stages is
// reported as skipped (not reached): in particular, no claim is read as evidence until
// the signature binding holds (spec 3.3, step 1: "BEFORE any other field is trusted").
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
	Section string
	Stage   Stage
	Check   func(*state) Finding // Rule and Section are filled in by Verify
}

// state is what the rules share within one verification.
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

// Rules is the registry, in evaluation order.
var Rules = []Rule{
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
			// "No object canonicalized under this section may carry an integer outside
			// that range, and one that does MUST be rejected." Every double of magnitude
			// 2^53 or more is an integer, and every literal whose double is below 2^53 is
			// either not an integer or inside the range, so the double decides it.
			if s.rec == nil {
				return skip("no parsed record")
			}
			if path, n, bad := outOfRange(s.rec, "$"); bad {
				return failf("integer_out_of_range", "%s is %s, outside -(2^53-1) to 2^53-1", path, n.Literal)
			}
			return pass()
		}},

	{ID: "profile_present", Section: "3.3 Verifier profile compatibility", Stage: StageProfile,
		Check: func(s *state) Finding {
			// Read before the signature only to select semantics; nothing else is.
			p, ok := s.rec.Get("eat_profile")
			if str, isStr := p.(string); !ok || !isStr || str == "" {
				return fail("profile_absent", "eat_profile is absent, not a string, or empty")
			}
			return pass()
		}},
	{ID: "profile_accepted", Section: "3.3 Verifier profile compatibility; Changes from v0.1", Stage: StageProfile,
		Check: func(s *state) Finding {
			p, _ := s.rec.Get("eat_profile")
			if str, _ := p.(string); !slices.Contains(s.opts.AcceptedProfiles, str) {
				return failf("profile_not_accepted", "eat_profile %q is outside the declared set", p)
			}
			return pass()
		}},

	{ID: "cnf_key", Section: "3.1 cnf; 3.2.2 Signature binding", Stage: StageBinding,
		Check: func(s *state) Finding {
			cnf, ok := s.rec.Get("cnf")
			co, isObj := cnf.(*jcs.Object)
			if !ok || !isObj {
				return fail("cnf_absent", "cnf is absent or not an object")
			}
			j, ok := co.Get("jwk")
			if !ok {
				return fail("cnf_absent", "cnf.jwk is absent")
			}
			k, err := jwk.Parse(j)
			switch {
			case errors.Is(err, jwk.ErrPrivate):
				return fail("cnf_key_private", err.Error())
			case errors.Is(err, jwk.ErrUnsupported):
				return fail("cnf_key_unsupported", err.Error())
			case err != nil:
				return fail("cnf_key_invalid", err.Error())
			}
			s.key = k
			return pass()
		}},
	{ID: "signature", Section: "3.2.2 Signature binding (embedded); 3.3 step 1", Stage: StageBinding,
		Check: func(s *state) Finding {
			if s.key == nil {
				return skip("no usable cnf key")
			}
			v, ok := s.rec.Get("signature")
			if !ok {
				return fail("signature_absent", "no embedded signature; a record with no verifiable signature binding is not a Trust Record")
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
	{ID: "key_pinned", Section: "verifier policy (Options.PinnedKeys)", Stage: StageBinding,
		Check: func(s *state) Finding {
			if len(s.opts.PinnedKeys) == 0 {
				return skip("no keys pinned")
			}
			if s.key == nil {
				return skip("no usable cnf key")
			}
			if !slices.Contains(s.opts.PinnedKeys, s.key.Thumbprint()) {
				return failf("key_not_pinned", "cnf key %s is not a pinned key", s.key.Thumbprint())
			}
			return pass()
		}},

	{ID: "freshness", Section: "3.2.2 Freshness; 3.3 step 2", Stage: StageClaims,
		Check: func(s *state) Finding {
			iat, err := integer(s.rec, "iat")
			if err != nil {
				return fail("iat_invalid", err.Error())
			}
			if s.opts.SkipFreshness {
				return skip("freshness not applied (archived record)")
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
	{ID: "nonce", Section: "3.2.2 Freshness (challenge nonce)", Stage: StageClaims,
		Check: func(s *state) Finding {
			if s.opts.Nonce == "" {
				return skip("no challenge nonce issued")
			}
			rt, _ := s.rec.Get("runtime")
			ro, _ := rt.(*jcs.Object)
			var got any
			if ro != nil {
				got, _ = ro.Get("nonce")
			}
			if got != s.opts.Nonce {
				return fail("nonce_mismatch", "runtime.nonce is absent or does not echo the issued nonce")
			}
			return pass()
		}},
	{ID: "origin_platform", Section: "3.1.1 origin", Stage: StageClaims,
		Check: func(s *state) Finding {
			v, ok := s.rec.Get("origin")
			if !ok {
				return skip("no origin block: the record is self")
			}
			o, isObj := v.(*jcs.Object)
			if !isObj {
				return fail("origin_invalid", "origin is not an object")
			}
			kind, _ := o.Get("kind")
			switch kind {
			case "self":
				return pass()
			case "third-party-control-plane", "log-import":
			default:
				return failf("origin_invalid", "origin.kind %v is not in the closed set", kind)
			}
			rt, _ := s.rec.Get("runtime")
			ro, _ := rt.(*jcs.Object)
			var platform any
			if ro != nil {
				platform, _ = ro.Get("platform")
			}
			if platform != "software-only" {
				return failf("origin_platform_not_software_only",
					"origin.kind %q requires runtime.platform \"software-only\", found %v", kind, platform)
			}
			return pass()
		}},
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
	if !isNum || n.Float != math.Trunc(n.Float) {
		return 0, fmt.Errorf("%s is not an integer", name)
	}
	return int64(n.Float), nil // integer_range has already bounded it
}
