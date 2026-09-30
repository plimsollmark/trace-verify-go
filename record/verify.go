package record

import (
	"fmt"
	"slices"
	"time"
)

// Verify performs the specification's verification (ModeVerify) of one Trust Record
// with an embedded signature.
func Verify(data []byte, opts Options) Result {
	opts.Mode = ModeVerify
	return Evaluate(Rules, data, opts)
}

// CheckLevel performs the suite's conformance-level check (ModeLevel) at level.
func CheckLevel(data []byte, level int, opts Options) Result {
	opts.Mode, opts.Level = ModeLevel, level
	return Evaluate(Rules, data, opts)
}

// Evaluate runs the given rules in the mode opts names. Passing a registry other than
// Rules exists for the mutation check (delete a rule, see which vectors notice); it is
// not a way to relax verification.
func Evaluate(rules []Rule, data []byte, opts Options) Result {
	if opts.Mode == ModeLevel && len(opts.AcceptedProfiles) == 0 {
		opts.AcceptedProfiles = []string{ProfileV02}
	}
	s := &state{opts: opts, now: opts.Now, raw: data}
	if s.now.IsZero() {
		s.now = time.Now()
	}
	res := Result{Mode: opts.Mode, Level: opts.Level, Outcome: Verified}
	stopped := Stage(-1) // the stage whose failure stops later stages, if any
	var firstUnverified string
	for i, r := range rules {
		if i > 0 && r.Stage < rules[i-1].Stage {
			panic(fmt.Sprintf("record: rule %s is out of stage order", r.ID))
		}
		var f Finding
		switch {
		case stopped >= 0 && r.Stage > stopped:
			f = skip("not reached")
		case r.Stage > StageInput && s.rec == nil:
			f = skip("no parsed record")
		case r.Level > opts.Level:
			f = skip(fmt.Sprintf("required from level %d", r.Level))
		default:
			f = r.Check(s)
		}
		f.Rule, f.Suite, f.Section = r.ID, r.Suite, r.Section
		res.Findings = append(res.Findings, f)

		failed := f.Status == Fail
		if f.Status == Unverified {
			if opts.Mode == ModeLevel {
				from, ok := unverifiedFailsFrom[r.Suite]
				if !ok {
					from = 1
				}
				failed = opts.Level >= from
			} else if firstUnverified == "" {
				firstUnverified = f.Code
			}
		}
		if !failed || res.Outcome == Rejected || res.Outcome == Refused {
			continue
		}
		res.Code = f.Code
		switch {
		case opts.Mode == ModeVerify && (r.Stage == StageConfig || r.Stage == StageProfile):
			res.Outcome = Refused
		default:
			res.Outcome = Rejected
		}
		if opts.Mode == ModeVerify || r.Stage == StageInput {
			stopped = r.Stage
		}
	}
	if res.Outcome == Verified && firstUnverified != "" {
		res.Outcome, res.Code = OutcomeUnverified, firstUnverified
	}
	if res.Outcome == Verified && (s.rec == nil || (opts.Mode == ModeVerify && s.key == nil)) {
		res.Outcome, res.Code = Rejected, "not_evaluated" // only reachable with rules deleted
	}
	if res.Outcome == Verified {
		res.Profile, _ = s.str("eat_profile")
		res.AcceptedProfiles = slices.Clone(opts.AcceptedProfiles)
	}
	if s.key != nil {
		if f, _ := res.Finding("signature"); f.Status == Pass {
			res.KeyThumbprint = s.key.Thumbprint()
		}
	}
	return res
}
