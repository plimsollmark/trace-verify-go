package record

import (
	"fmt"
	"slices"
	"time"
)

// Verify checks one Trust Record with an embedded signature against the registry.
func Verify(data []byte, opts Options) Result {
	return VerifyWith(Rules, data, opts)
}

// VerifyWith runs the given rules instead of the registry. It exists for the mutation
// check (delete a rule, see which vectors notice) and is not a way to relax verification.
func VerifyWith(rules []Rule, data []byte, opts Options) Result {
	s := &state{opts: opts, now: opts.Now, raw: data}
	if s.now.IsZero() {
		s.now = time.Now()
	}
	res := Result{Outcome: Verified}
	stopped := Stage(-1) // the stage whose failure stopped evaluation, if any
	for i, r := range rules {
		if i > 0 && r.Stage < rules[i-1].Stage {
			panic(fmt.Sprintf("record: rule %s is out of stage order", r.ID))
		}
		var f Finding
		if stopped >= 0 && r.Stage > stopped {
			f = skip("not reached")
		} else {
			f = r.Check(s)
		}
		f.Rule, f.Section = r.ID, r.Section
		res.Findings = append(res.Findings, f)
		if f.Status != Fail && f.Status != Unverified {
			continue
		}
		if stopped < 0 {
			stopped = r.Stage
			res.Code = f.Code
			if r.Stage == StageConfig || r.Stage == StageProfile {
				res.Outcome = Refused
			} else {
				res.Outcome = Rejected
			}
		}
	}
	if res.Outcome == Verified {
		if s.rec == nil || s.key == nil { // only reachable with rules deleted
			res.Outcome, res.Code = Rejected, "not_evaluated"
			return res
		}
		p, _ := s.rec.Get("eat_profile")
		res.Profile, _ = p.(string)
		res.AcceptedProfiles = slices.Clone(opts.AcceptedProfiles)
		res.KeyThumbprint = s.key.Thumbprint()
	}
	return res
}
