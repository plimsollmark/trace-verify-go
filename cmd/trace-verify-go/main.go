// Command trace-verify-go checks one TRACE v0.2 Trust Record.
//
//	trace-verify-go [flags] record.json      (or - for standard input)
//
// By default it performs the specification's verification (spec 3.3): the signature
// binding first, then every claim. The issuer is authenticated only by a pinned key
// (-pin or -pin-jwk); with none, the result is unverified unless -trust-embedded-key
// says to accept the record's own cnf key. With -level N it performs the conformance suite's
// level check instead. Exit status: 0 verified (or the level is met), 1 anything else
// (rejected, refused, or unverified), 2 a usage or input error.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/plimsollmark/trace-verify-go/internal/policydir"
	"github.com/plimsollmark/trace-verify-go/jcs"
	"github.com/plimsollmark/trace-verify-go/jwk"
	"github.com/plimsollmark/trace-verify-go/record"
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trace-verify-go", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var accept, pins, pinFiles list
	level := fs.Int("level", -1, "perform the suite's level check at `N` (0, 1 or 2) instead of the spec's verification")
	fs.Var(&accept, "accept", "a `profile` the verifier accepts (repeatable; default the v0.2 profile)")
	fs.Var(&pins, "pin", "an RFC 7638 `thumbprint` of a trusted signing key (repeatable)")
	fs.Var(&pinFiles, "pin-jwk", "a `file` holding a trusted public JWK (repeatable)")
	trustEmbedded := fs.Bool("trust-embedded-key", false, "with no key pinned, accept the record's own cnf key as its issuer's (no issuer authentication; without a pin or this flag the result is UNVERIFIED)")
	now := fs.Int64("now", 0, "verification time in Unix `seconds` (default: the current time)")
	archived := fs.Bool("archived", false, "do not apply the age bounds to iat (checking an archived record)")
	maxAge := fs.Duration("max-age", 0, "maximum record age (default 24h, spec 3.2.2)")
	skew := fs.Duration("skew", 0, "allowed clock skew (default 5m, spec 3.2.2)")
	nonce := fs.String("nonce", "", "the challenge nonce this verifier issued")
	policyDir := fs.String("policy-dir", "", "a `directory` with resolutions.json, for resolving policy.policy_uri (TR-POL-003)")
	anchorProof := fs.String("anchor-proof", "", "an inclusion proof `file` for TR-ANC-002 (with -anchor-entry)")
	anchorEntry := fs.String("anchor-entry", "", "the registry entry `file` the proof is against, one JSON object (with -anchor-proof)")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	all := fs.Bool("v", false, "also list rules that were skipped")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: trace-verify-go [flags] record.json|-")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	var data []byte
	var err error
	if fs.Arg(0) == "-" {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(fs.Arg(0))
	}
	if err != nil {
		fmt.Fprintln(stderr, "trace-verify-go:", err)
		return 2
	}

	opts := record.Options{AcceptedProfiles: accept, PinnedKeys: pins, TrustEmbeddedKey: *trustEmbedded,
		SkipFreshness: *archived, MaxAge: *maxAge, ClockSkew: *skew, Nonce: *nonce}
	if len(opts.AcceptedProfiles) == 0 {
		opts.AcceptedProfiles = []string{record.ProfileV02}
	}
	if *now != 0 {
		opts.Now = time.Unix(*now, 0)
	}
	for _, f := range pinFiles {
		t, err := thumbprint(f)
		if err != nil {
			fmt.Fprintln(stderr, "trace-verify-go:", err)
			return 2
		}
		opts.PinnedKeys = append(opts.PinnedKeys, t)
	}
	if (*anchorProof == "") != (*anchorEntry == "") {
		fmt.Fprintln(stderr, "trace-verify-go: -anchor-proof and -anchor-entry go together")
		return 2
	}
	if *anchorProof != "" {
		opts.Anchor = &record.Anchor{}
		for _, f := range []struct {
			path string
			into *[]byte
		}{{*anchorProof, &opts.Anchor.Proof}, {*anchorEntry, &opts.Anchor.Entry}} {
			if *f.into, err = os.ReadFile(f.path); err != nil {
				fmt.Fprintln(stderr, "trace-verify-go:", err)
				return 2
			}
			*f.into = bytes.TrimSpace(*f.into)
		}
	}
	if *policyDir != "" {
		if opts.ResolvePolicy, err = policydir.Open(*policyDir); err != nil {
			fmt.Fprintln(stderr, "trace-verify-go:", err)
			return 2
		}
	}

	var res record.Result
	switch *level {
	case -1:
		res = record.Verify(data, opts)
	case 0, 1, 2:
		res = record.CheckLevel(data, *level, opts)
	default:
		fmt.Fprintln(stderr, "trace-verify-go: -level must be 0, 1 or 2")
		return 2
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintln(stderr, "trace-verify-go:", err)
			return 2
		}
	} else {
		report(stdout, res, *all)
	}
	if res.Outcome == record.Verified {
		return 0
	}
	return 1
}

func thumbprint(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	v, err := jcs.Parse(b)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	k, err := jwk.Parse(v)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return k.Thumbprint(), nil
}

func report(w io.Writer, r record.Result, all bool) {
	what := "verification (spec 3.3)"
	if r.Mode == record.ModeLevel {
		what = fmt.Sprintf("level %d check (trace-tests levels)", r.Level)
	}
	fmt.Fprintf(w, "%s: %s", what, strings.ToUpper(string(r.Outcome)))
	if r.Code != "" {
		fmt.Fprintf(w, " (%s)", r.Code)
	}
	fmt.Fprintln(w)
	if r.Outcome == record.Verified && r.Mode == record.ModeVerify {
		fmt.Fprintf(w, "profile %s under accepted set %v; key %s\n", r.Profile, r.AcceptedProfiles, r.KeyThumbprint)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "\nSTATUS\tRULE\tSUITE\tDETAIL")
	for _, f := range r.Findings {
		if f.Status == record.Skip && !all && !strings.HasPrefix(f.Detail, "no keys pinned") {
			continue
		}
		detail := f.Detail
		if f.Code != "" {
			detail = f.Code + ": " + detail
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Status, f.Rule, f.Suite, detail)
	}
	tw.Flush()
}
