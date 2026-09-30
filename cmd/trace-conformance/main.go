// Command trace-conformance runs the vendored TRACE vectors against this verifier and
// writes a self-contained HTML page: every set, every vector's expected and actual
// verdict, which rules the vectors can tell apart, and the findings from REPORT.md. It
// also writes the conformance statement, in the form TRACE v0.2 "Authority and
// conformance claims" asks for, from the same run.
//
//	go run ./cmd/trace-conformance
//
// The output carries no timestamp, so it changes only when a verdict does.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"html"
	"html/template"
	"io"
	"os"
	"regexp"
	"strings"
	texttemplate "text/template"

	"github.com/plimsollmark/trace-verify-go/internal/conformance"
	"github.com/plimsollmark/trace-verify-go/schema"
)

func main() {
	root := flag.String("vectors", "testdata/vectors", "the vendored vectors")
	report := flag.String("report", "REPORT.md", "the report whose findings the page shows")
	out := flag.String("out", "docs/conformance.html", "where to write the page")
	statement := flag.String("statement", "docs/conformance-statement.md", "where to write the conformance statement")
	flag.Parse()
	disagree, err := run(*root, *report, *out, *statement)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trace-conformance:", err)
		os.Exit(2)
	}
	if disagree > 0 {
		os.Exit(1)
	}
}

type row struct {
	File, Name, Expected, Got, Source string
	State                             string // agree, disagree, none
	Problems, Notes                   []string
}

type setView struct {
	Name, Slug, About, Dir string
	Rows                   []row
	Agree, Judged, None    int
	Files                  int // distinct vector files; a file run more than once is several cases
	Err                    string
}

type ruleView struct {
	ID, Suite, Section, Reason, Verifier string
	Level, Changed                       int
	Width                                int // bar width in pixels
}

type page struct {
	SpecCommit, SuiteTag, SchemaSHA string
	Version                         string
	Agree, Disagree, None, Judged   int
	Files                           int
	Rules, Distinguished            int
	Sets                            []setView
	RuleRows                        []ruleView
	Findings                        []template.HTML
}

func run(root, reportPath, out, statementOut string) (disagree int, err error) {
	p := page{SpecCommit: conformance.SpecCommit, SuiteTag: conformance.SuiteTag, SchemaSHA: schema.TraceClaimV02SHA256,
		Version: conformance.VerifierVersion}
	for _, sr := range conformance.Run(root, conformance.Sets, conformance.Default()) {
		sv := setView{Name: sr.Set.Name, Slug: "set-" + strings.ReplaceAll(sr.Set.Name, " ", "-"), About: sr.Set.About, Dir: sr.Set.Dir}
		if sr.Err != nil {
			sv.Err = sr.Err.Error()
		}
		seen := map[string]bool{}
		for _, v := range sr.Verdicts {
			// A repeated run is marked by a suffix on its file: #reversed, #no-resolver,
			// or a provenance depth.
			if f, _, _ := strings.Cut(v.Case.File, "#"); !seen[f] {
				seen[f] = true
				sv.Files++
			}
			r := row{File: strings.TrimPrefix(v.Case.File, sr.Set.Dir+"/"), Name: v.Case.Name,
				Expected: expected(v.Case.Expect), Got: got(v), Source: v.Case.Expect.Source,
				Problems: v.Problems, Notes: v.Notes}
			switch {
			case v.Case.Expect.Informational():
				r.State = "none"
				sv.None++
				p.None++
			case v.Passed():
				r.State = "agree"
				sv.Agree++
				sv.Judged++
			default:
				r.State = "disagree"
				sv.Judged++
			}
			sv.Rows = append(sv.Rows, r)
		}
		p.Agree += sv.Agree
		p.Judged += sv.Judged
		p.Files += sv.Files
		p.Sets = append(p.Sets, sv)
	}
	p.Disagree = p.Judged - p.Agree

	cov := conformance.Mutation(root, conformance.Sets, conformance.Default())
	most := 1
	for _, c := range cov {
		most = max(most, len(c.Changed))
	}
	for _, c := range cov {
		rv := ruleView{ID: c.ID, Suite: c.Suite, Section: c.Section, Level: c.Level, Verifier: c.Verifier,
			Changed: len(c.Changed), Width: 2 + 200*len(c.Changed)/most}
		if len(c.Changed) == 0 {
			rv.Reason = conformance.Uncovered[c.ID]
		} else {
			p.Distinguished++
		}
		p.RuleRows = append(p.RuleRows, rv)
	}
	p.Rules = len(cov)

	reportText, err := os.ReadFile(reportPath)
	if err != nil {
		return 0, err
	}
	p.Findings = findings(string(reportText))
	if len(p.Findings) == 0 {
		return 0, fmt.Errorf("%s has no numbered list under %q", reportPath, findingsHeading)
	}
	// The report quotes the headline; it must be the one this run produced.
	if headline := fmt.Sprintf("%d of %d judged cases agree, from %d vector files", p.Agree, p.Judged, p.Files); !strings.Contains(string(reportText), headline) {
		return 0, fmt.Errorf("%s does not say %q", reportPath, headline)
	}

	for _, w := range []struct {
		t    interface{ Execute(io.Writer, any) error }
		path string
	}{{tmpl, out}, {statementTmpl, statementOut}} {
		var buf bytes.Buffer
		if err := w.t.Execute(&buf, p); err != nil {
			return 0, err
		}
		if err := os.WriteFile(w.path, buf.Bytes(), 0o644); err != nil {
			return 0, err
		}
	}
	fmt.Printf("%s: %d of %d judged cases agree (from %d vector files), %d reported without an expectation; %d of %d rules distinguished by a vector\n",
		out, p.Agree, p.Judged, p.Files, p.None, p.Distinguished, p.Rules)
	return p.Disagree, nil
}

func expected(e conformance.Expect) string {
	switch {
	case e.Informational():
		return "none stated"
	case e.Finding != nil:
		return e.Finding.Rule + " " + string(e.Finding.Status)
	case e.Codes != nil:
		if len(e.Codes) == 0 {
			return e.Outcome
		}
		return e.Outcome + " (" + strings.Join(e.Codes, ", ") + ")"
	case e.Code != "" && e.CodeInformative:
		return e.Outcome + " (" + e.Code + ", informative)"
	case e.Code != "":
		return e.Outcome + " (" + e.Code + ")"
	}
	return e.Outcome
}

func got(v conformance.Verdict) string {
	if f := v.Case.Expect.Finding; f != nil && v.Got.Record != nil {
		if g, ok := v.Got.Record.Finding(f.Rule); ok {
			return f.Rule + " " + string(g.Status)
		}
	}
	if v.Got.Outcome == "" {
		return "not run"
	}
	if len(v.Got.Codes) > 0 {
		return v.Got.Outcome + " (" + strings.Join(v.Got.Codes, ", ") + ")"
	}
	if v.Got.Code != "" {
		return v.Got.Outcome + " (" + v.Got.Code + ")"
	}
	return v.Got.Outcome
}

var (
	itemStart = regexp.MustCompile(`(?m)^\d+\. `)
	bold      = regexp.MustCompile(`\*\*(.+?)\*\*`)
	code      = regexp.MustCompile("`([^`]+)`")
)

const findingsHeading = "\n## Findings\n"

// findings renders REPORT.md's numbered findings list, which stays the one home for them.
func findings(report string) []template.HTML {
	_, rest, ok := strings.Cut(report, findingsHeading)
	if !ok {
		return nil
	}
	if i := strings.Index(rest, "\n## "); i >= 0 {
		rest = rest[:i]
	}
	var out []template.HTML
	locs := itemStart.FindAllStringIndex(rest, -1)
	for i, l := range locs {
		end := len(rest)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		text := strings.Join(strings.Fields(rest[l[1]:end]), " ")
		text = html.EscapeString(text)
		text = bold.ReplaceAllString(text, "<strong>$1</strong>")
		text = code.ReplaceAllString(text, "<code>$1</code>")
		out = append(out, template.HTML(text)) // escaped above; only strong and code are added
	}
	return out
}

var tmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TRACE v0.2 conformance: trace-verify-go</title>
<style>
:root { color-scheme: light; --ink:#1d2330; --muted:#5b6475; --line:#dde2ea; --bg:#ffffff; --panel:#f6f8fb;
  --good:#1f7a3d; --good-bg:#e7f5ec; --bad:#b3261e; --bad-bg:#fbe9e7; --none:#5b6475; --none-bg:#eef1f5; --bar:#3b6fb6; }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 1120px; margin: 0 auto; padding: 28px 20px 60px; }
h1 { font-size: 26px; margin: 0 0 4px; }
h2 { font-size: 19px; margin: 36px 0 8px; padding-top: 8px; border-top: 1px solid var(--line); }
h3 { font-size: 16px; margin: 24px 0 4px; }
p.lede { color: var(--muted); margin: 0 0 16px; max-width: 820px; }
.pins { font-size: 13px; color: var(--muted); background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 10px 14px; }
.pins code { color: var(--ink); }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; margin: 18px 0; }
.tile { border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; background: var(--panel); }
.tile .n { font-size: 28px; font-weight: 650; }
.tile .l { color: var(--muted); font-size: 13px; }
table { border-collapse: collapse; width: 100%; font-size: 13.5px; }
th, td { text-align: left; vertical-align: top; padding: 6px 8px; border-bottom: 1px solid var(--line); }
th { color: var(--muted); font-weight: 600; font-size: 12.5px; }
td.file { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; word-break: break-all; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.92em; background: var(--panel); padding: 0 3px; border-radius: 3px; }
.pins code, ol.findings code { overflow-wrap: anywhere; }
td.nowrap, td.nowrap code { white-space: nowrap; }
.st { display: inline-block; white-space: nowrap; border-radius: 999px; padding: 1px 9px; font-size: 12px; font-weight: 600; }
.st.agree { color: var(--good); background: var(--good-bg); }
.st.disagree { color: var(--bad); background: var(--bad-bg); }
.st.none { color: var(--none); background: var(--none-bg); }
.small { color: var(--muted); font-size: 12px; }
.bar { display: inline-block; height: 10px; background: var(--bar); border-radius: 0 3px 3px 0; vertical-align: middle; margin-right: 6px; }
.bar.zero { background: var(--line); }
ol.findings li { margin: 0 0 10px; max-width: 900px; }
.wrap { overflow-x: auto; }
</style>
</head>
<body>
<main>
<h1>TRACE v0.2 conformance: trace-verify-go</h1>
<p class="lede">A Go verifier for TRACE Trust Records, written from the specification alone, run against the TRACE project's own published vectors. Each vector's expectation comes from the vector file; where a file states none, the row says where the expectation came from, or that there is none.</p>
<div class="pins">Specification and schema: <code>agentrust-io/trace-spec</code> at <code>{{.SpecCommit}}</code>, schema SHA-256 <code>{{.SchemaSHA}}</code>. Suite vectors: <code>agentrust-io/trace-tests</code> <code>{{.SuiteTag}}</code>. Verifier: <code>trace-verify-go</code> <code>{{.Version}}</code>. The claim in full: <code>docs/conformance-statement.md</code>.</div>

<div class="tiles">
  <div class="tile"><div class="n">{{.Agree}} of {{.Judged}}</div><div class="l">judged cases agree, from {{.Files}} vector files (a file run more than once is several cases)</div></div>
  <div class="tile"><div class="n">{{.Disagree}}</div><div class="l">cases disagree</div></div>
  <div class="tile"><div class="n">{{.None}}</div><div class="l">run and shown without a verdict (the vector states none)</div></div>
  <div class="tile"><div class="n">{{.Distinguished}} of {{.Rules}}</div><div class="l">rules whose deletion some vector notices</div></div>
</div>

<h2>Vector sets</h2>
<div class="wrap"><table>
<tr><th>Set</th><th>What it tests</th><th>Agree</th></tr>
{{range .Sets}}<tr><td><a href="#{{.Slug}}">{{.Name}}</a></td><td>{{.About}}{{if .Err}}<br><span class="st disagree">✗ could not load: {{.Err}}</span>{{end}}</td><td>{{.Agree}} of {{.Judged}}</td></tr>
{{end}}</table></div>

<h2 id="findings">Findings for the TRACE project</h2>
<p class="small">From <code>REPORT.md</code>, where they are kept. Each is something a second implementation surfaced about the specification, the schema or the suite.</p>
<ol class="findings">{{range .Findings}}<li>{{.}}</li>{{end}}</ol>

<h2 id="rules">Which rules the vectors can tell apart</h2>
<p class="small">Each rule is deleted in turn and the vectors are re-run: the bar is the number of vectors whose verdict changes. A rule no vector notices could be missing from an implementation that still passes every vector; the reason column says why, and where this repository tests it instead.</p>
<div class="wrap"><table>
<tr><th>Rule</th><th>Verifier</th><th>Suite code</th><th>Level</th><th>Vectors that notice its deletion</th><th>Source</th></tr>
{{range .RuleRows}}<tr><td class="nowrap"><code>{{.ID}}</code></td><td>{{.Verifier}}</td><td class="nowrap">{{.Suite}}</td><td>{{.Level}}</td>
<td>{{if .Changed}}<span class="bar" style="width:{{.Width}}px"></span>{{.Changed}}{{else}}<span class="bar zero" style="width:2px"></span>0<br><span class="small">{{.Reason}}</span>{{end}}</td><td class="small">{{.Section}}</td></tr>
{{end}}</table></div>

<h2>Every vector</h2>
{{range .Sets}}<h3 id="{{.Slug}}">{{.Name}} <span class="small">{{.Dir}}</span></h3>
<div class="wrap"><table>
<tr><th>Vector</th><th>Expected</th><th>This verifier</th><th>Result</th></tr>
{{range .Rows}}<tr><td class="file">{{.File}}</td><td>{{.Expected}}{{if .Source}}<br><span class="small">{{.Source}}</span>{{end}}</td><td>{{.Got}}</td>
<td>{{if eq .State "agree"}}<span class="st agree">✓ agrees</span>{{else if eq .State "disagree"}}<span class="st disagree">✗ disagrees</span>{{else}}<span class="st none">– no expectation</span>{{end}}
{{range .Problems}}<br><span class="small">{{.}}</span>{{end}}{{range .Notes}}<br><span class="small">note: {{.}}</span>{{end}}</td></tr>
{{end}}</table></div>
{{end}}
</main>
</body>
</html>
`))

// statementTmpl is the conformance statement, in Markdown.
var statementTmpl = texttemplate.Must(texttemplate.New("statement").Parse(`# Conformance statement: trace-verify-go {{.Version}}

Generated by ` + "`go run ./cmd/trace-conformance`" + ` from the vectors this repository vendors. Do not edit;
regenerate. It is a statement about a verifier, not about any Trust Record, made in the
form TRACE v0.2 "Authority and conformance claims" asks for.

| | |
|---|---|
| Specification | TRACE v0.2 (draft), ` + "`agentrust-io/trace-spec`" + ` at commit ` + "`{{.SpecCommit}}`" + ` (an unreleased checkout, so the full commit is named) |
| Schema used for validation | ` + "`schema/trace-claim.json`" + `, SHA-256 ` + "`{{.SchemaSHA}}`" + ` |
| Normative companion | TRACE Registry Anchor Format v1, ` + "`spec/registry-anchor-v1.md`" + ` at the same commit |
| Conformance suite | ` + "`agentrust-io/trace-tests`" + ` ` + "`{{.SuiteTag}}`" + `: its vectors and its documented checks; its runner was not used |
| Verifier | ` + "`trace-verify-go`" + ` {{.Version}}, Go, standard library only |
| Assessed | the specification's verification (3.3) with the declared profile set ` + "`tag:agentrust-io.com,2026:trace-v0.2`" + `, and the suite's level check at levels 0, 1 and 2 |

## Result

{{.Agree}} of {{.Judged}} judged cases agree, from {{.Files}} vector files; {{.Disagree}} disagree; {{.None}} run and reported
without a verdict, because the vector states none. A file run more than once is several
cases: delegation vectors in both record orders, build-provenance vectors at each depth,
and policy-resolution vectors with and without a resolver.

| Set | Source | Files | Cases that agree | Without a verdict |
|---|---|---|---|---|
{{range .Sets}}| {{.Name}} | ` + "`{{.Dir}}`" + ` | {{.Files}} | {{.Agree}} of {{.Judged}} | {{.None}} |
{{end}}
## What the vectors can tell apart

Deleting one rule at a time and rerunning every vector, the method of trace-spec
` + "`docs/conformance-method.md`" + `: {{.Distinguished}} of this verifier's {{.Rules}} rules change some vector's verdict. The
others are listed, each with the reason no vector notices it, on the conformance page.

## Scope

Which verification steps of spec 3.3 this verifier performs, and which it does not, is in
` + "`REPORT.md`" + `, "What is verified". Passing these vectors is not complete conformance:
several rules have no vector (` + "`REPORT.md`" + ` findings 8, 17 and 22).
`))
