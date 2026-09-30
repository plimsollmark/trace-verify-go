// Command trace-conformance runs the vendored TRACE vectors against this verifier and
// writes a self-contained HTML page: every set, every vector's expected and actual
// verdict, which rules the vectors can tell apart, and the findings from PLAN.md.
//
//	go run ./cmd/trace-conformance -out docs/conformance.html
//
// The output carries no timestamp, so it changes only when a verdict does.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"html"
	"html/template"
	"os"
	"regexp"
	"strings"

	"github.com/plimsollmark/trace-verify-go/internal/conformance"
	"github.com/plimsollmark/trace-verify-go/record"
	"github.com/plimsollmark/trace-verify-go/schema"
)

func main() {
	root := flag.String("vectors", "testdata/vectors", "the vendored vectors")
	plan := flag.String("plan", "PLAN.md", "the plan whose findings the page shows")
	out := flag.String("out", "docs/conformance.html", "where to write the page")
	flag.Parse()
	disagree, err := run(*root, *plan, *out)
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
	Agree, Judged          int
	Err                    string
}

type ruleView struct {
	ID, Suite, Section, Reason string
	Level, Changed             int
	Width                      int // bar width in pixels
}

type page struct {
	SpecCommit, SuiteTag, SchemaSHA string
	Agree, Disagree, None, Judged   int
	Rules, Distinguished            int
	Sets                            []setView
	RuleRows                        []ruleView
	Findings                        []template.HTML
}

func run(root, planPath, out string) (disagree int, err error) {
	p := page{SpecCommit: conformance.SpecCommit, SuiteTag: conformance.SuiteTag, SchemaSHA: schema.TraceClaimV02SHA256}
	for _, sr := range conformance.Run(root, conformance.Sets, record.Rules) {
		sv := setView{Name: sr.Set.Name, Slug: "set-" + strings.ReplaceAll(sr.Set.Name, " ", "-"), About: sr.Set.About, Dir: sr.Set.Dir}
		if sr.Err != nil {
			sv.Err = sr.Err.Error()
		}
		for _, v := range sr.Verdicts {
			r := row{File: strings.TrimPrefix(v.Case.File, sr.Set.Dir+"/"), Name: v.Case.Name,
				Expected: expected(v.Case.Expect), Got: got(v), Source: v.Case.Expect.Source,
				Problems: v.Problems, Notes: v.Notes}
			switch {
			case v.Case.Expect.Informational():
				r.State = "none"
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
		p.Sets = append(p.Sets, sv)
	}
	p.Disagree = p.Judged - p.Agree

	cov := conformance.Mutation(root, conformance.Sets, record.Rules)
	most := 1
	for _, c := range cov {
		most = max(most, len(c.Changed))
	}
	for _, c := range cov {
		rv := ruleView{ID: c.Rule.ID, Suite: c.Rule.Suite, Section: c.Rule.Section, Level: c.Rule.Level,
			Changed: len(c.Changed), Width: 2 + 200*len(c.Changed)/most}
		if len(c.Changed) == 0 {
			rv.Reason = conformance.Uncovered[c.Rule.ID]
		} else {
			p.Distinguished++
		}
		p.RuleRows = append(p.RuleRows, rv)
	}
	p.Rules = len(cov)

	planText, err := os.ReadFile(planPath)
	if err != nil {
		return 0, err
	}
	p.Findings = findings(string(planText))

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, p); err != nil {
		return 0, err
	}
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
		return 0, err
	}
	fmt.Printf("%s: %d of %d judged vectors agree, %d reported without an expectation; %d of %d rules distinguished by a vector\n",
		out, p.Agree, p.Judged, p.None, p.Distinguished, p.Rules)
	return p.Disagree, nil
}

func expected(e conformance.Expect) string {
	switch {
	case e.Informational():
		return "none stated"
	case e.Finding != nil:
		return e.Finding.Rule + " " + string(e.Finding.Status)
	case e.Code != "" && e.CodeInformative:
		return string(e.Outcome) + " (" + e.Code + ", informative)"
	case e.Code != "":
		return string(e.Outcome) + " (" + e.Code + ")"
	}
	return string(e.Outcome)
}

func got(v conformance.Verdict) string {
	if f := v.Case.Expect.Finding; f != nil {
		if g, ok := v.Got.Finding(f.Rule); ok {
			return f.Rule + " " + string(g.Status)
		}
	}
	if v.Got.Outcome == "" {
		return "not run"
	}
	if v.Got.Code != "" {
		return string(v.Got.Outcome) + " (" + v.Got.Code + ")"
	}
	return string(v.Got.Outcome)
}

var (
	itemStart = regexp.MustCompile(`(?m)^\d+\. `)
	bold      = regexp.MustCompile(`\*\*(.+?)\*\*`)
	code      = regexp.MustCompile("`([^`]+)`")
)

// findings renders PLAN.md's numbered findings list, which stays the one home for them.
func findings(plan string) []template.HTML {
	_, rest, ok := strings.Cut(plan, "## Findings so far")
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
<div class="pins">Specification and schema: <code>agentrust-io/trace-spec</code> at <code>{{.SpecCommit}}</code>, schema SHA-256 <code>{{.SchemaSHA}}</code>. Suite vectors: <code>agentrust-io/trace-tests</code> <code>{{.SuiteTag}}</code>.</div>

<div class="tiles">
  <div class="tile"><div class="n">{{.Agree}} of {{.Judged}}</div><div class="l">vectors with an expectation agree</div></div>
  <div class="tile"><div class="n">{{.Disagree}}</div><div class="l">vectors disagree</div></div>
  <div class="tile"><div class="n">{{.None}}</div><div class="l">run and shown without a verdict (the vector states none)</div></div>
  <div class="tile"><div class="n">{{.Distinguished}} of {{.Rules}}</div><div class="l">rules whose deletion some vector notices</div></div>
</div>

<h2>Vector sets</h2>
<div class="wrap"><table>
<tr><th>Set</th><th>What it tests</th><th>Agree</th></tr>
{{range .Sets}}<tr><td><a href="#{{.Slug}}">{{.Name}}</a></td><td>{{.About}}{{if .Err}}<br><span class="st disagree">✗ could not load: {{.Err}}</span>{{end}}</td><td>{{.Agree}} of {{.Judged}}</td></tr>
{{end}}</table></div>

<h2 id="findings">Findings for the TRACE project</h2>
<p class="small">From <code>PLAN.md</code>, where they are kept. Each is something a second implementation surfaced about the specification, the schema or the suite.</p>
<ol class="findings">{{range .Findings}}<li>{{.}}</li>{{end}}</ol>

<h2 id="rules">Which rules the vectors can tell apart</h2>
<p class="small">Each rule is deleted in turn and the vectors are re-run: the bar is the number of vectors whose verdict changes. A rule no vector notices could be missing from an implementation that still passes every vector; the reason column says why, and where this repository tests it instead.</p>
<div class="wrap"><table>
<tr><th>Rule</th><th>Suite code</th><th>Level</th><th>Vectors that notice its deletion</th><th>Source</th></tr>
{{range .RuleRows}}<tr><td class="nowrap"><code>{{.ID}}</code></td><td class="nowrap">{{.Suite}}</td><td>{{.Level}}</td>
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
