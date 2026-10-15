package reporter

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Severity ratings (CVSS v3.x qualitative scale)
// ---------------------------------------------------------------------------

type rating struct {
	Label string
	Bg    string // badge background and card accent
	Fg    string // badge text
	Tint  string // light background for summary chips
}

var (
	ratingCritical = rating{"Critical", "#7A1020", "#FFFFFF", "#F9E7EA"}
	ratingHigh     = rating{"High", "#D3263A", "#FFFFFF", "#FCEBED"}
	ratingMedium   = rating{"Medium", "#F0A202", "#3A2600", "#FDF4DF"}
	ratingLow      = rating{"Low", "#2F8F5B", "#FFFFFF", "#E7F4EC"}
	ratingNone     = rating{"None", "#6B7280", "#FFFFFF", "#EFF0F2"}

	ratingOrder = []rating{ratingCritical, ratingHigh, ratingMedium, ratingLow, ratingNone}
)

func rate(severity float64) rating {
	switch {
	case severity >= 9.0:
		return ratingCritical
	case severity >= 7.0:
		return ratingHigh
	case severity >= 4.0:
		return ratingMedium
	case severity > 0:
		return ratingLow
	default:
		return ratingNone
	}
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// bySeverity returns a copy of findings ordered highest severity first,
// keeping the original order for equal severities.
func bySeverity(findings []*Finding) []*Finding {
	sorted := make([]*Finding, 0, len(findings))
	for _, f := range findings {
		if f != nil {
			sorted = append(sorted, f)
		}
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Severity > sorted[j].Severity
	})
	return sorted
}

// sectionNames returns a Finding's section names in a stable, sorted order.
func sectionNames(f *Finding) []string {
	names := make([]string, 0, len(f.Sections))
	for name := range f.Sections {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// writeOutput writes data to path, creating parent directories as needed.
func writeOutput(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating directory for %s: %w", path, err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------

var mdHeadingRe = regexp.MustCompile(`^(#{1,5})(\s)`)

// demoteHeadings pushes headings inside section content one level down, so a
// merged batch block's "## Sub Name" nests under its "## Section" heading.
func demoteHeadings(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = mdHeadingRe.ReplaceAllString(line, "#$1$2")
	}
	return strings.Join(lines, "\n")
}

// WriteMarkdown writes findings as Markdown: each finding name is an h1 with
// its CVSS score quoted underneath, followed by each section as an h2.
func WriteMarkdown(findings []*Finding, path string) error {
	var b strings.Builder

	for _, f := range bySeverity(findings) {
		fmt.Fprintf(&b, "# %s\n\n", f.Name)
		fmt.Fprintf(&b, "> CVSS: %.1f\n\n", f.Severity)

		for _, name := range sectionNames(f) {
			fmt.Fprintf(&b, "## %s\n\n", name)
			fmt.Fprintf(&b, "%s\n\n", strings.TrimSpace(demoteHeadings(f.Sections[name])))
		}
	}

	return writeOutput(path, []byte(b.String()))
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

const (
	fontStack = `'Inter', 'Segoe UI', -apple-system, BlinkMacSystemFont, 'Helvetica Neue', Arial, sans-serif`
	monoStack = `'JetBrains Mono', 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace`

	styleBody      = "margin:0;padding:48px 20px;background:#F3F4F7;font-family:" + fontStack + ";color:#1F2430;-webkit-font-smoothing:antialiased;"
	styleWrap      = "max-width:960px;margin:0 auto;"
	styleHeader    = "background:linear-gradient(135deg,#141A2E 0%,#232B47 100%);color:#FFFFFF;border-radius:16px;padding:36px 40px;margin-bottom:28px;box-shadow:0 10px 30px rgba(20,26,46,0.18);"
	styleEyebrow   = "font-size:12px;font-weight:600;letter-spacing:0.14em;text-transform:uppercase;color:#9AA6C7;margin:0 0 10px 0;"
	styleTitle     = "font-size:30px;font-weight:700;letter-spacing:-0.02em;margin:0 0 6px 0;"
	styleMeta      = "font-size:14px;color:#B9C2DC;margin:0 0 24px 0;"
	styleChips     = "display:flex;flex-wrap:wrap;gap:10px;"
	styleCard      = "background:#FFFFFF;border-radius:14px;padding:30px 34px;margin-bottom:22px;box-shadow:0 1px 2px rgba(16,24,40,0.06),0 6px 18px rgba(16,24,40,0.06);"
	styleTitleRow  = "display:flex;align-items:center;justify-content:space-between;gap:24px;padding-bottom:18px;margin-bottom:6px;border-bottom:1px solid #ECEEF3;"
	styleH1        = "font-size:22px;font-weight:700;letter-spacing:-0.01em;line-height:1.3;margin:0;color:#141A2E;"
	styleH2        = "font-size:12px;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;color:#6A7390;margin:26px 0 10px 0;"
	styleH3        = "font-size:16px;font-weight:650;color:#232B47;margin:22px 0 8px 0;"
	styleH4        = "font-size:14px;font-weight:650;color:#232B47;margin:18px 0 6px 0;"
	styleP         = "font-size:15px;line-height:1.7;margin:0 0 12px 0;color:#2B3142;"
	styleUL        = "font-size:15px;line-height:1.7;margin:0 0 12px 0;padding-left:22px;color:#2B3142;"
	styleCode      = "font-family:" + monoStack + ";font-size:13px;background:#F1F3F8;border:1px solid #E3E7EF;border-radius:5px;padding:1px 6px;color:#232B47;"
	styleTableWrap = "overflow-x:auto;margin:6px 0 16px 0;border:1px solid #E3E7EF;border-radius:10px;"
	styleTable     = "border-collapse:collapse;width:100%;font-size:13px;"
	styleTH        = "text-align:left;font-weight:650;background:#F6F7FA;color:#3A4258;padding:10px 14px;border-bottom:1px solid #E3E7EF;white-space:nowrap;"
	styleTD        = "padding:9px 14px;border-bottom:1px solid #EEF0F4;color:#2B3142;vertical-align:top;font-family:" + monoStack + ";"
	styleFooter    = "text-align:center;font-size:12px;color:#8A92A8;margin-top:30px;"
	styleEmpty     = "font-size:15px;color:#6A7390;text-align:center;padding:40px 0;margin:0;"
)

func badgeHTML(f *Finding) string {
	r := rate(f.Severity)
	return fmt.Sprintf(
		`<span style="flex:none;display:inline-flex;align-items:center;gap:8px;background:%s;color:%s;border-radius:999px;padding:6px 14px;font-size:12px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;white-space:nowrap;">%s<span style="opacity:0.55;">&middot;</span><span style="letter-spacing:0.02em;">CVSS %.1f</span></span>`,
		r.Bg, r.Fg, r.Label, f.Severity,
	)
}

func chipHTML(r rating, count int) string {
	return fmt.Sprintf(
		`<span style="display:inline-flex;align-items:center;gap:8px;background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.14);border-radius:999px;padding:6px 14px 6px 8px;font-size:13px;color:#FFFFFF;"><span style="display:inline-block;min-width:22px;text-align:center;background:%s;color:%s;border-radius:999px;padding:2px 7px;font-weight:700;font-size:12px;">%d</span>%s</span>`,
		r.Bg, r.Fg, count, r.Label,
	)
}

// WriteHTML writes findings as a self-contained HTML report with inline
// styles. Each finding's severity is shown as a colour-coded CVSS badge to the
// right of its title.
func WriteHTML(findings []*Finding, path string) error {
	sorted := bySeverity(findings)

	counts := map[string]int{}
	for _, f := range sorted {
		counts[rate(f.Severity).Label]++
	}

	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
	b.WriteString("<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString("<title>Security Findings Report</title>\n")
	b.WriteString("</head>\n")
	fmt.Fprintf(&b, "<body style=\"%s\">\n<div style=\"%s\">\n", styleBody, styleWrap)

	// Header with summary.
	fmt.Fprintf(&b, "<header style=\"%s\">\n", styleHeader)
	fmt.Fprintf(&b, "<p style=\"%s\">RuleHound Configuration Audit</p>\n", styleEyebrow)
	fmt.Fprintf(&b, "<h1 style=\"%s\">Security Findings Report</h1>\n", styleTitle)
	fmt.Fprintf(&b, "<p style=\"%s\">%d finding(s) &middot; Generated %s</p>\n",
		styleMeta, len(sorted), html.EscapeString(time.Now().Format("2 January 2006, 15:04")))
	fmt.Fprintf(&b, "<div style=\"%s\">\n", styleChips)
	for _, r := range ratingOrder {
		if counts[r.Label] > 0 {
			b.WriteString(chipHTML(r, counts[r.Label]))
			b.WriteString("\n")
		}
	}
	b.WriteString("</div>\n</header>\n")

	if len(sorted) == 0 {
		fmt.Fprintf(&b, "<section style=\"%s\"><p style=\"%s\">No findings.</p></section>\n", styleCard, styleEmpty)
	}

	// One card per finding.
	for _, f := range sorted {
		r := rate(f.Severity)
		fmt.Fprintf(&b, "<section style=\"%sborder-top:5px solid %s;\">\n", styleCard, r.Bg)
		fmt.Fprintf(&b, "<div style=\"%s\">\n", styleTitleRow)
		fmt.Fprintf(&b, "<h1 style=\"%s\">%s</h1>\n", styleH1, html.EscapeString(f.Name))
		b.WriteString(badgeHTML(f))
		b.WriteString("\n")
		b.WriteString("</div>\n")

		for _, name := range sectionNames(f) {
			fmt.Fprintf(&b, "<h2 style=\"%s\">%s</h2>\n", styleH2, html.EscapeString(name))
			b.WriteString(renderContentHTML(f.Sections[name]))
		}
		b.WriteString("</section>\n")
	}

	fmt.Fprintf(&b, "<p style=\"%s\">Generated by RuleHound</p>\n", styleFooter)
	b.WriteString("</div>\n</body>\n</html>\n")

	return writeOutput(path, []byte(b.String()))
}

var (
	htmlHeadingRe  = regexp.MustCompile(`^(#{1,6})\s+(.*)$`)
	htmlListRe     = regexp.MustCompile(`^[-*]\s+(.*)$`)
	htmlTableSepRe = regexp.MustCompile(`^:?-{3,}:?$`)
	inlineCodeRe   = regexp.MustCompile("`([^`]+)`")
	inlineBoldRe   = regexp.MustCompile(`\*\*([^*]+)\*\*`)
)

// renderContentHTML renders the small Markdown subset that section content
// uses: headings, pipe tables, bullet lists and paragraphs, plus `code` and
// **bold** inline. Everything is HTML-escaped first.
func renderContentHTML(text string) string {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var b strings.Builder

	isBlockStart := func(s string) bool {
		return htmlHeadingRe.MatchString(s) || strings.HasPrefix(s, "|") || htmlListRe.MatchString(s)
	}

	for i := 0; i < len(lines); {
		line := strings.TrimSpace(lines[i])

		switch {
		case line == "":
			i++

		case htmlHeadingRe.MatchString(line):
			m := htmlHeadingRe.FindStringSubmatch(line)
			if len(m[1]) <= 2 {
				fmt.Fprintf(&b, "<h3 style=\"%s\">%s</h3>\n", styleH3, inlineHTML(m[2]))
			} else {
				fmt.Fprintf(&b, "<h4 style=\"%s\">%s</h4>\n", styleH4, inlineHTML(m[2]))
			}
			i++

		case strings.HasPrefix(line, "|"):
			var rows []string
			for i < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i]), "|") {
				rows = append(rows, strings.TrimSpace(lines[i]))
				i++
			}
			b.WriteString(tableHTML(rows))

		case htmlListRe.MatchString(line):
			fmt.Fprintf(&b, "<ul style=\"%s\">\n", styleUL)
			for i < len(lines) && htmlListRe.MatchString(strings.TrimSpace(lines[i])) {
				m := htmlListRe.FindStringSubmatch(strings.TrimSpace(lines[i]))
				fmt.Fprintf(&b, "<li>%s</li>\n", inlineHTML(m[1]))
				i++
			}
			b.WriteString("</ul>\n")

		default:
			var para []string
			for i < len(lines) {
				l := strings.TrimSpace(lines[i])
				if l == "" || (len(para) > 0 && isBlockStart(l)) {
					break
				}
				para = append(para, inlineHTML(l))
				i++
			}
			fmt.Fprintf(&b, "<p style=\"%s\">%s</p>\n", styleP, strings.Join(para, "<br>"))
		}
	}

	return b.String()
}

func inlineHTML(s string) string {
	s = html.EscapeString(s)
	s = inlineCodeRe.ReplaceAllString(s, `<code style="`+styleCode+`">$1</code>`)
	s = inlineBoldRe.ReplaceAllString(s, `<strong>$1</strong>`)
	return s
}

func splitTableRow(row string) []string {
	row = strings.ReplaceAll(row, `\|`, "\x00")
	row = strings.TrimSpace(row)
	row = strings.TrimPrefix(row, "|")
	row = strings.TrimSuffix(row, "|")
	cells := strings.Split(row, "|")
	for i, c := range cells {
		cells[i] = strings.TrimSpace(strings.ReplaceAll(c, "\x00", "|"))
	}
	return cells
}

func isSeparatorRow(cells []string) bool {
	for _, c := range cells {
		if !htmlTableSepRe.MatchString(c) {
			return false
		}
	}
	return len(cells) > 0
}

// tableHTML renders Markdown pipe-table rows. A separator row after the first
// row marks it as the header.
func tableHTML(rows []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<div style=\"%s\"><table style=\"%s\">\n", styleTableWrap, styleTable)

	body := rows
	if len(rows) >= 2 && isSeparatorRow(splitTableRow(rows[1])) {
		b.WriteString("<thead><tr>")
		for _, c := range splitTableRow(rows[0]) {
			fmt.Fprintf(&b, "<th style=\"%s\">%s</th>", styleTH, inlineHTML(c))
		}
		b.WriteString("</tr></thead>\n")
		body = rows[2:]
	}

	b.WriteString("<tbody>\n")
	for _, row := range body {
		cells := splitTableRow(row)
		if isSeparatorRow(cells) {
			continue
		}
		b.WriteString("<tr>")
		for _, c := range cells {
			fmt.Fprintf(&b, "<td style=\"%s\">%s</td>", styleTD, inlineHTML(c))
		}
		b.WriteString("</tr>\n")
	}
	b.WriteString("</tbody>\n</table></div>\n")

	return b.String()
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

// WriteCSV writes one row per finding: Name, Severity, Rating, one column per
// section name used by any finding (sorted), then Flags (one per line).
func WriteCSV(findings []*Finding, path string) error {
	seen := map[string]bool{}
	var sections []string
	for _, f := range findings {
		if f == nil {
			continue
		}
		for name := range f.Sections {
			if !seen[name] {
				seen[name] = true
				sections = append(sections, name)
			}
		}
	}
	sort.Strings(sections)

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	header := append([]string{"Name", "Severity", "Rating"}, sections...)
	header = append(header, "Flags")
	if err := w.Write(header); err != nil {
		return err
	}

	for _, f := range findings {
		if f == nil {
			continue
		}
		row := []string{f.Name, fmt.Sprintf("%.1f", f.Severity), rate(f.Severity).Label}
		for _, name := range sections {
			row = append(row, f.Sections[name])
		}
		row = append(row, strings.Join(f.Flags, "\n"))
		if err := w.Write(row); err != nil {
			return err
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	return writeOutput(path, buf.Bytes())
}

// ---------------------------------------------------------------------------
// JSON / YAML (mirror the Finding struct)
// ---------------------------------------------------------------------------

type findingDoc struct {
	Name     string            `json:"Name" yaml:"Name"`
	Severity float64           `json:"Severity" yaml:"Severity"`
	Sections map[string]string `json:"Sections" yaml:"Sections"`
	Flags    []string          `json:"Flags" yaml:"Flags"`
}

func toDocs(findings []*Finding) []findingDoc {
	docs := make([]findingDoc, 0, len(findings))
	for _, f := range findings {
		if f == nil {
			continue
		}
		d := findingDoc{Name: f.Name, Severity: f.Severity, Sections: f.Sections, Flags: f.Flags}
		if d.Sections == nil {
			d.Sections = map[string]string{}
		}
		if d.Flags == nil {
			d.Flags = []string{}
		}
		docs = append(docs, d)
	}
	return docs
}

// WriteJSON writes findings as a JSON array mirroring the Finding struct.
func WriteJSON(findings []*Finding, path string) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep <, > and & readable in evidence text
	enc.SetIndent("", "  ")
	if err := enc.Encode(toDocs(findings)); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return writeOutput(path, buf.Bytes())
}

// WriteYAML writes findings as a YAML list mirroring the Finding struct.
func WriteYAML(findings []*Finding, path string) error {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(toDocs(findings)); err != nil {
		return fmt.Errorf("encoding YAML: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("encoding YAML: %w", err)
	}
	return writeOutput(path, buf.Bytes())
}
