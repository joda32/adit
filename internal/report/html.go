package report

import (
	"os"
	"strconv"
	"strings"
	"time"

	"adit/internal/collect"
)

// Meta describes the collection run for the dashboard header.
type Meta struct {
	Domain string
	DC     string
	When   time.Time // zero means time.Now()
}

// WriteHTML renders a self-contained, single-file dashboard to path.
func WriteHTML(tables []*collect.Table, meta Meta, path string) error {
	if meta.When.IsZero() {
		meta.When = time.Now()
	}
	model := buildModel(tables, meta)

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return dashboardTemplate.Execute(f, model)
}

// --- view model ---

type htmlModel struct {
	Domain    string
	DC        string
	Generated string
	Stats     []stat
	Findings  []finding
	Sections  []htmlSection
	Empty     []string
}

type stat struct{ Label, Value, Sub string }

type finding struct {
	Label  string
	Value  string
	Level  string // css class: critical/high/medium/low/info
	Detail string
}

type htmlSection struct {
	ID      string
	Name    string
	Count   int
	Headers []string
	Rows    [][]htmlCell
}

type htmlCell struct {
	Text  string
	Badge string // css badge class, or ""
}

func buildModel(tables []*collect.Table, meta Meta) htmlModel {
	ordered := orderTables(tables)

	m := htmlModel{
		Domain:    orDash(meta.Domain),
		DC:        orDash(meta.DC),
		Generated: meta.When.Format("2006-01-02 15:04:05 MST"),
		Stats:     overviewStats(tables),
		Findings:  securityFindings(tables),
	}
	for _, t := range ordered {
		if len(t.Rows) == 0 {
			m.Empty = append(m.Empty, t.Name)
			continue
		}
		m.Sections = append(m.Sections, section(t))
	}
	return m
}

func section(t *collect.Table) htmlSection {
	s := htmlSection{ID: slug(t.Name), Name: t.Name, Count: len(t.Rows), Headers: t.Headers}
	for _, r := range t.Rows {
		cells := make([]htmlCell, len(r))
		for i, c := range r {
			header := ""
			if i < len(t.Headers) {
				header = t.Headers[i]
			}
			cells[i] = htmlCell{Text: c, Badge: badgeClass(header, c)}
		}
		s.Rows = append(s.Rows, cells)
	}
	return s
}

// --- overview stats ---

func overviewStats(tables []*collect.Table) []stat {
	var out []stat
	if u := tableByName(tables, "Users"); u != nil {
		enabled := countCol(u, "Enabled", eq("True"))
		out = append(out,
			stat{"Users", itoa(len(u.Rows)), plural(enabled, "enabled")},
			stat{"Disabled Users", itoa(len(u.Rows) - enabled), ""},
			stat{"Password Never Expires", itoa(countCol(u, "Password Never Expires", eq("True"))), ""},
			stat{"Never Logged In", itoa(countCol(u, "Never Logged in", eq("True"))), ""},
		)
	}
	if c := tableByName(tables, "Computers"); c != nil {
		out = append(out, stat{"Computers", itoa(len(c.Rows)), plural(countCol(c, "Enabled", eq("True")), "enabled")})
	}
	if g := tableByName(tables, "Groups"); g != nil {
		out = append(out, stat{"Groups", itoa(len(g.Rows)), ""})
	}
	if d := tableByName(tables, "DomainControllers"); d != nil {
		out = append(out, stat{"Domain Controllers", itoa(len(d.Rows)), ""})
	}
	if t := tableByName(tables, "Trusts"); t != nil {
		out = append(out, stat{"Trusts", itoa(len(t.Rows)), ""})
	}
	return out
}

// --- security findings ---

func securityFindings(tables []*collect.Table) []finding {
	var out []finding

	if k := tableByName(tables, "Kerberoastable"); k != nil && len(k.Rows) > 0 {
		crit := countCol(k, "Risk Level", in("CRITICAL", "HIGH"))
		out = append(out, finding{"Kerberoastable Accounts", itoa(len(k.Rows)),
			levelIf(len(k.Rows) > 0, "high"), plural(crit, "high/critical risk")})
	}
	if a := tableByName(tables, "ASREPRoastable"); a != nil {
		out = append(out, finding{"AS-REP Roastable", itoa(len(a.Rows)),
			levelIf(len(a.Rows) > 0, "critical"), "no Kerberos pre-auth required"})
	}
	if kt := tableByName(tables, "krbtgt"); kt != nil && len(kt.Rows) > 0 {
		risk := cellValue(kt, 0, "Risk Level")
		age := cellValue(kt, 0, "Password Age (days)")
		out = append(out, finding{"krbtgt Password", age + " days",
			riskClass(risk), "Golden Ticket exposure window"})
	}
	if ct := tableByName(tables, "CertificateTemplates"); ct != nil {
		vuln := countCol(ct, "Risk Level", in("CRITICAL", "HIGH", "MEDIUM"))
		out = append(out, finding{"Vulnerable Cert Templates", itoa(vuln),
			levelIf(vuln > 0, "critical"), "ADCS ESC1–ESC4/ESC9"})
	}
	if pg := tableByName(tables, "ProtectedGroups"); pg != nil {
		unhardened := countCol(pg, "Risk Level", eq("HIGH"))
		out = append(out, finding{"Tier-0 Not in Protected Users", itoa(unhardened),
			levelIf(unhardened > 0, "high"), "privileged users lacking hardening"})
	}
	if u := tableByName(tables, "Users"); u != nil {
		spn := countCol(u, "HasSPN", eq("True"))
		if spn > 0 {
			out = append(out, finding{"Users With SPN", itoa(spn), "medium", "candidate service accounts"})
		}
	}
	if l := tableByName(tables, "LAPS"); l != nil && len(l.Rows) > 0 {
		readable := countCol(l, "Readable", eq("True"))
		out = append(out, finding{"LAPS Passwords Readable", itoa(readable),
			levelIf(readable > 0, "high"), plural(len(l.Rows), "computers with LAPS")})
	}
	return out
}

// --- badge / risk classification ---

func badgeClass(header, value string) string {
	switch header {
	case "Risk Level":
		return riskClass(value)
	case "ESC Vulnerabilities":
		if value != "" && value != "None" {
			return "high"
		}
	case "badSuccessor Vulnerable":
		if strings.EqualFold(value, "true") {
			return "critical"
		}
	}
	return ""
}

func riskClass(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	case "INFO":
		return "info"
	default:
		return ""
	}
}

// --- small helpers ---

func tableByName(tables []*collect.Table, name string) *collect.Table {
	for _, t := range tables {
		if t.Name == name {
			return t
		}
	}
	return nil
}

func colIndex(t *collect.Table, header string) int {
	for i, h := range t.Headers {
		if h == header {
			return i
		}
	}
	return -1
}

func countCol(t *collect.Table, header string, pred func(string) bool) int {
	i := colIndex(t, header)
	if i < 0 {
		return 0
	}
	n := 0
	for _, r := range t.Rows {
		if i < len(r) && pred(r[i]) {
			n++
		}
	}
	return n
}

func cellValue(t *collect.Table, row int, header string) string {
	i := colIndex(t, header)
	if i < 0 || row >= len(t.Rows) || i >= len(t.Rows[row]) {
		return ""
	}
	return t.Rows[row][i]
}

func eq(want string) func(string) bool { return func(s string) bool { return s == want } }

// in matches case-insensitively: it is used for the "Risk Level" column, whose
// values arrive in mixed case (e.g. the collector emits title-case "Medium" for
// some ADCS templates), so an exact-case set would silently undercount.
func in(vals ...string) func(string) bool {
	set := map[string]bool{}
	for _, v := range vals {
		set[strings.ToUpper(v)] = true
	}
	return func(s string) bool { return set[strings.ToUpper(s)] }
}

func levelIf(cond bool, level string) string {
	if cond {
		return level
	}
	return "low"
}

func itoa(n int) string { return strconv.Itoa(n) }

func plural(n int, label string) string {
	if n == 0 {
		return ""
	}
	return itoa(n) + " " + label
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// slug turns a table name into an HTML id.
func slug(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return "s-" + strings.Trim(b.String(), "-")
}
