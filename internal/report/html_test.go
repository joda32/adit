package report_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"adit/internal/collect"
	"adit/internal/report"
)

func TestWriteHTML(t *testing.T) {
	tables := []*collect.Table{
		{Name: "Users", Headers: []string{"UserName", "Enabled", "HasSPN"}, Rows: [][]string{
			{"alice", "True", "False"}, {"bob", "False", "True"},
		}},
		{Name: "Kerberoastable", Headers: []string{"SAM Account Name", "Risk Level"}, Rows: [][]string{
			{"svc-sql", "CRITICAL"},
		}},
		// Data with HTML-special chars must be escaped, not injected.
		{Name: "Groups", Headers: []string{"Name"}, Rows: [][]string{
			{`<script>alert(1)</script>`},
		}},
		{Name: "Printers", Headers: []string{"Name"}}, // empty -> listed, no section
	}

	path := filepath.Join(t.TempDir(), "dash.html")
	meta := report.Meta{Domain: "example.local", DC: "dc01.example.local", When: time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)}
	if err := report.WriteHTML(tables, meta, path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)

	// Template integrity: no html/template escaping breakage of the script/style.
	if strings.Contains(html, "ZgotmplZ") {
		t.Error("template escaping broke the CSS/JS")
	}
	if !strings.Contains(html, "IntersectionObserver") {
		t.Error("dashboard script missing")
	}
	// Overview stat + finding.
	if !strings.Contains(html, "example.local") {
		t.Error("domain missing")
	}
	if !strings.Contains(html, `badge critical`) {
		t.Error("risk badge not applied to Kerberoastable CRITICAL")
	}
	// Empty table listed, not sectioned.
	if !strings.Contains(html, "Printers") {
		t.Error("empty collector not noted")
	}
	// XSS-safe: the raw script tag from data must be escaped.
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Error("attacker-controlled data was not escaped")
	}
	if !strings.Contains(html, "&lt;script&gt;alert(1)") {
		t.Error("expected escaped group name")
	}
}
