package report_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xuri/excelize/v2"

	"adit/internal/collect"
	"adit/internal/report"
)

func TestWriteXLSX(t *testing.T) {
	tables := []*collect.Table{
		{Name: "Forest", Headers: []string{"Category", "Value"}, Rows: [][]string{{"Name", "corp.local"}}},
		{Name: "Users", Headers: []string{"UserName", "Enabled"}, Rows: [][]string{
			{"alice", "True"}, {"bob", "False"},
		}},
		{Name: "Groups", Headers: []string{"Name", "SID"}}, // empty
	}

	path := filepath.Join(t.TempDir(), "report.xlsx")
	if err := report.WriteXLSX(tables, path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("workbook not written: %v", err)
	}

	f, err := excelize.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	names := f.GetSheetList()
	// TOC first, then Users before Groups (ADRecon order), Forest last.
	want := []string{"Table of Contents", "Users", "Groups", "Forest"}
	if len(names) != len(want) {
		t.Fatalf("sheets = %v, want %v", names, want)
	}
	for i, w := range want {
		if names[i] != w {
			t.Errorf("sheet[%d] = %q, want %q", i, names[i], w)
		}
	}

	// Users sheet content.
	if v, _ := f.GetCellValue("Users", "A1"); v != "UserName" {
		t.Errorf("Users A1 = %q", v)
	}
	if v, _ := f.GetCellValue("Users", "A2"); v != "alice" {
		t.Errorf("Users A2 = %q", v)
	}
	if v, _ := f.GetCellValue("Users", "B3"); v != "False" {
		t.Errorf("Users B3 = %q", v)
	}

	// TOC lists each sheet with its record count.
	if v, _ := f.GetCellValue("Table of Contents", "A1"); v != "Sheet Name" {
		t.Errorf("TOC A1 = %q", v)
	}
	// Users is the first data sheet -> TOC row 2.
	if v, _ := f.GetCellValue("Table of Contents", "A2"); v != "Users" {
		t.Errorf("TOC A2 = %q", v)
	}
	if v, _ := f.GetCellValue("Table of Contents", "B2"); v != "2" {
		t.Errorf("TOC B2 (Users count) = %q, want 2", v)
	}
}

func TestWriteXLSXFromCSV(t *testing.T) {
	dir := t.TempDir()
	writeCSV(t, filepath.Join(dir, "Users.csv"), "UserName,Enabled\nalice,True\nbob,False\n")
	writeCSV(t, filepath.Join(dir, "Domain.csv"), "Category,Value\nName,corp.local\n")

	out := filepath.Join(dir, "report.xlsx")
	if err := report.WriteXLSXFromCSV(dir, out); err != nil {
		t.Fatal(err)
	}
	f, err := excelize.OpenFile(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	rows, _ := f.GetRows("Users")
	if len(rows) != 3 || rows[0][0] != "UserName" || rows[2][0] != "bob" {
		t.Errorf("Users rows = %v", rows)
	}
}

func writeCSV(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
