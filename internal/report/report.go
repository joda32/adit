// Package report renders collected tables into a styled multi-sheet XLSX
// workbook — one sheet per collector plus a Table of Contents — mirroring the
// ADRecon/PyADRecon Excel output.
package report

import (
	"fmt"
	"strings"

	"github.com/xuri/excelize/v2"

	"adit/internal/collect"
)

// sheetOrder is the ADRecon sheet order; tables are emitted in this order, then
// any others alphabetically. Names match collect.Table.Name.
var sheetOrder = []string{
	"Audit Findings",
	"Users", "UserSPNs", "krbtgt", "ProtectedGroups", "ASREPRoastable", "Kerberoastable",
	"gMSA", "dMSA", "GroupMembers", "Groups", "OUs", "Computers", "ComputerSPNs", "LAPS",
	"Bitlocker", "Printers", "DNSZones", "DNSRecords", "gPLinks", "GPOs",
	"DomainControllers", "CertificateTemplates", "CertificateAuthorities",
	"PasswordPolicy", "FineGrainedPasswordPolicy", "SchemaHistory", "Sites",
	"Subnets", "Trusts", "Domain", "Forest",
}

const tocSheet = "Table of Contents"

// WriteXLSX writes the tables to a styled workbook at path.
func WriteXLSX(tables []*collect.Table, path string) error {
	f := excelize.NewFile()
	defer f.Close()

	// Reuse the default sheet as the Table of Contents.
	if err := f.SetSheetName("Sheet1", tocSheet); err != nil {
		return err
	}

	headerStyle, err := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"0066CC"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "left", Vertical: "top"},
	})
	if err != nil {
		return err
	}

	used := map[string]bool{strings.ToLower(tocSheet): true}
	var tocRows [][2]string
	for _, t := range orderTables(tables) {
		name := uniqueSheetName(t.Name, used)
		if err := writeSheet(f, name, t, headerStyle); err != nil {
			return err
		}
		tocRows = append(tocRows, [2]string{name, fmt.Sprintf("%d", len(t.Rows))})
	}

	if err := writeTOC(f, headerStyle, tocRows); err != nil {
		return err
	}

	// Put the Table of Contents first and active.
	if idx, err := f.GetSheetIndex(tocSheet); err == nil {
		f.SetActiveSheet(idx)
	}
	return f.SaveAs(path)
}

// writeSheet writes one table's header + rows with styling, a frozen header row,
// an autofilter and sensible column widths.
func writeSheet(f *excelize.File, name string, t *collect.Table, headerStyle int) error {
	if _, err := f.NewSheet(name); err != nil {
		return err
	}
	if len(t.Headers) == 0 {
		return nil
	}

	// Header row.
	headerRow := toAnySlice(t.Headers)
	if err := f.SetSheetRow(name, "A1", &headerRow); err != nil {
		return err
	}
	lastCol, err := excelize.ColumnNumberToName(len(t.Headers))
	if err != nil {
		return err
	}
	if err := f.SetCellStyle(name, "A1", lastCol+"1", headerStyle); err != nil {
		return err
	}

	// Data rows.
	widths := make([]int, len(t.Headers))
	for i, h := range t.Headers {
		widths[i] = len(h)
	}
	for r, row := range t.Rows {
		cells := toAnySlice(row)
		cell := fmt.Sprintf("A%d", r+2)
		if err := f.SetSheetRow(name, cell, &cells); err != nil {
			return err
		}
		for i, v := range row {
			if i < len(widths) && len(v) > widths[i] {
				widths[i] = len(v)
			}
		}
	}

	// Column widths (clamped), freeze header, autofilter.
	for i := range t.Headers {
		col, _ := excelize.ColumnNumberToName(i + 1)
		_ = f.SetColWidth(name, col, col, clampWidth(widths[i]))
	}
	_ = f.SetPanes(name, &excelize.Panes{
		Freeze: true, YSplit: 1, TopLeftCell: "A2", ActivePane: "bottomLeft",
	})
	_ = f.AutoFilter(name, fmt.Sprintf("A1:%s1", lastCol), nil)
	return nil
}

// writeTOC writes the Table of Contents with hyperlinks to each sheet.
func writeTOC(f *excelize.File, headerStyle int, sheets [][2]string) error {
	header := []any{"Sheet Name", "Record Count"}
	if err := f.SetSheetRow(tocSheet, "A1", &header); err != nil {
		return err
	}
	if err := f.SetCellStyle(tocSheet, "A1", "B1", headerStyle); err != nil {
		return err
	}
	linkStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Color: "0563C1", Underline: "single"},
	})
	for i, s := range sheets {
		rowNum := i + 2
		nameCell := fmt.Sprintf("A%d", rowNum)
		_ = f.SetCellValue(tocSheet, nameCell, s[0])
		_ = f.SetCellValue(tocSheet, fmt.Sprintf("B%d", rowNum), s[1])
		_ = f.SetCellHyperLink(tocSheet, nameCell, fmt.Sprintf("'%s'!A1", s[0]), "Location")
		_ = f.SetCellStyle(tocSheet, nameCell, nameCell, linkStyle)
	}
	_ = f.SetColWidth(tocSheet, "A", "A", 32)
	_ = f.SetColWidth(tocSheet, "B", "B", 14)
	return nil
}

// orderTables returns the tables sorted by sheetOrder, then remaining ones in
// their given order.
func orderTables(tables []*collect.Table) []*collect.Table {
	byName := make(map[string]*collect.Table, len(tables))
	for _, t := range tables {
		byName[t.Name] = t
	}
	var out []*collect.Table
	seen := map[string]bool{}
	for _, name := range sheetOrder {
		if t, ok := byName[name]; ok {
			out = append(out, t)
			seen[name] = true
		}
	}
	for _, t := range tables {
		if !seen[t.Name] {
			out = append(out, t)
		}
	}
	return out
}

// uniqueSheetName sanitizes a name to Excel's rules (<=31 chars, no []:*?/\) and
// ensures uniqueness (case-insensitive).
func uniqueSheetName(name string, used map[string]bool) string {
	name = strings.Map(func(r rune) rune {
		if strings.ContainsRune(`[]:*?/\`, r) {
			return '_'
		}
		return r
	}, name)
	if len(name) > 31 {
		name = name[:31]
	}
	if name == "" {
		name = "Sheet"
	}
	base := name
	for i := 2; used[strings.ToLower(name)]; i++ {
		suffix := fmt.Sprintf("_%d", i)
		if len(base)+len(suffix) > 31 {
			base = base[:31-len(suffix)]
		}
		name = base + suffix
	}
	used[strings.ToLower(name)] = true
	return name
}

func toAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func clampWidth(n int) float64 {
	const min, max = 10, 60
	if n < min {
		n = min
	}
	if n > max {
		n = max
	}
	return float64(n) + 1
}
