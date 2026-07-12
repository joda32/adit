package report

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"adit/internal/collect"
)

// WriteXLSXFromCSV reads every .csv in csvDir into a table and writes a workbook
// to outPath — the standalone "generate report from existing CSVs" mode.
func WriteXLSXFromCSV(csvDir, outPath string) error {
	tables, err := readCSVDir(csvDir)
	if err != nil {
		return err
	}
	return WriteXLSX(tables, outPath)
}

// WriteHTMLFromCSV renders the dashboard from an existing CSV directory.
func WriteHTMLFromCSV(csvDir, outPath string, meta Meta) error {
	tables, err := readCSVDir(csvDir)
	if err != nil {
		return err
	}
	return WriteHTML(tables, meta, outPath)
}

func readCSVDir(csvDir string) ([]*collect.Table, error) {
	entries, err := os.ReadDir(csvDir)
	if err != nil {
		return nil, err
	}
	var tables []*collect.Table
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".csv") {
			continue
		}
		t, err := readCSVTable(filepath.Join(csvDir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		tables = append(tables, t)
	}
	if len(tables) == 0 {
		return nil, fmt.Errorf("no CSV files found in %s", csvDir)
	}
	return tables, nil
}

func readCSVTable(path string) (*collect.Table, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // tolerate ragged rows
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}

	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	t := &collect.Table{Name: name}
	if len(records) > 0 {
		t.Headers = records[0]
		t.Rows = records[1:]
	}
	return t, nil
}
