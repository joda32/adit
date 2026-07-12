package audit

import (
	"encoding/json"
	"os"
	"time"
)

// Report is the top-level audit document written to disk.
type Report struct {
	Tool        string    `json:"tool"`
	Version     string    `json:"version"`
	GeneratedAt string    `json:"generated_at"`
	Domain      string    `json:"domain"`
	BaseDN      string    `json:"base_dn"`
	Result      Result    `json:"result"`
	generated   time.Time `json:"-"`
}

// NewReport wraps a Result with document metadata.
func NewReport(version, domain, baseDN string, generated time.Time, r Result) Report {
	return Report{
		Tool:        "adit audit",
		Version:     version,
		GeneratedAt: generated.UTC().Format(time.RFC3339),
		Domain:      domain,
		BaseDN:      baseDN,
		Result:      r,
		generated:   generated,
	}
}

// WriteJSON writes the report as indented JSON to path.
func (r Report) WriteJSON(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
