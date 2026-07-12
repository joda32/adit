// Package audit turns collected directory data into deterministic, evidence-
// backed security findings (a read-only audit layer over the ADWS collectors).
// Each rule is side-effect free and evaluates a pre-loaded Snapshot; findings
// carry a rule id, severity, affected objects, evidence and remediation, and
// serialise to JSON. This is Phase 1: attribute- and ACL-based rules that need
// no new transport (no SYSVOL/SMB) and no effective-rights graph yet.
package audit

import "sort"

// Severity levels, matching the spec's model.
type Severity string

const (
	Critical Severity = "Critical"
	High     Severity = "High"
	Medium   Severity = "Medium"
	Low      Severity = "Low"
	Info     Severity = "Informational"
)

// Score maps a severity to a representative numeric risk score.
func (s Severity) Score() float64 {
	switch s {
	case Critical:
		return 9.0
	case High:
		return 8.0
	case Medium:
		return 5.0
	case Low:
		return 2.0
	default:
		return 0.0
	}
}

// rank orders severities most-severe first.
func (s Severity) rank() int {
	switch s {
	case Critical:
		return 0
	case High:
		return 1
	case Medium:
		return 2
	case Low:
		return 3
	default:
		return 4
	}
}

// Affected identifies an object a finding applies to.
type Affected struct {
	DistinguishedName string `json:"distinguished_name,omitempty"`
	ObjectSID         string `json:"object_sid,omitempty"`
	SAMAccountName    string `json:"sam_account_name,omitempty"`
}

// Finding is a single audit result.
type Finding struct {
	RuleID      string            `json:"rule_id"`
	Title       string            `json:"title"`
	Category    string            `json:"category"`
	Severity    Severity          `json:"severity"`
	RiskScore   float64           `json:"risk_score"`
	Confidence  string            `json:"confidence"`
	Description string            `json:"description"`
	Risk        string            `json:"risk"`
	Affected    []Affected        `json:"affected_objects,omitempty"`
	Evidence    map[string]string `json:"evidence,omitempty"`
	Remediation string            `json:"remediation"`
	DataSource  []string          `json:"data_source"`
	SafeCheck   bool              `json:"safe_check"`
}

// sortFindings orders findings by severity (most severe first), then rule id.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if a, b := fs[i].Severity.rank(), fs[j].Severity.rank(); a != b {
			return a < b
		}
		return fs[i].RuleID < fs[j].RuleID
	})
}

// Counts summarises findings by severity.
type Counts struct {
	Critical, High, Medium, Low, Info, Total int
}

func count(fs []Finding) Counts {
	var c Counts
	for _, f := range fs {
		c.Total++
		switch f.Severity {
		case Critical:
			c.Critical++
		case High:
			c.High++
		case Medium:
			c.Medium++
		case Low:
			c.Low++
		default:
			c.Info++
		}
	}
	return c
}
