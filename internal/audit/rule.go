package audit

// check is a single audit rule: static metadata plus an evaluation function.
// Fn returns findings with only the dynamic parts set (Affected, Evidence, and
// optionally a raised Severity); Run fills in the rest from the metadata.
type check struct {
	ID          string
	Title       string
	Category    string
	Severity    Severity
	Description string
	Risk        string
	Remediation string
	Fn          func(s *Snapshot) []Finding
}

// registry holds every rule. Rules register themselves via addChecks in init.
var registry []check

func addChecks(cs ...check) { registry = append(registry, cs...) }

// Result is the outcome of an audit run.
type Result struct {
	Findings []Finding `json:"findings"`
	Counts   Counts    `json:"counts"`
	Rules    int       `json:"rules_evaluated"`
}

// Run evaluates every registered rule against the snapshot and returns the
// findings sorted by severity.
func Run(s *Snapshot) Result {
	var findings []Finding
	for _, c := range registry {
		for _, f := range c.Fn(s) {
			// A rule may set RuleID/Title/Severity per finding (e.g. the ACL
			// family, which reports distinct rights); otherwise inherit the
			// rule metadata.
			f.RuleID = orStr(f.RuleID, c.ID)
			f.Title = orStr(f.Title, c.Title)
			f.Category = orStr(f.Category, c.Category)
			f.Description = orStr(f.Description, c.Description)
			f.Risk = orStr(f.Risk, c.Risk)
			f.Remediation = orStr(f.Remediation, c.Remediation)
			if f.Severity == "" {
				f.Severity = c.Severity
			}
			f.RiskScore = f.Severity.Score()
			if f.Confidence == "" {
				f.Confidence = "High"
			}
			f.DataSource = []string{"ADWS"}
			f.SafeCheck = true
			findings = append(findings, f)
		}
	}
	sortFindings(findings)
	return Result{Findings: findings, Counts: count(findings), Rules: len(registry)}
}

// finding is a small constructor for a rule's dynamic finding.
func finding(a Affected, evidence map[string]string) Finding {
	return Finding{Affected: []Affected{a}, Evidence: evidence}
}

func orStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
