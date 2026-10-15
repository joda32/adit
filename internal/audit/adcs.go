package audit

import (
	"strings"

	"adit/internal/collect"
)

// ADCS certificate-template rules. The ESC1–4/9 assessment is shared with the
// recon collector via collect.AssessTemplate, so the audit findings and the
// CertificateTemplates CSV can never disagree.

type escMeta struct {
	id, title, description, risk, remediation string
}

var escRuleMeta = map[string]escMeta{
	"ESC1": {
		"AD-CS-001", "ESC1 — certificate template allows enrollee-supplied subject",
		"A template issues client-authentication certificates, lets the enrollee supply the subject/SAN, and can be enrolled by non-privileged principals.",
		"An attacker can request a certificate in the name of any principal (including a Domain Admin) and authenticate as them.",
		"Remove ENROLLEE_SUPPLIES_SUBJECT, require manager approval, or restrict enrollment to trusted principals.",
	},
	"ESC2": {
		"AD-CS-002", "ESC2 — certificate template has Any-Purpose or no EKU",
		"A template grants the Any-Purpose EKU (or no EKU), so issued certificates can be used for any purpose, and non-privileged principals can enroll.",
		"Certificates from this template can be used for client authentication and beyond, enabling impersonation.",
		"Restrict the EKUs to the minimum required and limit enrollment to trusted principals.",
	},
	"ESC3": {
		"AD-CS-003", "ESC3 — Certificate Request Agent template",
		"A template grants the Certificate Request Agent (Enrollment Agent) EKU without adequate approval or signature requirements.",
		"An enrollment agent certificate lets the holder request certificates on behalf of other users, enabling impersonation.",
		"Require manager approval and/or authorized signatures, and restrict enrollment to trusted principals.",
	},
	"ESC4": {
		"AD-CS-004", "ESC4 — weak access control on certificate template",
		"A non-privileged principal (or a low-privileged owner) has write access to the certificate template object.",
		"An attacker who can modify the template can reconfigure it into an ESC1-style escalation path.",
		"Remove write/owner rights from non-Tier-0 principals on the template object.",
	},
	"ESC9": {
		"AD-CS-009", "ESC9 — certificate template lacks the security extension",
		"A template has the no-security-extension flag set with client authentication, no approvals, and low-privileged enrollment.",
		"The missing szOID_NTDS_CA_SECURITY_EXT enables certificate theft and impersonation despite strong certificate mapping.",
		"Remove CT_FLAG_NO_SECURITY_EXTENSION, require approval, and restrict enrollment.",
	},
}

func init() {
	addChecks(check{
		Category: "Certificates",
		Fn:       (*Snapshot).ruleADCSTemplates,
	})
}

// ruleADCSTemplates flags ESC-vulnerable certificate templates, one finding per
// ESC class per template.
func (s *Snapshot) ruleADCSTemplates() (out []Finding) {
	for _, o := range s.CertTemplates {
		a := collect.AssessTemplate(o, s.DomainSID)
		if len(a.ESC) == 0 {
			continue
		}
		name := firstNonEmpty(txt(o, "displayName"), txt(o, "cn"))
		for _, esc := range a.ESC {
			meta, ok := escRuleMeta[esc]
			if !ok {
				continue
			}
			out = append(out, Finding{
				RuleID:      meta.id,
				Title:       meta.title,
				Severity:    escSeverityFor(esc, a.Risk),
				Description: meta.description,
				Risk:        meta.risk,
				Remediation: meta.remediation,
				Affected: []Affected{{
					DistinguishedName: txt(o, "distinguishedName"),
					SAMAccountName:    txt(o, "cn"),
				}},
				Evidence: map[string]string{
					"template":          name,
					"esc":               esc,
					"all_esc":           strings.Join(a.ESC, ", "),
					"enrollment_rights": principalNames(a.Enroll),
					"write_rights":      principalNames(a.Write),
					"owner":             a.Owner.Name,
					"risk_factors":      strings.Join(a.Factors, "; "),
				},
			})
		}
	}
	return out
}

// escCeiling is the maximum severity an ESC class warrants on its own, so a
// secondary ESC on a template does not inherit a more severe class's rating.
var escCeiling = map[string]Severity{
	"ESC1": Critical,
	"ESC2": Critical,
	"ESC3": High,
	"ESC4": High,
	"ESC9": High,
}

// escSeverityFor returns the per-class severity: the template's overall risk,
// but never more severe than the ESC class's own ceiling.
func escSeverityFor(esc, risk string) Severity {
	sev := escSeverity(risk)
	if ceil, ok := escCeiling[esc]; ok && sev.rank() < ceil.rank() {
		return ceil
	}
	return sev
}

// escSeverity maps the collector's risk label to an audit severity.
func escSeverity(risk string) Severity {
	switch strings.ToUpper(strings.TrimSpace(risk)) {
	case "CRITICAL":
		return Critical
	case "HIGH":
		return High
	case "LOW":
		return Low
	default: // MEDIUM, or an ESC present with an unexpected label
		return Medium
	}
}

func principalNames(ps []collect.Principal) string {
	if len(ps) == 0 {
		return "None"
	}
	names := make([]string, len(ps))
	for i, p := range ps {
		names[i] = p.Name
	}
	return strings.Join(names, "; ")
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
