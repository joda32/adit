package audit

import (
	"strings"

	"adit/internal/adws"
)

// CA / PKI-object level ADCS rules.
//
// Scope note: ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2), ESC7 (CA officer/ManageCA
// roles) and ESC8 (web-enrollment NTLM relay) live in the CA host's registry
// and HTTP endpoints, not in Active Directory, so they cannot be observed over
// ADWS. What is AD-visible is ESC5 — dangerous control of the PKI objects — and
// the presence of CAs, which we report so the residual host-level checks can be
// followed up off-ADWS.

// adminRIDs are the trailing RIDs of built-in privileged groups. A SID ending
// in one of these is a Tier-0 group in *some* domain (user RIDs start at 1000),
// so it is an expected controller of PKI objects even in another forest domain.
var adminRIDs = map[string]bool{
	"512": true, "516": true, "518": true, "519": true, "520": true,
	"521": true, "498": true, "517": true, "526": true, "527": true,
}

func hasAdminRID(sid string) bool {
	if i := strings.LastIndexByte(sid, '-'); i >= 0 {
		return adminRIDs[sid[i+1:]]
	}
	return false
}

// isExpectedPKIController is isExpectedController widened to accept any built-in
// admin RID regardless of domain (Enterprise Admins et al. live in the root
// domain, which may differ from the audited domain in a forest).
func (s *Snapshot) isExpectedPKIController(sid string) bool {
	return s.isExpectedController(sid, "") || hasAdminRID(sid)
}

func init() {
	addChecks(
		check{
			ID: "AD-CS-005", Title: "Dangerous control over an AD CS PKI object (ESC5)",
			Category: "Certificates", Severity: Critical,
			Description: "A non-Tier-0 principal has takeover-grade control (GenericAll/Write, WriteDACL/Owner) over an AD CS PKI object such as NTAuthCertificates, the Certification Authorities store, or a CA object.",
			Risk:        "Writing NTAuthCertificates lets an attacker add a rogue CA certificate and forge authentication certificates for any principal; control of a CA object allows publishing attacker-chosen templates.",
			Remediation: "Remove write/owner rights from non-Tier-0 principals on AD CS PKI objects; restore the default ACLs.",
			Fn:          (*Snapshot).ruleADCSObjectControl,
		},
		check{
			ID: "AD-CS-006", Title: "AD CS present — verify host-level ESC6/ESC7/ESC8 off-ADWS",
			Category: "Certificates", Severity: Info,
			Description: "One or more Certificate Authorities are present. ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2), ESC7 (CA ManageCA/Certificates roles) and ESC8 (web enrollment / NTLM relay) are stored in the CA host registry and HTTP endpoints, which are not exposed over ADWS.",
			Risk:        "These CA-host misconfigurations can enable domain-wide compromise but cannot be confirmed via ADWS alone.",
			Remediation: "Verify ESC6/ESC7/ESC8 directly against each CA host (e.g. with Certipy 'find' / 'ca').",
			Fn:          (*Snapshot).ruleADCSHostChecks,
		},
	)
}

// ruleADCSObjectControl flags non-Tier-0 dangerous control over PKI objects.
func (s *Snapshot) ruleADCSObjectControl() (out []Finding) {
	for _, o := range s.PKIObjects {
		d := parseSD(o)
		if d == nil {
			continue
		}
		label := pkiLabel(o)
		sev := pkiSeverity(o)

		if d.Owner != "" && !s.isExpectedPKIController(d.Owner) {
			out = append(out, Finding{
				RuleID: "AD-CS-005", Severity: sev,
				Title:    "Untrusted owner of an AD CS PKI object (ESC5)",
				Affected: []Affected{{DistinguishedName: txt(o, "distinguishedName")}},
				Evidence: map[string]string{"object": label, "owner": s.principalName(d.Owner), "right": "Owner"},
			})
		}
		if d.DACL == nil {
			continue
		}
		seen := map[string]bool{}
		for _, ace := range d.DACL.ACEs {
			if s.isExpectedPKIController(ace.SID) {
				continue
			}
			r, ok := classifyDangerous(ace)
			if !ok || seen[ace.SID+r.kind] {
				continue
			}
			seen[ace.SID+r.kind] = true
			out = append(out, Finding{
				RuleID: "AD-CS-005", Severity: sev,
				Affected: []Affected{{DistinguishedName: txt(o, "distinguishedName")}},
				Evidence: map[string]string{
					"object":    label,
					"principal": s.principalName(ace.SID),
					"right":     r.kind,
				},
			})
		}
	}
	return out
}

// ruleADCSHostChecks emits a single informational finding when CAs exist,
// pointing at the host-level ESCs that ADWS cannot see.
func (s *Snapshot) ruleADCSHostChecks() []Finding {
	if len(s.CAs) == 0 {
		return nil
	}
	var affected []Affected
	var names []string
	for _, ca := range s.CAs {
		host := firstNonEmpty(txt(ca, "dNSHostName"), txt(ca, "cn"))
		names = append(names, host)
		affected = append(affected, Affected{DistinguishedName: txt(ca, "distinguishedName"), SAMAccountName: txt(ca, "cn")})
	}
	return []Finding{{
		RuleID:   "AD-CS-006",
		Affected: affected,
		Evidence: map[string]string{
			"certificate_authorities": strings.Join(names, ", "),
			"not_checked":             "ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2), ESC7 (CA role ACLs), ESC8 (web enrollment / NTLM relay)",
		},
	}}
}

// pkiLabel gives a friendly name for a PKI object.
func pkiLabel(o *adws.Object) string {
	dn := strings.ToLower(txt(o, "distinguishedName"))
	switch {
	case strings.HasPrefix(dn, "cn=ntauthcertificates"):
		return "NTAuthCertificates"
	case strings.HasPrefix(dn, "cn=certification authorities"):
		return "Certification Authorities store"
	}
	if n := firstNonEmpty(txt(o, "cn"), txt(o, "name")); n != "" {
		return "CA " + n
	}
	return txt(o, "distinguishedName")
}

// pkiSeverity rates control of the object: forging-capable objects are Critical,
// individual CA objects High.
func pkiSeverity(o *adws.Object) Severity {
	dn := strings.ToLower(txt(o, "distinguishedName"))
	if strings.HasPrefix(dn, "cn=ntauthcertificates") || strings.HasPrefix(dn, "cn=certification authorities") {
		return Critical
	}
	return High
}
