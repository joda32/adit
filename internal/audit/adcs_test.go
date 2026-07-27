package audit

import (
	"encoding/hex"
	"testing"

	"adit/internal/adws"
)

// esc1SD: template DACL where Authenticated Users hold Certificate-Enrollment
// and Domain Admins hold GenericAll (impacket ground truth, shared with the
// collector's ESC1 test).
const esc1SD = "0100048068000000840000000000000014000000040054000200000005002800000100000100000068c9100efb78d21190d400c04f79dc5501010000000000050b0000000000240000000010" +
	"010500000000000515000000dcf4dc3b833d2b46828ba62800020000" +
	"010500000000000515000000dcf4dc3b833d2b46828ba62800020000" +
	"010500000000000515000000dcf4dc3b833d2b46828ba62800020000"

func certTemplate(t *testing.T, sdHex string, pairs ...string) *adws.Object {
	t.Helper()
	o := obj(pairs...)
	b, err := hex.DecodeString(sdHex)
	if err != nil {
		t.Fatal(err)
	}
	o.Attributes["nTSecurityDescriptor"] = []adws.Value{{Binary: b, IsBinary: true}}
	return o
}

func TestADCSESC1Finding(t *testing.T) {
	s := testSnapshot()
	s.CertTemplates = []*adws.Object{certTemplate(t, esc1SD,
		"cn", "VulnTemplate",
		"displayName", "Vulnerable Template",
		"distinguishedName", "CN=VulnTemplate,CN=Certificate Templates,DC=corp,DC=local",
		"msPKI-Certificate-Name-Flag", "1", // ENROLLEE_SUPPLIES_SUBJECT
		"msPKI-Enrollment-Flag", "0", // no manager approval
		"msPKI-RA-Signature", "0",
		"pKIExtendedKeyUsage", "1.3.6.1.5.5.7.3.2", // client auth
	)}
	got := runRule(s, (*Snapshot).ruleADCSTemplates)
	if len(got) != 1 {
		t.Fatalf("expected 1 ADCS finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.RuleID != "AD-CS-001" || f.Severity != Critical {
		t.Fatalf("want AD-CS-001/Critical, got %s/%s", f.RuleID, f.Severity)
	}
	if f.Affected[0].SAMAccountName != "VulnTemplate" {
		t.Errorf("affected = %+v", f.Affected)
	}
	if f.Evidence["enrollment_rights"] != "Authenticated Users" {
		t.Errorf("enrollment_rights = %q", f.Evidence["enrollment_rights"])
	}
	if f.Evidence["esc"] != "ESC1" {
		t.Errorf("esc = %q", f.Evidence["esc"])
	}
}

func TestADCSNoFindingWhenClean(t *testing.T) {
	s := testSnapshot()
	// A template with no enrollee-supplied subject and no dangerous EKU/ACL:
	// manager approval set, so ESC1 is mitigated away.
	s.CertTemplates = []*adws.Object{certTemplate(t, esc1SD,
		"cn", "Managed",
		"msPKI-Certificate-Name-Flag", "1",
		"msPKI-Enrollment-Flag", "2", // PEND_ALL_REQUESTS (manager approval) -> ESC1 -> MEDIUM, still an ESC
		"pKIExtendedKeyUsage", "1.3.6.1.5.5.7.3.2",
	)}
	got := runRule(s, (*Snapshot).ruleADCSTemplates)
	// Manager approval downgrades ESC1 to MEDIUM but it is still reported.
	if len(got) != 1 || got[0].Severity != Medium {
		t.Fatalf("expected 1 Medium ADCS finding (manager-approval-mitigated ESC1), got %+v", got)
	}
}

func TestADCSFlowsThroughRun(t *testing.T) {
	s := testSnapshot()
	s.CertTemplates = []*adws.Object{certTemplate(t, esc1SD,
		"cn", "VulnTemplate",
		"msPKI-Certificate-Name-Flag", "1",
		"msPKI-Enrollment-Flag", "0",
		"pKIExtendedKeyUsage", "1.3.6.1.5.5.7.3.2",
	)}
	s.build()
	res := Run(s)
	var found bool
	for _, f := range res.Findings {
		if f.RuleID == "AD-CS-001" {
			found = true
			if f.Category != "Certificates" || f.RiskScore == 0 || !f.SafeCheck {
				t.Errorf("metadata not filled by Run: %+v", f)
			}
		}
	}
	if !found {
		t.Fatal("AD-CS-001 did not flow through Run")
	}
}
