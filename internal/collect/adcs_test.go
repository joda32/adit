package collect_test

import (
	"testing"

	"adit/internal/adws"
	"adit/internal/collect"
)

// ESC1 template security descriptor (impacket ground truth): Authenticated
// Users have Certificate-Enrollment; Domain Admins have GenericAll.
const esc1SD = "0100048068000000840000000000000014000000040054000200000005002800000100000100000068c9100efb78d21190d400c04f79dc5501010000000000050b0000000000240000000010" +
	"010500000000000515000000dcf4dc3b833d2b46828ba62800020000" +
	"010500000000000515000000dcf4dc3b833d2b46828ba62800020000" +
	"010500000000000515000000dcf4dc3b833d2b46828ba62800020000"

func TestCertificateTemplatesESC1(t *testing.T) {
	tmpl := &adws.Object{Attributes: map[string][]adws.Value{
		"cn":                          tv("VulnTemplate"),
		"displayName":                 tv("Vulnerable Template"),
		"distinguishedName":           tv("CN=VulnTemplate,CN=Certificate Templates,...,DC=corp,DC=local"),
		"msPKI-Certificate-Name-Flag": tv("1"),                 // ENROLLEE_SUPPLIES_SUBJECT
		"msPKI-Enrollment-Flag":       tv("0"),                 // no manager approval
		"msPKI-RA-Signature":          tv("0"),                 // no authorized signatures
		"pKIExtendedKeyUsage":         tv("1.3.6.1.5.5.7.3.2"), // client auth
		"nTSecurityDescriptor":        bv(t, esc1SD),
	}}
	q := &mockQuerier{fn: func(_, filter string, _ []string) ([]*adws.Object, error) {
		switch filter {
		case "(objectCategory=domainDNS)": // domain SID lookup
			return []*adws.Object{{Attributes: map[string][]adws.Value{
				"objectSid": bv(t, "010400000000000515000000dcf4dc3b833d2b46828ba628"),
			}}}, nil
		case "(objectClass=pKICertificateTemplate)":
			return []*adws.Object{tmpl}, nil
		}
		return nil, nil
	}}

	cfg := collect.Config{ConfigDN: "CN=Configuration,DC=corp,DC=local"}
	tbl, err := collect.New(q, "DC=corp,DC=local", cfg).CertificateTemplates()
	if err != nil {
		t.Fatal(err)
	}
	if len(tbl.Rows) != 1 {
		t.Fatalf("got %d rows", len(tbl.Rows))
	}
	checks := map[string]string{
		"Template Name":             "VulnTemplate",
		"Enrollee Supplies Subject": "True",
		"Client Authentication":     "True",
		"ESC Vulnerabilities":       "ESC1",
		"Risk Level":                "CRITICAL",
		"Enrollment Rights":         "Authenticated Users",
		"Write Permissions":         "Domain Admins",
		"Owner":                     "Domain Admins",
	}
	for h, want := range checks {
		if got := cell(t, tbl, 0, h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
}

func TestCertificateTemplatesRequiresConfigDN(t *testing.T) {
	q := &mockQuerier{fn: func(_, _ string, _ []string) ([]*adws.Object, error) {
		t.Fatal("should not query without ConfigDN")
		return nil, nil
	}}
	tbl, err := collect.New(q, "dc", collect.Config{}).CertificateTemplates()
	if err != nil || len(tbl.Rows) != 0 {
		t.Errorf("expected empty table without ConfigDN")
	}
}

// TestAssessESCManagerApprovalMitigation verifies manager approval downgrades
// ESC1 from CRITICAL to MEDIUM (via the full collector path).
func TestCertificateTemplatesManagerApprovalMitigatesESC1(t *testing.T) {
	tmpl := &adws.Object{Attributes: map[string][]adws.Value{
		"cn":                          tv("Managed"),
		"msPKI-Certificate-Name-Flag": tv("1"),
		"msPKI-Enrollment-Flag":       tv("2"), // PEND_ALL_REQUESTS (manager approval)
		"pKIExtendedKeyUsage":         tv("1.3.6.1.5.5.7.3.2"),
		"nTSecurityDescriptor":        bv(t, esc1SD),
	}}
	q := &mockQuerier{fn: func(_, filter string, _ []string) ([]*adws.Object, error) {
		if filter == "(objectClass=pKICertificateTemplate)" {
			return []*adws.Object{tmpl}, nil
		}
		return nil, nil
	}}
	tbl, err := collect.New(q, "dc", collect.Config{ConfigDN: "CN=Configuration,dc"}).CertificateTemplates()
	if err != nil {
		t.Fatal(err)
	}
	if got := cell(t, tbl, 0, "Risk Level"); got != "MEDIUM" {
		t.Errorf("Risk Level = %q, want MEDIUM (manager approval)", got)
	}
	if got := cell(t, tbl, 0, "Requires Manager Approval"); got != "True" {
		t.Errorf("Requires Manager Approval = %q", got)
	}
}
