package collect_test

import (
	"strings"
	"testing"

	"adit/internal/adws"
	"adit/internal/collect"
)

func single(o *adws.Object) *mockQuerier {
	return &mockQuerier{fn: func(_, _ string, _ []string) ([]*adws.Object, error) {
		return []*adws.Object{o}, nil
	}}
}

func TestOUs(t *testing.T) {
	ou := &adws.Object{Attributes: map[string][]adws.Value{
		"name":              tv("Servers"),
		"distinguishedName": tv("OU=Servers,OU=Tier0,DC=corp,DC=local"),
		"description":       tv("server OU"),
	}}
	tbl, err := collect.New(single(ou), "dc", collect.Config{}).OUs()
	if err != nil {
		t.Fatal(err)
	}
	if got := cell(t, tbl, 0, "Depth"); got != "2" {
		t.Errorf("Depth = %q, want 2", got)
	}
	if got := cell(t, tbl, 0, "Name"); got != "Servers" {
		t.Errorf("Name = %q", got)
	}
}

func TestTrusts(t *testing.T) {
	trust := &adws.Object{Attributes: map[string][]adws.Value{
		"distinguishedName": tv("CN=child.corp.local,CN=System,DC=corp,DC=local"),
		"trustPartner":      tv("child.corp.local"),
		"trustDirection":    tv("3"),
		"trustType":         tv("2"),
		"trustAttributes":   tv("32"), // 0x20 Within Forest
	}}
	tbl, err := collect.New(single(trust), "dc", collect.Config{}).Trusts()
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]string{
		"Source Domain":   "corp.local",
		"Target Domain":   "child.corp.local",
		"Trust Direction": "Bidirectional",
		"Trust Type":      "Uplevel",
		"Attributes":      "Within Forest",
	}
	for h, want := range checks {
		if got := cell(t, tbl, 0, h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
}

func TestSitesRequiresConfigDN(t *testing.T) {
	var base string
	q := &mockQuerier{fn: func(b, _ string, _ []string) ([]*adws.Object, error) {
		base = b
		return nil, nil
	}}
	// With no ConfigDN, Sites returns empty without querying.
	tbl, _ := collect.New(q, "dc", collect.Config{}).Sites()
	if len(tbl.Rows) != 0 || base != "" {
		t.Errorf("expected no query without ConfigDN")
	}
	// With ConfigDN it queries under CN=Sites,<configDN>.
	collect.New(q, "dc", collect.Config{ConfigDN: "CN=Configuration,DC=corp,DC=local"}).Sites()
	if base != "CN=Sites,CN=Configuration,DC=corp,DC=local" {
		t.Errorf("site base = %q", base)
	}
}

func TestUserSPNsOneRowPerSPN(t *testing.T) {
	u := &adws.Object{Attributes: map[string][]adws.Value{
		"sAMAccountName":       tv("svc"),
		"userAccountControl":   tv("512"),
		"servicePrincipalName": mv("MSSQLSvc/db01.corp.local:1433", "HTTP/web01.corp.local"),
		"memberOf":             mv("CN=SQL Admins,OU=Groups,DC=corp,DC=local"),
	}}
	tbl, err := collect.New(single(u), "dc", collect.Config{}).UserSPNs()
	if err != nil {
		t.Fatal(err)
	}
	if len(tbl.Rows) != 2 {
		t.Fatalf("got %d rows, want 2 (one per SPN)", len(tbl.Rows))
	}
	if got := cell(t, tbl, 0, "Service"); got != "MSSQLSvc" {
		t.Errorf("row0 Service = %q", got)
	}
	if got := cell(t, tbl, 0, "Host"); got != "db01.corp.local:1433" {
		t.Errorf("row0 Host = %q", got)
	}
	if got := cell(t, tbl, 0, "Memberof"); got != "SQL Admins" {
		t.Errorf("Memberof = %q", got)
	}
}

func TestKerberoastableRisk(t *testing.T) {
	u := &adws.Object{Attributes: map[string][]adws.Value{
		"sAMAccountName":                tv("svc"),
		"userAccountControl":            tv("512"),
		"servicePrincipalName":          mv("MSSQLSvc/db01"),
		"adminCount":                    tv("1"), // privileged -> CRITICAL
		"msDS-SupportedEncryptionTypes": tv("4"), // RC4 only, no AES256 -> weak
	}}
	tbl, err := collect.New(single(u), "dc", collect.Config{Now: fixedNow}).Kerberoastable()
	if err != nil {
		t.Fatal(err)
	}
	if got := cell(t, tbl, 0, "Risk Level"); got != "CRITICAL" {
		t.Errorf("Risk Level = %q, want CRITICAL", got)
	}
	factors := cell(t, tbl, 0, "Risk Factors")
	if !strings.Contains(factors, "Privileged") || !strings.Contains(factors, "RC4") {
		t.Errorf("Risk Factors = %q", factors)
	}
	if got := cell(t, tbl, 0, "SPN Count"); got != "1" {
		t.Errorf("SPN Count = %q", got)
	}
}

func TestKRBTGTGoldenTicketRisk(t *testing.T) {
	// pwdLastSet ~ 2019-04-17 vs fixedNow 2023 -> > 365 days -> CRITICAL.
	k := &adws.Object{Attributes: map[string][]adws.Value{
		"sAMAccountName":    tv("krbtgt"),
		"distinguishedName": tv("CN=krbtgt,CN=Users,DC=corp,DC=local"),
		"pwdLastSet":        tv("132000000000000000"),
	}}
	tbl, err := collect.New(single(k), "dc", collect.Config{Now: fixedNow}).KRBTGT()
	if err != nil {
		t.Fatal(err)
	}
	if got := cell(t, tbl, 0, "Risk Level"); got != "CRITICAL" {
		t.Errorf("Risk Level = %q, want CRITICAL", got)
	}
	if got := cell(t, tbl, 0, "Risk Factors"); !strings.Contains(got, "Golden Ticket") {
		t.Errorf("Risk Factors = %q", got)
	}
}

func TestASREPRoastable(t *testing.T) {
	u := &adws.Object{Attributes: map[string][]adws.Value{
		"sAMAccountName":     tv("noauth"),
		"userAccountControl": tv("4194816"), // 0x400200 DONT_REQ_PREAUTH | NORMAL
	}}
	tbl, err := collect.New(single(u), "dc", collect.Config{Now: fixedNow}).ASREPRoastable()
	if err != nil {
		t.Fatal(err)
	}
	if got := cell(t, tbl, 0, "Has SPN"); got != "No" {
		t.Errorf("Has SPN = %q", got)
	}
	if got := cell(t, tbl, 0, "Enabled"); got != "True" {
		t.Errorf("Enabled = %q", got)
	}
	if got := cell(t, tbl, 0, "Risk Level"); got != "Medium" {
		t.Errorf("Risk Level = %q, want Medium", got)
	}
}
