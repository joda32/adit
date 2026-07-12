package collect_test

import (
	"strings"
	"testing"

	"adit/internal/adws"
	"adit/internal/collect"
)

// nTSecurityDescriptor (impacket, same as internal/sd tests): owner Domain
// Admins; DACL grants Domain Admins GenericAll.
const gmsaNtSD = "0100048090000000ac000000000000001400000004007c00030000000000240000000010" +
	"010500000000000515000000dcf4dc3b833d2b46828ba62800020000" +
	"050028000001000001000000531a72ab2f1ed011981900aa0040529b01010000000000050a000000" +
	"060028000001000001000000531a72ab2f1ed011981900aa0040529b010100000000000100000000" +
	"010500000000000515000000dcf4dc3b833d2b46828ba62800020000" +
	"010500000000000515000000dcf4dc3b833d2b46828ba62801020000"

// msDS-GroupMSAMembership (impacket): a custom group RID-1106 may retrieve.
const gmsaMembership = "010004804000000050000000000000001400000004002c000100000000002400ff010f00" +
	"010500000000000515000000dcf4dc3b833d2b46828ba6285204000001020000000000052000000020020000" +
	"01020000000000052000000020020000"

func TestGMSA(t *testing.T) {
	acc := &adws.Object{Attributes: map[string][]adws.Value{
		"sAMAccountName":               tv("svc-sql$"),
		"name":                         tv("svc-sql"),
		"userAccountControl":           tv("4096"),
		"dNSHostName":                  tv("sql.corp.local"),
		"servicePrincipalName":         mv("MSSQLSvc/sql.corp.local:1433"),
		"pwdLastSet":                   tv("133200000000000000"),
		"msDS-ManagedPasswordInterval": tv("30"),
		"objectSid":                    bv(t, "010500000000000515000000dcf4dc3b833d2b46828ba62853040000"),
		"nTSecurityDescriptor":         bv(t, gmsaNtSD),
		"msDS-GroupMSAMembership":      bv(t, gmsaMembership),
	}}
	q := &mockQuerier{fn: func(_, _ string, _ []string) ([]*adws.Object, error) {
		return []*adws.Object{acc}, nil
	}}
	tbl, err := collect.New(q, "DC=corp,DC=local", collect.Config{Now: fixedNow}).GMSA()
	if err != nil {
		t.Fatal(err)
	}
	if len(tbl.Rows) != 1 {
		t.Fatalf("got %d rows", len(tbl.Rows))
	}
	checks := map[string]string{
		"SAM Account Name":                  "svc-sql$",
		"Enabled":                           "True",
		"Owner":                             "Domain Admins",
		"Password Rotation Interval (days)": "30",
		"Write Permissions":                 "Domain Admins",
		// RID-1106 isn't a well-known SID, so it resolves to the raw SID string.
		"Allowed To Retrieve Password": "S-1-5-21-1004336348-1177238915-682003330-1106",
	}
	for h, want := range checks {
		if got := cell(t, tbl, 0, h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
}

func TestDMSABadSuccessor(t *testing.T) {
	acc := &adws.Object{Attributes: map[string][]adws.Value{
		"sAMAccountName":                    tv("dmsa1$"),
		"name":                              tv("dmsa1"),
		"userAccountControl":                tv("4096"),
		"msDS-ManagedAccountPrecededByLink": tv("CN=oldsvc,CN=Managed Service Accounts,DC=corp,DC=local"),
		"msDS-DelegatedMSAState":            tv("2"),
		"objectSid":                         bv(t, "010500000000000515000000dcf4dc3b833d2b46828ba62854040000"),
	}}
	q := &mockQuerier{fn: func(_, filter string, _ []string) ([]*adws.Object, error) {
		switch {
		case strings.HasPrefix(filter, "(lDAPDisplayName="): // schema supports dMSA
			return []*adws.Object{{Attributes: map[string][]adws.Value{
				"lDAPDisplayName": tv("msDS-DelegatedManagedServiceAccount"),
			}}}, nil
		case filter == "(objectClass=msDS-DelegatedManagedServiceAccount)":
			return []*adws.Object{acc}, nil
		}
		return nil, nil
	}}
	cfg := collect.Config{Now: fixedNow, SchemaDN: "CN=Schema,CN=Configuration,DC=corp,DC=local"}
	tbl, err := collect.New(q, "DC=corp,DC=local", cfg).DMSA()
	if err != nil {
		t.Fatal(err)
	}
	if len(tbl.Rows) != 1 {
		t.Fatalf("got %d rows", len(tbl.Rows))
	}
	checks := map[string]string{
		"SAM Account Name":                  "dmsa1$",
		"Enabled":                           "TRUE", // dMSA uses upper-case
		"badSuccessor Vulnerable":           "True",
		"Risk Level":                        "CRITICAL",
		"Superseded Account (BadSuccessor)": "CN=oldsvc,CN=Managed Service Accounts,DC=corp,DC=local",
	}
	for h, want := range checks {
		if got := cell(t, tbl, 0, h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
}

func TestDMSANotSupported(t *testing.T) {
	q := &mockQuerier{fn: func(_, _ string, _ []string) ([]*adws.Object, error) {
		return nil, nil // schema class not found
	}}
	tbl, err := collect.New(q, "dc", collect.Config{SchemaDN: "CN=Schema,dc"}).DMSA()
	if err != nil {
		t.Fatal(err)
	}
	if len(tbl.Rows) != 0 {
		t.Errorf("expected no rows when dMSA unsupported")
	}
}
