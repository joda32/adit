package collect_test

import (
	"strings"
	"testing"

	"adit/internal/adws"
	"adit/internal/collect"
)

// LAPS computer SD (impacket): custom group RID-1105 has object-specific
// CONTROL_ACCESS for the LAPS attribute GUID; Domain Admins have GenericAll.
const lapsSD = "01000480780000009400000000000000140000000400640002000000050038000001000001000000c4b3a2f1000011112222333344445555010500000000000515000000dcf4dc3b833d2b46828ba62851040000" +
	"00240000000010" +
	"010500000000000515000000dcf4dc3b833d2b46828ba62800020000" +
	"010500000000000515000000dcf4dc3b833d2b46828ba62800020000" +
	"010500000000000515000000dcf4dc3b833d2b46828ba62800020000"

// schemaIDGUID bytes (bytes_le) for the LAPS attribute GUID above.
const lapsSchemaGUIDBytes = "c4b3a2f1000011112222333344445555"

func TestLAPS(t *testing.T) {
	computer := &adws.Object{Attributes: map[string][]adws.Value{
		"dNSHostName":                 tv("ws01.corp.local"),
		"userAccountControl":          tv("4096"),
		"ms-Mcs-AdmPwd":               tv("S3cr3tP@ss!"),
		"ms-Mcs-AdmPwdExpirationTime": tv("133200000000000000"),
		"nTSecurityDescriptor":        bv(t, lapsSD),
	}}
	q := &mockQuerier{fn: func(_, filter string, _ []string) ([]*adws.Object, error) {
		switch {
		case strings.HasPrefix(filter, "(name=ms-Mcs-AdmPwd)"):
			return []*adws.Object{{Attributes: map[string][]adws.Value{
				"name":         tv("ms-Mcs-AdmPwd"),
				"schemaIDGUID": bv(t, lapsSchemaGUIDBytes),
			}}}, nil
		case filter == "(objectCategory=computer)":
			return []*adws.Object{computer}, nil
		}
		return nil, nil
	}}
	cfg := collect.Config{SchemaDN: "CN=Schema,CN=Configuration,DC=corp,DC=local"}
	tbl, err := collect.New(q, "DC=corp,DC=local", cfg).LAPS()
	if err != nil {
		t.Fatal(err)
	}
	if len(tbl.Rows) != 1 {
		t.Fatalf("got %d rows", len(tbl.Rows))
	}
	checks := map[string]string{
		"Hostname": "ws01.corp.local",
		"Stored":   "True",
		"Readable": "True",
		"Password": "S3cr3tP@ss!",
	}
	for h, want := range checks {
		if got := cell(t, tbl, 0, h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
	// The custom RID-1105 principal should be listed with the explicit reason;
	// Domain Admins (high-priv) filtered out.
	readers := cell(t, tbl, 0, "Readers")
	if !strings.Contains(readers, "Explicit LAPS read permission") {
		t.Errorf("Readers = %q, want an explicit LAPS reader", readers)
	}
	if strings.Contains(readers, "Domain Admins") {
		t.Errorf("Readers should filter Domain Admins: %q", readers)
	}
}

func TestLAPSNotInstalled(t *testing.T) {
	q := &mockQuerier{fn: func(_, filter string, _ []string) ([]*adws.Object, error) {
		return nil, nil // schema lookup returns nothing -> LAPS not installed
	}}
	tbl, err := collect.New(q, "dc", collect.Config{SchemaDN: "CN=Schema,dc"}).LAPS()
	if err != nil {
		t.Fatal(err)
	}
	if len(tbl.Rows) != 0 {
		t.Errorf("expected no rows when LAPS not installed")
	}
}

func TestProtectedGroups(t *testing.T) {
	// Tier-0 user NOT in Protected Users -> HIGH.
	da := &adws.Object{Attributes: map[string][]adws.Value{
		"sAMAccountName": tv("alice"),
		"name":           tv("Alice Admin"),
		"objectCategory": tv("CN=Person,CN=Schema,CN=Configuration,DC=corp,DC=local"),
		"objectSid":      bv(t, "010500000000000515000000dcf4dc3b833d2b46828ba62851040000"),
		"memberOf":       mv("CN=Domain Admins,CN=Users,DC=corp,DC=local"),
		"adminCount":     tv("1"),
	}}
	// The Domain Admins group object itself.
	grp := &adws.Object{Attributes: map[string][]adws.Value{
		"name":           tv("Domain Admins"),
		"objectCategory": tv("CN=Group,CN=Schema,CN=Configuration,DC=corp,DC=local"),
		"objectSid":      bv(t, "010500000000000515000000dcf4dc3b833d2b46828ba62800020000"),
	}}
	q := &mockQuerier{fn: func(_, _ string, _ []string) ([]*adws.Object, error) {
		return []*adws.Object{da, grp}, nil
	}}
	tbl, err := collect.New(q, "dc", collect.Config{}).ProtectedGroups()
	if err != nil {
		t.Fatal(err)
	}
	if len(tbl.Rows) != 2 {
		t.Fatalf("got %d rows", len(tbl.Rows))
	}
	// Row 0: Alice — tier-0 user, not in Protected Users.
	if got := cell(t, tbl, 0, "Type"); got != "User" {
		t.Errorf("alice Type = %q", got)
	}
	if got := cell(t, tbl, 0, "Risk Level"); got != "HIGH" {
		t.Errorf("alice Risk Level = %q, want HIGH", got)
	}
	if got := cell(t, tbl, 0, "In Protected Users Group"); got != "No" {
		t.Errorf("alice Protected Users = %q", got)
	}
	if got := cell(t, tbl, 0, "AdminSDHolder Protected Group Membership"); got != "Domain Admins" {
		t.Errorf("alice membership = %q", got)
	}
	// Row 1: the Domain Admins group object.
	if got := cell(t, tbl, 1, "Type"); got != "Group" {
		t.Errorf("group Type = %q", got)
	}
	if got := cell(t, tbl, 1, "Status"); got != "AdminSDHolder Protected Group (Built-in)" {
		t.Errorf("group Status = %q", got)
	}
	if got := cell(t, tbl, 1, "Risk Level"); got != "Info" {
		t.Errorf("group Risk Level = %q, want Info", got)
	}
}
