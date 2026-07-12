package collect_test

import (
	"encoding/csv"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"adit/internal/adws"
	"adit/internal/collect"
)

// mockQuerier returns objects based on a supplied function.
type mockQuerier struct {
	fn func(base, filter string, attrs []string) ([]*adws.Object, error)
}

func (m *mockQuerier) Query(base, filter string, attrs []string) ([]*adws.Object, error) {
	return m.fn(base, filter, attrs)
}

func tv(s string) []adws.Value { return []adws.Value{{Text: s}} }
func mv(ss ...string) []adws.Value {
	vs := make([]adws.Value, len(ss))
	for i, s := range ss {
		vs[i] = adws.Value{Text: s}
	}
	return vs
}
func bv(t *testing.T, h string) []adws.Value {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return []adws.Value{{Binary: b, IsBinary: true}}
}

func cell(t *testing.T, tbl *collect.Table, rowIdx int, header string) string {
	t.Helper()
	for i, h := range tbl.Headers {
		if h == header {
			return tbl.Rows[rowIdx][i]
		}
	}
	t.Fatalf("no column %q", header)
	return ""
}

var fixedNow = time.Date(2023, 3, 6, 0, 0, 0, 0, time.UTC)

func TestUsers(t *testing.T) {
	user := &adws.Object{Attributes: map[string][]adws.Value{
		"sAMAccountName":       tv("jdoe"),
		"name":                 tv("John Doe"),
		"userAccountControl":   tv("66048"), // NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD
		"pwdLastSet":           tv("133200000000000000"),
		"lastLogonTimestamp":   tv("0"),
		"accountExpires":       tv("9223372036854775807"),
		"objectSid":            bv(t, "010500000000000515000000dcf4dc3b833d2b46828ba62800020000"),
		"servicePrincipalName": mv("HTTP/host", "HOST/host"),
		"whenCreated":          tv("20230101000000.0Z"),
		"distinguishedName":    tv("CN=John Doe,OU=Users,DC=corp,DC=local"),
	}}
	q := &mockQuerier{fn: func(_, _ string, _ []string) ([]*adws.Object, error) {
		return []*adws.Object{user}, nil
	}}

	tbl, err := collect.New(q, "DC=corp,DC=local", collect.Config{Now: fixedNow}).Users()
	if err != nil {
		t.Fatal(err)
	}
	if len(tbl.Rows) != 1 {
		t.Fatalf("got %d rows", len(tbl.Rows))
	}

	checks := map[string]string{
		"UserName":                "jdoe",
		"Enabled":                 "True",
		"Password Never Expires":  "True",
		"Never Logged in":         "True",
		"HasSPN":                  "True",
		"Kerberos RC4":            "Default",
		"SID":                     "S-1-5-21-1004336348-1177238915-682003330-512",
		"Password LastSet":        "2/4/2023 4:00:00 PM",
		"Account Expiration Date": "",
		"whenCreated":             "1/1/2023 12:00:00 AM",
		"Password Age (days)":     "29",
		"Logon Age (days)":        "",
		"UserAccountControl":      "66048",
	}
	for header, want := range checks {
		if got := cell(t, tbl, 0, header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestUsersDelegation(t *testing.T) {
	// TrustedForDelegation (0x80000) + NORMAL_ACCOUNT.
	user := &adws.Object{Attributes: map[string][]adws.Value{
		"sAMAccountName":     tv("svc"),
		"userAccountControl": tv("524800"), // 0x80000 | 0x200
	}}
	q := &mockQuerier{fn: func(_, _ string, _ []string) ([]*adws.Object, error) {
		return []*adws.Object{user}, nil
	}}
	tbl, _ := collect.New(q, "dc", collect.Config{Now: fixedNow}).Users()
	if got := cell(t, tbl, 0, "Delegation Type"); got != "Unconstrained" {
		t.Errorf("Delegation Type = %q", got)
	}
	if got := cell(t, tbl, 0, "Delegation Protocol"); got != "Kerberos" {
		t.Errorf("Delegation Protocol = %q", got)
	}
}

func TestUsersCannotChangePasswordFromACL(t *testing.T) {
	// nTSecurityDescriptor whose DACL denies Change-Password to Everyone
	// (impacket ground truth, same bytes as internal/sd tests).
	const sdHex = "0100048090000000ac000000000000001400000004007c00030000000000240000000010" +
		"010500000000000515000000dcf4dc3b833d2b46828ba62800020000" +
		"050028000001000001000000531a72ab2f1ed011981900aa0040529b01010000000000050a000000" +
		"060028000001000001000000531a72ab2f1ed011981900aa0040529b010100000000000100000000" +
		"010500000000000515000000dcf4dc3b833d2b46828ba62800020000" +
		"010500000000000515000000dcf4dc3b833d2b46828ba62801020000"
	user := &adws.Object{Attributes: map[string][]adws.Value{
		"sAMAccountName":       tv("locked"),
		"userAccountControl":   tv("512"), // no PASSWD_CANT_CHANGE flag
		"ntSecurityDescriptor": bv(t, sdHex),
	}}
	q := &mockQuerier{fn: func(_, _ string, _ []string) ([]*adws.Object, error) {
		return []*adws.Object{user}, nil
	}}
	tbl, err := collect.New(q, "dc", collect.Config{Now: fixedNow}).Users()
	if err != nil {
		t.Fatal(err)
	}
	if got := cell(t, tbl, 0, "Cannot Change Password"); got != "True" {
		t.Errorf("Cannot Change Password = %q, want True (from ACL)", got)
	}
}

func TestUsersOnlyEnabledFilter(t *testing.T) {
	var gotFilter string
	q := &mockQuerier{fn: func(_, filter string, _ []string) ([]*adws.Object, error) {
		gotFilter = filter
		return nil, nil
	}}
	collect.New(q, "dc", collect.Config{OnlyEnabled: true}).Users()
	if !strings.Contains(gotFilter, "1.2.840.113556.1.4.803:=2") {
		t.Errorf("only-enabled filter missing UAC clause: %q", gotFilter)
	}
}

func TestGroups(t *testing.T) {
	group := &adws.Object{Attributes: map[string][]adws.Value{
		"name":              tv("Domain Admins"),
		"groupType":         tv("-2147483646"), // global security
		"adminCount":        tv("1"),
		"managedBy":         tv("CN=Administrator,CN=Users,DC=corp,DC=local"),
		"objectSid":         bv(t, "010500000000000515000000dcf4dc3b833d2b46828ba62800020000"),
		"whenCreated":       tv("20230101000000.0Z"),
		"distinguishedName": tv("CN=Domain Admins,CN=Users,DC=corp,DC=local"),
	}}
	q := &mockQuerier{fn: func(_, _ string, _ []string) ([]*adws.Object, error) {
		return []*adws.Object{group}, nil
	}}
	tbl, err := collect.New(q, "dc", collect.Config{}).Groups()
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]string{
		"Name":          "Domain Admins",
		"GroupCategory": "Security",
		"GroupScope":    "Global",
		"ManagedBy":     "Administrator",
		"AdminCount":    "1",
		"SID":           "S-1-5-21-1004336348-1177238915-682003330-512",
	}
	for header, want := range checks {
		if got := cell(t, tbl, 0, header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestComputersUnionsFilters(t *testing.T) {
	comp := &adws.Object{Attributes: map[string][]adws.Value{
		"sAMAccountName":         tv("WS01$"),
		"name":                   tv("WS01"),
		"dNSHostName":            tv("ws01.corp.local"),
		"userAccountControl":     tv("4096"), // WORKSTATION_TRUST_ACCOUNT (enabled)
		"operatingSystem":        tv("Windows 10 Pro"),
		"operatingSystemVersion": tv("10.0 (19045)"),
		"pwdLastSet":             tv("133200000000000000"),
		"distinguishedName":      tv("CN=WS01,OU=Computers,DC=corp,DC=local"),
	}}
	var filtersSeen int
	q := &mockQuerier{fn: func(_, filter string, _ []string) ([]*adws.Object, error) {
		filtersSeen++
		if strings.Contains(filter, "objectCategory=computer") {
			return []*adws.Object{comp}, nil
		}
		return nil, nil
	}}
	tbl, err := collect.New(q, "dc", collect.Config{Now: fixedNow}).Computers()
	if err != nil {
		t.Fatal(err)
	}
	if filtersSeen != 3 {
		t.Errorf("expected 3 filters queried, got %d", filtersSeen)
	}
	if len(tbl.Rows) != 1 {
		t.Fatalf("got %d rows", len(tbl.Rows))
	}
	if got := cell(t, tbl, 0, "Operating System"); got != "Windows 10 Pro 10.0 (19045)" {
		t.Errorf("Operating System = %q", got)
	}
	if got := cell(t, tbl, 0, "Enabled"); got != "True" {
		t.Errorf("Enabled = %q", got)
	}
}

func TestWriteCSV(t *testing.T) {
	tbl := &collect.Table{
		Name:    "Groups",
		Headers: []string{"Name", "SID"},
		Rows:    [][]string{{"Domain Admins", "S-1-5-21-x-512"}, {"Users, All", "S-1-5-21-x-513"}},
	}
	dir := t.TempDir()
	path, err := tbl.WriteCSV(dir)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, "Groups.csv") {
		t.Errorf("path = %q", path)
	}
	f, _ := os.Open(path)
	defer f.Close()
	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 || records[0][0] != "Name" || records[2][0] != "Users, All" {
		t.Errorf("csv = %v", records)
	}
}
