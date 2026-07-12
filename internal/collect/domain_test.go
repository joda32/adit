package collect_test

import (
	"strconv"
	"testing"

	"adit/internal/adws"
	"adit/internal/collect"
)

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// kv looks up a Value by Category in a two-column table.
func kv(t *testing.T, tbl *collect.Table, category string) string {
	t.Helper()
	for _, row := range tbl.Rows {
		if row[0] == category {
			return row[1]
		}
	}
	t.Fatalf("no category %q", category)
	return ""
}

func TestDomain(t *testing.T) {
	q := &mockQuerier{fn: func(base, _ string, _ []string) ([]*adws.Object, error) {
		switch {
		case base == "DC=corp,DC=local":
			return []*adws.Object{{Attributes: map[string][]adws.Value{
				"msDS-Behavior-Version":     tv("7"),
				"name":                      tv("CORP"),
				"objectSid":                 bv(t, "010400000000000515000000dcf4dc3b833d2b46828ba628"),
				"ms-DS-MachineAccountQuota": tv("10"),
			}}}, nil
		case base == "CN=RID Manager$,CN=System,DC=corp,DC=local":
			// rIDAvailablePool: total (high32)=100000, issued (low32)=1500.
			pool := int64(100000)<<32 | 1500
			return []*adws.Object{{Attributes: map[string][]adws.Value{
				"rIDAvailablePool": tv(itoa(pool)),
			}}}, nil
		}
		return nil, nil
	}}
	tbl, err := collect.New(q, "DC=corp,DC=local", collect.Config{}).Domain()
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]string{
		"Name":             "corp.local",
		"NetBIOS":          "CORP",
		"Functional Level": "Windows2016Domain",
		"RIDs Issued":      "1500",
		"RIDs Remaining":   "98500",
	}
	for cat, want := range checks {
		if got := kv(t, tbl, cat); got != want {
			t.Errorf("%s = %q, want %q", cat, got, want)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	obj := &adws.Object{Attributes: map[string][]adws.Value{
		"minPwdLength":     tv("14"),
		"pwdHistoryLength": tv("24"),
		"pwdProperties":    tv("1"),               // complexity on, reversible off
		"maxPwdAge":        tv("-36288000000000"), // 42 days
		"lockoutThreshold": tv("5"),
		"lockoutDuration":  tv("-9000000000"), // 15 minutes
	}}
	q := &mockQuerier{fn: func(_, _ string, _ []string) ([]*adws.Object, error) {
		return []*adws.Object{obj}, nil
	}}
	tbl, err := collect.New(q, "dc", collect.Config{}).PasswordPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if len(tbl.Rows) != 9 {
		t.Fatalf("got %d rows, want 9", len(tbl.Rows))
	}
	// Row 0 = history, its Current Value column (index 1).
	if tbl.Rows[0][1] != "24" {
		t.Errorf("history = %q", tbl.Rows[0][1])
	}
	// Maximum password age formatted as interval.
	if got := findPolicy(t, tbl, "Maximum password age (d h m s)"); got != "42d 0h 0m 0s" {
		t.Errorf("max age = %q", got)
	}
	// Complexity TRUE.
	if got := findPolicy(t, tbl, "Password must meet complexity requirements"); got != "TRUE" {
		t.Errorf("complexity = %q", got)
	}
	// Lockout duration.
	if got := findPolicy(t, tbl, "Account lockout duration (d h m s)"); got != "0d 0h 15m 0s" {
		t.Errorf("lockout = %q", got)
	}
}

func findPolicy(t *testing.T, tbl *collect.Table, policy string) string {
	t.Helper()
	for _, row := range tbl.Rows {
		if row[0] == policy {
			return row[1]
		}
	}
	t.Fatalf("no policy %q", policy)
	return ""
}

func TestDomainControllersFSMO(t *testing.T) {
	q := &mockQuerier{fn: func(base, filter string, _ []string) ([]*adws.Object, error) {
		switch {
		case filter == "(objectCategory=domainDNS)": // PDC owner
			return []*adws.Object{{Attributes: map[string][]adws.Value{
				"fSMORoleOwner": tv("CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=local"),
			}}}, nil
		case filter == "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))":
			return []*adws.Object{{Attributes: map[string][]adws.Value{
				"name":              tv("DC1"),
				"dNSHostName":       tv("dc1.corp.local"),
				"operatingSystem":   tv("Windows Server 2022"),
				"serverReferenceBL": tv("CN=DC1,CN=Servers,CN=HQ,CN=Sites,CN=Configuration,DC=corp,DC=local"),
			}}}, nil
		}
		return nil, nil
	}}
	tbl, err := collect.New(q, "DC=corp,DC=local", collect.Config{}).DomainControllers()
	if err != nil {
		t.Fatal(err)
	}
	if len(tbl.Rows) != 1 {
		t.Fatalf("got %d rows", len(tbl.Rows))
	}
	checks := map[string]string{
		"Name": "dc1", "Site": "HQ", "PDC": "TRUE", "Schema": "FALSE",
	}
	for h, want := range checks {
		if got := cell(t, tbl, 0, h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
}

func TestGPLinks(t *testing.T) {
	guid := "{31B2F340-016D-11D2-945F-00C04FB984F9}"
	q := &mockQuerier{fn: func(_, filter string, _ []string) ([]*adws.Object, error) {
		switch filter {
		case "(objectCategory=groupPolicyContainer)":
			return []*adws.Object{{Attributes: map[string][]adws.Value{
				"name":        tv(guid),
				"displayName": tv("Default Domain Policy"),
			}}}, nil
		case "(|(objectCategory=domainDNS)(objectCategory=organizationalUnit))":
			return []*adws.Object{{Attributes: map[string][]adws.Value{
				"name":              tv("corp"),
				"distinguishedName": tv("DC=corp,DC=local"),
				"gPLink":            tv("[LDAP://cn=" + guid + ",cn=policies,cn=system,DC=corp,DC=local;0]"),
				"gPOptions":         tv("0"),
			}}}, nil
		}
		return nil, nil
	}}
	tbl, err := collect.New(q, "DC=corp,DC=local", collect.Config{}).GPLinks()
	if err != nil {
		t.Fatal(err)
	}
	if len(tbl.Rows) != 1 {
		t.Fatalf("got %d rows", len(tbl.Rows))
	}
	if got := cell(t, tbl, 0, "GPO"); got != "Default Domain Policy" {
		t.Errorf("GPO = %q (want resolved display name)", got)
	}
	if got := cell(t, tbl, 0, "Link Enabled"); got != "True" {
		t.Errorf("Link Enabled = %q", got)
	}
	if got := cell(t, tbl, 0, "Enforced"); got != "False" {
		t.Errorf("Enforced = %q", got)
	}
}
