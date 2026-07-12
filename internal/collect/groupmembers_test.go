package collect_test

import (
	"testing"

	"adit/internal/adws"
	"adit/internal/collect"
)

func TestGroupMembers(t *testing.T) {
	q := &mockQuerier{fn: func(_, filter string, _ []string) ([]*adws.Object, error) {
		switch filter {
		case "(&(objectCategory=person)(objectClass=user))": // user cache
			return []*adws.Object{{Attributes: map[string][]adws.Value{
				"distinguishedName": tv("CN=alice,CN=Users,DC=corp,DC=local"),
				"sAMAccountName":    tv("alice"),
				"objectSid":         bv(t, "010500000000000515000000dcf4dc3b833d2b46828ba62851040000"),
			}}}, nil
		case "(objectCategory=group)": // group cache
			return []*adws.Object{{Attributes: map[string][]adws.Value{
				"distinguishedName": tv("CN=Nested,CN=Users,DC=corp,DC=local"),
				"name":              tv("Nested"),
				"objectSid":         bv(t, "010500000000000515000000dcf4dc3b833d2b46828ba62852040000"),
			}}}, nil
		case "(objectCategory=computer)": // computer cache
			return nil, nil
		case "(&(objectCategory=group)(member=*))": // main
			return []*adws.Object{{Attributes: map[string][]adws.Value{
				"name": tv("Admins"),
				"member": mv(
					`CN=alice,CN=Users,DC=corp,DC=local`,
					`CN=Nested,CN=Users,DC=corp,DC=local`,
					`CN=Wagner\, Klaus,CN=Users,DC=corp,DC=local`,                   // escaped comma, not in cache
					`CN=ForeignUser,CN=ForeignSecurityPrincipals,DC=other,DC=local`, // cross-domain
				),
			}}}, nil
		}
		return nil, nil
	}}

	tbl, err := collect.New(q, "DC=corp,DC=local", collect.Config{}).GroupMembers()
	if err != nil {
		t.Fatal(err)
	}
	if len(tbl.Rows) != 4 {
		t.Fatalf("got %d rows, want 4", len(tbl.Rows))
	}

	// Row 0: alice (cache hit, user).
	rowEq(t, tbl, 0, map[string]string{
		"Group Name": "Admins", "Member UserName": "alice", "Member Name": "alice", "AccountType": "user",
	})
	// Row 1: Nested group (cache hit, group).
	rowEq(t, tbl, 1, map[string]string{
		"Member UserName": "Nested", "Member Name": "Nested", "AccountType": "group",
	})
	// Row 2: escaped-comma CN, cache miss (no fallback object) -> DN guess "user".
	rowEq(t, tbl, 2, map[string]string{
		"Member Name": "Wagner, Klaus", "AccountType": "user", "Member UserName": "",
	})
	// Row 3: cross-domain foreign principal.
	rowEq(t, tbl, 3, map[string]string{
		"Member Name": "ForeignUser",
		"Member SID":  "ForeignSecurityPrincipal:other.local",
		"AccountType": "foreignSecurityPrincipal",
	})
}

func rowEq(t *testing.T, tbl *collect.Table, r int, want map[string]string) {
	t.Helper()
	for h, w := range want {
		if got := cell(t, tbl, r, h); got != w {
			t.Errorf("row %d %s = %q, want %q", r, h, got, w)
		}
	}
}
