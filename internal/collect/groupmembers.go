package collect

import (
	"strings"

	"adit/internal/adws"
)

// memberInfo is a resolved directory principal in the DN cache.
type memberInfo struct {
	username    string
	sid         string
	accountType string
}

// pgPrincipal is a user/computer carrying a primaryGroupID, used to expand
// primary-group membership (which is not stored in a group's member attribute).
type pgPrincipal struct {
	username       string
	sid            string
	dn             string
	primaryGroupID string
	accountType    string
}

// GroupMembers expands group memberships. It builds a DN→principal cache from
// bulk user/group/computer queries so most members resolve without a per-member
// round-trip; cross-domain (foreign) members are labelled without any lookup,
// and rare cache misses fall back to a single lookup on the member DN.
func (c *Collector) GroupMembers() (*Table, error) {
	cache, pgMembers, err := c.buildDNCache()
	if err != nil {
		return nil, err
	}
	baseDC := dcParts(c.baseDN)

	groups, err := c.q.Query(c.baseDN, "(&(objectCategory=group)(member=*))",
		[]string{"sAMAccountName", "name", "member", "objectSid"})
	if err != nil {
		return nil, err
	}

	t := &Table{Name: "GroupMembers", Headers: []string{
		"Group Name", "Member UserName", "Member Name", "Member SID", "AccountType",
	}}
	for _, g := range groups {
		groupName := text(g, "name")
		for _, m := range g.Attributes["member"] {
			dn := m.Text
			info := c.resolveMember(dn, baseDC, cache)
			var r row
			r.str(groupName)
			r.str(info.username)
			r.str(firstCN(dn))
			r.str(info.sid)
			r.str(info.accountType)
			t.Rows = append(t.Rows, r.cells)
		}
	}

	// Expand primary-group membership (primaryGroupID -> Domain Users / Domain
	// Computers / Domain Controllers, …), which is never listed in a group's
	// member attribute and so is missed by the member expansion above.
	groupNameBySID := map[string]string{}
	for _, info := range cache {
		if info.accountType == "group" && info.sid != "" {
			groupNameBySID[info.sid] = info.username
		}
	}
	for _, m := range pgMembers {
		if m.primaryGroupID == "" || m.sid == "" {
			continue
		}
		name, ok := groupNameBySID[domainSIDOf(m.sid)+"-"+m.primaryGroupID]
		if !ok {
			continue
		}
		var r row
		r.str(name)
		r.str(m.username)
		r.str(firstCN(m.dn))
		r.str(m.sid)
		r.str(m.accountType + " (primary group)")
		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

// buildDNCache bulk-loads users, groups and computers into a lower(DN)->info
// map, and returns the users/computers carrying a primaryGroupID (in query
// order) so primary-group membership can be expanded deterministically.
func (c *Collector) buildDNCache() (map[string]memberInfo, []pgPrincipal, error) {
	cache := map[string]memberInfo{}
	var pg []pgPrincipal

	users, err := c.q.Query(c.baseDN, "(&(objectCategory=person)(objectClass=user))",
		[]string{"distinguishedName", "sAMAccountName", "objectSid", "primaryGroupID"})
	if err != nil {
		return nil, nil, err
	}
	for _, o := range users {
		dn, sam, sid := text(o, "distinguishedName"), text(o, "sAMAccountName"), sidText(o, "objectSid")
		cache[strings.ToLower(dn)] = memberInfo{username: sam, sid: sid, accountType: "user"}
		pg = append(pg, pgPrincipal{username: sam, sid: sid, dn: dn,
			primaryGroupID: text(o, "primaryGroupID"), accountType: "user"})
	}

	groups, err := c.q.Query(c.baseDN, "(objectCategory=group)",
		[]string{"distinguishedName", "name", "objectSid"})
	if err != nil {
		return nil, nil, err
	}
	for _, o := range groups {
		cache[strings.ToLower(text(o, "distinguishedName"))] = memberInfo{
			username: text(o, "name"), sid: sidText(o, "objectSid"), accountType: "group",
		}
	}

	computers, err := c.q.Query(c.baseDN, "(objectCategory=computer)",
		[]string{"distinguishedName", "sAMAccountName", "objectSid", "primaryGroupID"})
	if err != nil {
		return nil, nil, err
	}
	for _, o := range computers {
		dn, sam, sid := text(o, "distinguishedName"), text(o, "sAMAccountName"), sidText(o, "objectSid")
		cache[strings.ToLower(dn)] = memberInfo{username: sam, sid: sid, accountType: "computer"}
		pg = append(pg, pgPrincipal{username: sam, sid: sid, dn: dn,
			primaryGroupID: text(o, "primaryGroupID"), accountType: "computer"})
	}
	return cache, pg, nil
}

// domainSIDOf returns the domain portion of a SID (everything before the last
// "-", i.e. dropping the RID).
func domainSIDOf(sid string) string {
	if i := strings.LastIndex(sid, "-"); i >= 0 {
		return sid[:i]
	}
	return sid
}

// resolveMember resolves one member DN to a principal.
func (c *Collector) resolveMember(dn string, baseDC []string, cache map[string]memberInfo) memberInfo {
	memberDC := dcParts(dn)
	// Cross-domain member: label without any lookup.
	if len(memberDC) > 0 && !equalStrings(memberDC, baseDC) {
		return memberInfo{
			sid:         "ForeignSecurityPrincipal:" + strings.Join(memberDC, "."),
			accountType: foreignTypeFromDN(dn),
		}
	}
	// Same domain: cache hit is O(1).
	if info, ok := cache[strings.ToLower(dn)]; ok {
		return info
	}
	// Miss: fall back to a single lookup, then guess from the DN structure.
	info := memberInfo{}
	if o, _ := c.queryFirst(dn, "(objectClass=*)", []string{"sAMAccountName", "objectSid", "objectClass"}); o != nil {
		info.username = text(o, "sAMAccountName")
		info.sid = sidText(o, "objectSid")
		info.accountType = accountTypeFromClasses(o)
	}
	if info.accountType == "" {
		info.accountType = missTypeFromDN(dn)
	}
	return info
}

// accountTypeFromClasses maps objectClass values to an account type.
func accountTypeFromClasses(o *adws.Object) string {
	classes := map[string]bool{}
	for _, v := range o.Attributes["objectClass"] {
		classes[strings.ToLower(v.Text)] = true
	}
	switch {
	case classes["computer"]:
		return "computer"
	case classes["user"]:
		return "user"
	case classes["group"]:
		return "group"
	case classes["msds-managedserviceaccount"] || classes["msds-groupmanagedserviceaccount"]:
		return "msa"
	case classes["foreignsecurityprincipal"]:
		return "foreignSecurityPrincipal"
	default:
		return "unknown"
	}
}

// foreignTypeFromDN guesses the type of a cross-domain member from its DN.
func foreignTypeFromDN(dn string) string {
	switch {
	case containsCI(dn, ",CN=Users,") || containsCI(dn, ",OU=Users,"):
		return "user"
	case containsCI(dn, ",CN=Computers,") || containsCI(dn, ",OU=Computers,"):
		return "computer"
	case containsCI(dn, ",CN=Builtin,") || containsCI(dn, "CN=Groups"):
		return "group"
	default:
		return "foreignSecurityPrincipal"
	}
}

// missTypeFromDN guesses the type of a cache-miss same-domain member from its DN.
func missTypeFromDN(dn string) string {
	switch {
	case containsCI(dn, ",CN=ForeignSecurityPrincipals,"):
		return "foreignSecurityPrincipal"
	case containsCI(dn, ",CN=Users,") || containsCI(dn, ",OU=Users,"):
		return "user"
	case containsCI(dn, ",CN=Computers,") || containsCI(dn, ",OU=Computers,"):
		return "computer"
	case containsCI(dn, ",CN=Builtin,") || containsCI(dn, "CN=Groups"):
		return "group"
	default:
		return "unknown"
	}
}

// firstCN extracts the value of the first CN= RDN, unescaping LDAP backslash
// escapes (e.g. "CN=Wagner\, Klaus,..." -> "Wagner, Klaus"). Returns the DN
// unchanged if it has no CN.
func firstCN(dn string) string {
	i := strings.Index(dn, "CN=")
	if i < 0 {
		return dn
	}
	s := dn[i+3:]
	var b strings.Builder
	for j := 0; j < len(s); j++ {
		if s[j] == '\\' && j+1 < len(s) {
			b.WriteByte(s[j+1])
			j++
			continue
		}
		if s[j] == ',' {
			break
		}
		b.WriteByte(s[j])
	}
	return b.String()
}

// dcParts returns the lower-cased DC= components of a DN.
func dcParts(dn string) []string {
	var parts []string
	for _, p := range strings.Split(dn, ",") {
		p = strings.TrimSpace(p)
		if len(p) >= 3 && strings.EqualFold(p[:3], "DC=") {
			parts = append(parts, strings.ToLower(p[3:]))
		}
	}
	return parts
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsCI(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
