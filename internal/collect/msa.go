package collect

import (
	"strings"

	"adit/internal/addecode"
	"adit/internal/adws"
	"adit/internal/sd"
)

var msaAttributes = []string{
	"sAMAccountName", "name", "distinguishedName", "description",
	"userAccountControl", "pwdLastSet", "lastLogonTimestamp",
	"servicePrincipalName", "objectSid", "whenCreated", "whenChanged",
	"dNSHostName", "msDS-AllowedToDelegateTo",
}

// GMSA collects Group Managed Service Accounts, including who may retrieve each
// managed password (from msDS-GroupMSAMembership) and who can modify the account.
func (c *Collector) GMSA() (*Table, error) {
	attrs := append(append([]string{}, msaAttributes...),
		"msDS-ManagedPasswordInterval", "msDS-GroupMSAMembership", "nTSecurityDescriptor")
	objects, err := c.q.Query(c.baseDN, "(objectClass=msDS-GroupManagedServiceAccount)", attrs)
	if err != nil {
		return nil, err
	}
	t := &Table{Name: "gMSA", Headers: []string{
		"SAM Account Name", "Name", "Enabled", "Owner", "Description", "DNS Hostname", "SPNs",
		"Password Age (days)", "Password Rotation Interval (days)", "Logon Age (days)",
		"Delegation Services", "Allowed To Retrieve Password", "Write Permissions", "SID",
		"Password LastSet", "Last Logon Date", "whenCreated", "whenChanged", "Distinguished Name",
	}}

	for _, o := range objects {
		pwdAge, pwdOK, pwdSetStr := c.pwdAge(o)
		logonAge, logonOK, logonStr := c.logonAge(o)

		interval := int64(30)
		if v := text(o, "msDS-ManagedPasswordInterval"); v != "" {
			interval = intText(o, "msDS-ManagedPasswordInterval")
		}

		owner := "Unknown"
		var write []principal
		if descriptor := parseSDValue(o, "nTSecurityDescriptor"); descriptor != nil {
			if n := resolvePrincipal(descriptor.Owner); n != "" {
				owner = n
			}
			write = dangerousWritePrincipals(descriptor)
		}

		allowed := "Not readable"
		if membership := parseSDValue(o, "msDS-GroupMSAMembership"); membership != nil {
			if ps := msaMembershipPrincipals(membership); len(ps) > 0 {
				allowed = strings.Join(ps, ", ")
			}
		}

		var r row
		r.str(text(o, "sAMAccountName"))
		r.str(text(o, "name"))
		r.str(enabledStr(o))
		r.str(owner)
		r.str(text(o, "description"))
		r.str(text(o, "dNSHostName"))
		r.str(listText(o, "servicePrincipalName"))
		r.optInt(pwdAge, pwdOK)
		r.intv(interval)
		r.optInt(logonAge, logonOK)
		r.str(listText(o, "msDS-AllowedToDelegateTo"))
		r.str(allowed)
		r.str(joinPrincipalsOrNone(write))
		r.str(sidText(o, "objectSid"))
		r.str(pwdSetStr)
		r.str(logonStr)
		r.str(whenStr(o, "whenCreated"))
		r.str(whenStr(o, "whenChanged"))
		r.str(text(o, "distinguishedName"))
		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

// DMSA collects Delegated Managed Service Accounts (Windows Server 2025+) and
// flags the BadSuccessor escalation (a superseded account link).
func (c *Collector) DMSA() (*Table, error) {
	t := &Table{Name: "dMSA", Headers: []string{
		"SAM Account Name", "Name", "Enabled", "Description", "DNS Hostname", "SPNs",
		"Password Age (days)", "Logon Age (days)", "Delegation Services",
		"Superseded Account (BadSuccessor)", "dMSA State", "badSuccessor Vulnerable",
		"Risk Level", "SID", "Password LastSet", "Last Logon Date",
		"whenCreated", "whenChanged", "Distinguished Name",
	}}
	// dMSA requires the Windows Server 2025+ schema.
	if c.cfg.SchemaDN == "" {
		return t, nil
	}
	if ok, _ := c.queryFirst(c.cfg.SchemaDN, "(lDAPDisplayName=msDS-DelegatedManagedServiceAccount)", []string{"lDAPDisplayName"}); ok == nil {
		return t, nil
	}

	attrs := append(append([]string{}, msaAttributes...),
		"msDS-ManagedAccountPrecededByLink", "msDS-DelegatedMSAState")
	objects, err := c.q.Query(c.baseDN, "(objectClass=msDS-DelegatedManagedServiceAccount)", attrs)
	if err != nil {
		return nil, err
	}

	for _, o := range objects {
		pwdAge, pwdOK, pwdSetStr := c.pwdAge(o)
		logonAge, logonOK, logonStr := c.logonAge(o)
		superseded := text(o, "msDS-ManagedAccountPrecededByLink")
		badSuccessor := superseded != ""
		risk := "Low"
		if badSuccessor {
			risk = "CRITICAL"
		}

		var r row
		r.str(text(o, "sAMAccountName"))
		r.str(text(o, "name"))
		r.str(boolTrueFalse(addecode.ParseUAC(uint32(intText(o, "userAccountControl"))).Enabled))
		r.str(text(o, "description"))
		r.str(text(o, "dNSHostName"))
		r.str(listText(o, "servicePrincipalName"))
		r.optInt(pwdAge, pwdOK)
		r.optInt(logonAge, logonOK)
		r.str(listText(o, "msDS-AllowedToDelegateTo"))
		r.str(superseded)
		r.str(text(o, "msDS-DelegatedMSAState"))
		r.boolean(badSuccessor)
		r.str(risk)
		r.str(sidText(o, "objectSid"))
		r.str(pwdSetStr)
		r.str(logonStr)
		// The reference leaves these empty (it passes a raw string to its
		// datetime formatter); we render the real dates.
		r.str(whenStr(o, "whenCreated"))
		r.str(whenStr(o, "whenChanged"))
		r.str(text(o, "distinguishedName"))
		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

// parseSDValue parses a binary security-descriptor attribute, or returns nil.
func parseSDValue(o *adws.Object, attr string) *sd.SecurityDescriptor {
	v := o.Attributes[attr]
	if len(v) == 0 || !v[0].IsBinary {
		return nil
	}
	descriptor, err := sd.Parse(v[0].Binary)
	if err != nil {
		return nil
	}
	return descriptor
}

// msaMembershipPrincipals returns the principals allowed to retrieve a gMSA
// password (ALLOW ACEs in the msDS-GroupMSAMembership DACL).
func msaMembershipPrincipals(descriptor *sd.SecurityDescriptor) []string {
	if descriptor.DACL == nil {
		return nil
	}
	var out []string
	for _, ace := range descriptor.DACL.ACEs {
		if ace.Type == sd.AceTypeAccessAllowed {
			out = append(out, resolvePrincipal(ace.SID))
		}
	}
	return out
}

// joinPrincipalsOrNone joins principal names with ", ", or "None" if empty.
func joinPrincipalsOrNone(ps []principal) string {
	if len(ps) == 0 {
		return "None"
	}
	names := make([]string, len(ps))
	for i, p := range ps {
		names[i] = p.name
	}
	return strings.Join(names, ", ")
}
