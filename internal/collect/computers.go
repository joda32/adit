package collect

import (
	"strings"

	"adit/internal/addecode"
	"adit/internal/adws"
)

var computerAttributes = []string{
	"sAMAccountName", "name", "distinguishedName", "dNSHostName",
	"operatingSystem", "operatingSystemVersion", "operatingSystemServicePack",
	"operatingSystemHotfix", "userAccountControl", "pwdLastSet",
	"lastLogonTimestamp", "description", "primaryGroupID", "objectSid",
	"sIDHistory", "servicePrincipalName", "msDS-AllowedToDelegateTo",
	"msDS-SupportedEncryptionTypes", "whenCreated", "whenChanged",
}

// Computers collects computer objects, service accounts (users ending in $),
// and managed service accounts — the three filters the reference unions.
//
// The EOL-status and DNS-derived IP columns of the reference require the OS
// end-of-life database and the DNS collector respectively, and are omitted here
// until those land.
func (c *Collector) Computers() (*Table, error) {
	filters := []string{
		"(objectCategory=computer)",
		"(&(objectCategory=person)(objectClass=user)(sAMAccountName=*$))",
		"(objectClass=msDS-ManagedServiceAccount)",
	}
	if c.cfg.OnlyEnabled {
		filters[0] = "(&(objectCategory=computer)" + onlyEnabledClause() + ")"
		filters[1] = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=*$)" + onlyEnabledClause() + ")"
		filters[2] = "(&(objectClass=msDS-ManagedServiceAccount)" + onlyEnabledClause() + ")"
	}

	var objects []*adws.Object
	for _, f := range filters {
		part, err := c.q.Query(c.baseDN, f, computerAttributes)
		if err != nil {
			return nil, err
		}
		objects = append(objects, part...)
	}

	t := &Table{
		Name: "Computers",
		Headers: []string{
			"UserName", "Name", "DNSHostName", "Enabled", "Operating System",
			"Logon Age (days)", "Password Age (days)",
			thresholdHeader("Dormant", c.cfg.DormantDays), thresholdHeader("Password Age", c.cfg.PasswordAgeDays),
			"Delegation Type", "Delegation Protocol", "Delegation Services",
			"Primary Group ID", "SID", "SIDHistory", "Description",
			"Last Logon Date", "Password LastSet", "UserAccountControl",
			"whenCreated", "whenChanged", "Distinguished Name",
		},
	}

	for _, o := range objects {
		uac := addecode.ParseUAC(uint32(intText(o, "userAccountControl")))

		pwdSet, pwdOK := addecode.ParseFileTime(text(o, "pwdLastSet"))
		var pwdAgePresent, pwdOverAge bool
		var pwdAge int64
		pwdSetStr := ""
		if pwdOK && pwdSet.Year() != 1601 {
			pwdAge = daysBetween(c.cfg.Now, pwdSet)
			pwdAgePresent = true
			pwdOverAge = pwdAge > int64(c.cfg.PasswordAgeDays)
			pwdSetStr = addecode.FormatDateTime(pwdSet, true)
		}

		logon, logonOK := addecode.ParseFileTime(text(o, "lastLogonTimestamp"))
		var logonAgePresent, dormant bool
		var logonAge int64
		logonStr := ""
		if logonOK && logon.Year() != 1601 {
			logonAge = daysBetween(c.cfg.Now, logon)
			logonAgePresent = true
			dormant = logonAge > int64(c.cfg.DormantDays)
			logonStr = addecode.FormatDateTime(logon, true)
		}

		osFull := strings.TrimSpace(strings.Join(nonEmpty(
			text(o, "operatingSystem"),
			text(o, "operatingSystemServicePack"),
			text(o, "operatingSystemVersion"),
		), " "))

		delType, delProto, delSvc := delegation(o, uac)

		var r row
		r.str(text(o, "sAMAccountName"))
		r.str(text(o, "name"))
		r.str(text(o, "dNSHostName"))
		r.boolean(uac.Enabled)
		r.str(osFull)
		r.optInt(logonAge, logonAgePresent)
		r.optInt(pwdAge, pwdAgePresent)
		r.boolean(dormant)
		r.boolean(pwdOverAge)
		r.str(delType)
		r.str(delProto)
		r.str(delSvc)
		r.str(text(o, "primaryGroupID"))
		r.str(sidText(o, "objectSid"))
		r.str(sidListText(o, "sIDHistory"))
		r.str(text(o, "description"))
		r.str(logonStr)
		r.str(pwdSetStr)
		r.str(text(o, "userAccountControl"))
		r.str(addecode.FormatDateTime(addecode.GeneralizedTimeToTime(text(o, "whenCreated"))))
		r.str(addecode.FormatDateTime(addecode.GeneralizedTimeToTime(text(o, "whenChanged"))))
		r.str(text(o, "distinguishedName"))

		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

// nonEmpty returns the non-empty strings from the arguments, preserving order.
func nonEmpty(parts ...string) []string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return out
}
