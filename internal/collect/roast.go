package collect

import (
	"fmt"
	"strconv"
	"strings"

	"adit/internal/addecode"
)

// weakRC4 reports whether the account relies on RC4 while lacking AES256 — the
// "easier to crack" condition the reference flags for roastable accounts.
func weakRC4(k addecode.KerbEnc) bool {
	rc4 := k.RC4 == "Supported" || k.RC4 == "Default"
	aes := k.AES256 == "Supported" || k.AES256 == "Default"
	return rc4 && !aes
}

func optDays(age int64, present bool) string {
	if present {
		return strconv.FormatInt(age, 10)
	}
	return "Unknown"
}

// Kerberoastable collects user accounts with SPNs (excluding krbtgt), with a
// risk assessment.
func (c *Collector) Kerberoastable() (*Table, error) {
	filter := "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))"
	if c.cfg.OnlyEnabled {
		filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt))" + onlyEnabledClause() + ")"
	}
	objects, err := c.q.Query(c.baseDN, filter,
		[]string{"sAMAccountName", "name", "distinguishedName", "userAccountControl",
			"pwdLastSet", "lastLogonTimestamp", "adminCount", "memberOf",
			"servicePrincipalName", "msDS-SupportedEncryptionTypes", "objectSid",
			"description", "info", "whenCreated"})
	if err != nil {
		return nil, err
	}
	t := &Table{Name: "Kerberoastable", Headers: []string{
		"SAM Account Name", "Name", "Enabled", "Risk Level", "Risk Factors", "SPN Count",
		"Service Principal Names", "AdminCount", "Kerberos RC4", "Kerberos AES-128",
		"Kerberos AES-256", "Password Age (days)", "Last Logon", "Logon Age (days)",
		"Member Of", "SID", "Description", "Info", "Created", "Distinguished Name",
	}}
	for _, o := range objects {
		kerb := addecode.ParseKerbEnc(text(o, "msDS-SupportedEncryptionTypes"))
		pwdAge, pwdOK, _ := c.pwdAge(o)
		logonAge, logonOK, logonStr := c.logonAge(o)
		privileged := text(o, "adminCount") == "1"

		riskLevel := "Medium"
		factors := []string{"Kerberoastable (user account with SPN)"}
		if privileged {
			riskLevel = "CRITICAL"
			factors = append(factors, "Privileged account (AdminCount=1)")
		}
		if weakRC4(kerb) {
			if riskLevel == "Medium" {
				riskLevel = "HIGH"
			}
			factors = append(factors, "Uses weak RC4 encryption (easier to crack)")
		}
		if pwdOK && pwdAge > 365 {
			factors = append(factors, fmt.Sprintf("Old password (%d days)", pwdAge))
		} else if pwdOK && pwdAge < 90 {
			factors = append(factors, "Password recently changed")
		}

		spns := o.Attributes["servicePrincipalName"]
		var spnTexts []string
		for _, s := range spns {
			spnTexts = append(spnTexts, s.Text)
		}
		spnStr := strings.Join(first3(spnTexts), "; ")
		if len(spns) > 3 {
			spnStr += fmt.Sprintf(" ... (%d total)", len(spns))
		}

		var r row
		r.str(text(o, "sAMAccountName"))
		r.str(text(o, "name"))
		r.str(enabledStr(o))
		r.str(riskLevel)
		r.str(strings.Join(factors, "; "))
		r.intv(int64(len(spns)))
		r.str(spnStr)
		r.str(text(o, "adminCount"))
		r.str(kerb.RC4)
		r.str(kerb.AES128)
		r.str(kerb.AES256)
		r.str(optDays(pwdAge, pwdOK))
		r.str(orNever(logonStr))
		r.str(optDays(logonAge, logonOK))
		r.str(orNone(strings.Join(first5(groupsOf(o)), "; ")))
		r.str(sidText(o, "objectSid"))
		r.str(text(o, "description"))
		r.str(text(o, "info"))
		r.str(whenStr(o, "whenCreated"))
		r.str(text(o, "distinguishedName"))
		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

// ASREPRoastable collects accounts with DONT_REQ_PREAUTH set.
func (c *Collector) ASREPRoastable() (*Table, error) {
	filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
	if c.cfg.OnlyEnabled {
		filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)" + onlyEnabledClause() + ")"
	}
	objects, err := c.q.Query(c.baseDN, filter,
		[]string{"sAMAccountName", "name", "distinguishedName", "userAccountControl",
			"pwdLastSet", "lastLogonTimestamp", "adminCount", "memberOf",
			"servicePrincipalName", "objectSid", "description", "info", "whenCreated"})
	if err != nil {
		return nil, err
	}
	t := &Table{Name: "ASREPRoastable", Headers: []string{
		"SAM Account Name", "Name", "Enabled", "Risk Level", "Risk Factors", "AdminCount",
		"Has SPN", "Password Age (days)", "Last Logon", "Logon Age (days)", "Member Of",
		"SID", "Description", "Info", "Created", "Distinguished Name",
	}}
	for _, o := range objects {
		pwdAge, pwdOK, _ := c.pwdAge(o)
		logonAge, logonOK, logonStr := c.logonAge(o)
		privileged := text(o, "adminCount") == "1"
		hasSPN := has(o, "servicePrincipalName")

		riskLevel := "Medium"
		factors := []string{"AS-REP Roasting vulnerable (no pre-authentication required)"}
		if privileged {
			riskLevel = "CRITICAL"
			factors = append(factors, "Privileged account (AdminCount=1)")
		} else if hasSPN {
			riskLevel = "HIGH"
			factors = append(factors, "Has SPN (can also be Kerberoasted)")
		}
		if pwdOK && pwdAge < 90 {
			factors = append(factors, "Password recently changed")
		}

		var r row
		r.str(text(o, "sAMAccountName"))
		r.str(text(o, "name"))
		r.str(enabledStr(o))
		r.str(riskLevel)
		r.str(strings.Join(factors, "; "))
		r.str(text(o, "adminCount"))
		r.str(yesNo(hasSPN))
		r.str(optDays(pwdAge, pwdOK))
		r.str(orNever(logonStr))
		r.str(optDays(logonAge, logonOK))
		r.str(orNone(strings.Join(first5(groupsOf(o)), "; ")))
		r.str(sidText(o, "objectSid"))
		r.str(text(o, "description"))
		r.str(text(o, "info"))
		r.str(whenStr(o, "whenCreated"))
		r.str(text(o, "distinguishedName"))
		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

// KRBTGT collects the krbtgt account with a Golden-Ticket risk assessment.
func (c *Collector) KRBTGT() (*Table, error) {
	objects, err := c.q.Query(c.baseDN, "(&(objectCategory=person)(objectClass=user)(sAMAccountName=krbtgt))",
		[]string{"sAMAccountName", "name", "distinguishedName", "pwdLastSet",
			"msDS-SupportedEncryptionTypes", "userAccountControl", "whenCreated",
			"whenChanged", "objectSid", "description"})
	if err != nil {
		return nil, err
	}
	t := &Table{Name: "krbtgt", Headers: []string{
		"Account Name", "Distinguished Name", "Password Last Set", "Password Age (days)",
		"Risk Level", "Risk Factors", "Kerberos RC4", "Kerberos AES-128", "Kerberos AES-256",
		"SID", "Created", "Last Modified", "Description",
	}}
	for _, o := range objects {
		kerb := addecode.ParseKerbEnc(text(o, "msDS-SupportedEncryptionTypes"))
		pwdAge, pwdOK, pwdSetStr := c.pwdAge(o)

		riskLevel := "Low"
		var factors []string
		if pwdOK {
			switch {
			case pwdAge > 365:
				riskLevel = "CRITICAL"
				factors = append(factors, fmt.Sprintf("krbtgt password not changed in %d days (Golden Ticket risk)", pwdAge))
			case pwdAge > 180:
				riskLevel = "HIGH"
				factors = append(factors, fmt.Sprintf("krbtgt password should be changed (last changed %d days ago)", pwdAge))
			default:
				factors = append(factors, fmt.Sprintf("Password changed %d days ago (acceptable)", pwdAge))
			}
		}
		if weakRC4(kerb) {
			factors = append(factors, "Using weak RC4 encryption (AES256 recommended)")
			if riskLevel == "Low" {
				riskLevel = "Medium"
			}
		}

		var r row
		r.str(text(o, "sAMAccountName"))
		r.str(text(o, "distinguishedName"))
		r.str(orNever(pwdSetStr))
		r.str(optDays(pwdAge, pwdOK))
		r.str(riskLevel)
		r.str(orNone(strings.Join(factors, "; ")))
		r.str(kerb.RC4)
		r.str(kerb.AES128)
		r.str(kerb.AES256)
		r.str(sidText(o, "objectSid"))
		r.str(whenStr(o, "whenCreated"))
		r.str(whenStr(o, "whenChanged"))
		r.str(text(o, "description"))
		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

func first3(s []string) []string { return firstN(s, 3) }
func first5(s []string) []string { return firstN(s, 5) }
func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func orNever(s string) string {
	if s == "" {
		return "Never"
	}
	return s
}
func orNone(s string) string {
	if s == "" {
		return "None"
	}
	return s
}
func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}
