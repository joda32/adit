package collect

import (
	"adit/internal/addecode"
	"adit/internal/adws"
	"adit/internal/sd"
)

var userAttributes = []string{
	"sAMAccountName", "name", "distinguishedName", "canonicalName",
	"userAccountControl", "pwdLastSet", "lastLogonTimestamp",
	"accountExpires", "adminCount", "description", "title",
	"department", "company", "manager", "mail", "mobile",
	"homeDirectory", "profilePath", "scriptPath", "memberOf",
	"primaryGroupID", "objectSid", "sIDHistory", "servicePrincipalName",
	"msDS-AllowedToDelegateTo", "msDS-SupportedEncryptionTypes",
	"givenName", "sn", "middleName", "c", "info", "userWorkstations",
	"whenCreated", "whenChanged", "ntSecurityDescriptor",
}

// Users collects user objects (objectCategory=person, objectClass=user).
func (c *Collector) Users() (*Table, error) {
	filter := "(&(objectCategory=person)(objectClass=user))"
	if c.cfg.OnlyEnabled {
		filter = "(&(objectCategory=person)(objectClass=user)" + onlyEnabledClause() + ")"
	}
	objects, err := c.q.Query(c.baseDN, filter, userAttributes)
	if err != nil {
		return nil, err
	}

	t := &Table{
		Name: "Users",
		Headers: []string{
			"UserName", "Name", "Enabled", "Must Change Password at Logon",
			"Cannot Change Password", "Password Never Expires", "Reversible Password Encryption",
			"Smartcard Logon Required", "Delegation Permitted", "Kerberos DES Only",
			"Kerberos RC4", "Kerberos AES-128bit", "Kerberos AES-256bit", "Does Not Require Pre Auth",
			"Never Logged in", "Logon Age (days)", "Password Age (days)",
			thresholdHeader("Dormant", c.cfg.DormantDays), thresholdHeader("Password Age", c.cfg.PasswordAgeDays),
			"Account Locked Out", "Password Expired", "Password Not Required",
			"Delegation Type", "Delegation Protocol", "Delegation Services",
			"Logon Workstations", "AdminCount", "Primary GroupID", "SID", "SIDHistory", "HasSPN",
			"Description", "Title", "Department", "Company", "Manager", "Info",
			"Last Logon Date", "Password LastSet", "Account Expiration Date", "Account Expiration (days)",
			"Mobile", "Email", "HomeDirectory", "ProfilePath", "ScriptPath", "UserAccountControl",
			"First Name", "Middle Name", "Last Name", "Country", "whenCreated", "whenChanged",
			"DistinguishedName", "CanonicalName",
		},
	}

	for _, o := range objects {
		uac := addecode.ParseUAC(uint32(intText(o, "userAccountControl")))
		kerb := addecode.ParseKerbEnc(text(o, "msDS-SupportedEncryptionTypes"))

		// Password last set.
		pwdSet, pwdOK := addecode.ParseFileTime(text(o, "pwdLastSet"))
		mustChange := !pwdOK || pwdSet.Year() == 1601
		var pwdAgePresent, pwdOverAge bool
		var pwdAge int64
		pwdSetStr := ""
		if pwdOK && pwdSet.Year() != 1601 {
			pwdAge = daysBetween(c.cfg.Now, pwdSet)
			pwdAgePresent = true
			pwdOverAge = pwdAge > int64(c.cfg.PasswordAgeDays)
			pwdSetStr = addecode.FormatDateTime(pwdSet, true)
		}

		// Last logon.
		logon, logonOK := addecode.ParseFileTime(text(o, "lastLogonTimestamp"))
		neverLoggedIn := !logonOK || logon.Year() == 1601
		var logonAgePresent, dormant bool
		var logonAge int64
		logonStr := ""
		if logonOK && logon.Year() != 1601 {
			logonAge = daysBetween(c.cfg.Now, logon)
			logonAgePresent = true
			dormant = logonAge > int64(c.cfg.DormantDays)
			logonStr = addecode.FormatDateTime(logon, true)
		}

		// Account expiration.
		exp, expOK := addecode.ParseFileTime(text(o, "accountExpires"))
		expStr := ""
		var expDays int64
		if expOK {
			expStr = addecode.FormatDateTime(exp, true)
			expDays = daysBetween(exp, c.cfg.Now) // days until expiry
		}

		// Cannot change password: prefer the DACL check, fall back to the UAC flag.
		cannotChange := uac.PasswordCantChange || cannotChangePasswordACL(o)

		// Delegation.
		delType, delProto, delSvc := delegation(o, uac)

		var r row
		r.str(text(o, "sAMAccountName"))
		r.str(text(o, "name"))
		r.boolean(uac.Enabled)
		r.boolean(mustChange)
		r.boolean(cannotChange)
		r.boolean(uac.PasswordNeverExpires)
		r.boolean(uac.ReversibleEncryption)
		r.boolean(uac.SmartcardRequired)
		r.boolean(!uac.NotDelegated)
		r.boolean(uac.UseDESKeyOnly)
		r.str(kerb.RC4)
		r.str(kerb.AES128)
		r.str(kerb.AES256)
		r.boolean(uac.DoesNotRequirePreAuth)
		r.boolean(neverLoggedIn)
		r.optInt(logonAge, logonAgePresent)
		r.optInt(pwdAge, pwdAgePresent)
		r.boolean(dormant)
		r.boolean(pwdOverAge)
		r.boolean(uac.AccountLockedOut)
		r.boolean(uac.PasswordExpired)
		r.boolean(uac.PasswordNotRequired)
		r.str(delType)
		r.str(delProto)
		r.str(delSvc)
		r.str(text(o, "userWorkstations"))
		r.str(text(o, "adminCount"))
		r.str(text(o, "primaryGroupID"))
		r.str(sidText(o, "objectSid"))
		r.str(sidListText(o, "sIDHistory"))
		r.boolean(has(o, "servicePrincipalName"))
		r.str(text(o, "description"))
		r.str(text(o, "title"))
		r.str(text(o, "department"))
		r.str(text(o, "company"))
		r.str(text(o, "manager"))
		r.str(text(o, "info"))
		r.str(logonStr)
		r.str(pwdSetStr)
		r.str(expStr)
		r.optInt(expDays, expOK)
		r.str(text(o, "mobile"))
		r.str(text(o, "mail"))
		r.str(text(o, "homeDirectory"))
		r.str(text(o, "profilePath"))
		r.str(text(o, "scriptPath"))
		r.str(text(o, "userAccountControl"))
		r.str(text(o, "givenName"))
		r.str(text(o, "middleName"))
		r.str(text(o, "sn"))
		r.str(text(o, "c"))
		r.str(addecode.FormatDateTime(addecode.GeneralizedTimeToTime(text(o, "whenCreated"))))
		r.str(addecode.FormatDateTime(addecode.GeneralizedTimeToTime(text(o, "whenChanged"))))
		r.str(text(o, "distinguishedName"))
		r.str(text(o, "canonicalName"))

		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

// cannotChangePasswordACL parses the ntSecurityDescriptor and reports whether
// the DACL denies the Change-Password right to SELF or Everyone.
func cannotChangePasswordACL(o *adws.Object) bool {
	vs := o.Attributes["ntSecurityDescriptor"]
	if len(vs) == 0 || !vs[0].IsBinary {
		return false
	}
	descriptor, err := sd.Parse(vs[0].Binary)
	if err != nil {
		return false
	}
	return descriptor.CannotChangePassword()
}

// delegation derives the delegation type/protocol/services columns shared by
// users and computers.
func delegation(o *adws.Object, uac addecode.UAC) (delType, delProto, delSvc string) {
	if uac.TrustedForDelegation {
		delType = "Unconstrained"
		delSvc = "Any"
	}
	if allowed := listText(o, "msDS-AllowedToDelegateTo"); allowed != "" {
		delType = "Constrained"
		delSvc = allowed
	}
	if uac.TrustedToAuthForDelegation {
		delProto = "Any"
	} else if delType != "" {
		delProto = "Kerberos"
	}
	return delType, delProto, delSvc
}
