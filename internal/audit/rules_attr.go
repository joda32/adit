package audit

import (
	"strconv"
	"strings"
	"time"

	"adit/internal/addecode"
	"adit/internal/adws"
	"adit/internal/sd"
)

// Attribute-based quick-win rules: everything derivable from the object
// attributes already loaded, with no ACL parsing and no new transport.

func init() {
	addChecks(
		// --- Domain-wide policy ---
		check{
			ID: "AD-DOM-005", Title: "Machine Account Quota allows self-service computer join",
			Category: "Domain", Severity: Medium,
			Description: "ms-DS-MachineAccountQuota is greater than zero, so any authenticated user can join computers to the domain.",
			Risk:        "Attackers can create machine accounts to enable RBCD, shadow-credential and other escalation attacks.",
			Remediation: "Set ms-DS-MachineAccountQuota to 0 and delegate machine creation to a dedicated group.",
			Fn:          (*Snapshot).ruleMachineAccountQuota,
		},
		check{
			ID: "AD-DOM-008", Title: "Reversible password encryption enabled domain-wide",
			Category: "Domain", Severity: High,
			Description: "The domain password policy stores passwords using reversible encryption.",
			Risk:        "Passwords can be recovered in clear text from the directory.",
			Remediation: "Disable reversible encryption in the Default Domain Policy and reset affected passwords.",
			Fn:          (*Snapshot).ruleReversibleDomain,
		},
		check{
			ID: "AD-KRB-001", Title: "krbtgt password is stale",
			Category: "Kerberos", Severity: High,
			Description: "The krbtgt account password has not been rotated within the recommended interval.",
			Risk:        "A leaked krbtgt hash enables long-lived golden tickets; stale passwords widen that window.",
			Remediation: "Rotate the krbtgt password twice (with replication in between) on a regular schedule.",
			Fn:          (*Snapshot).ruleKrbtgtAge,
		},

		// --- User accounts ---
		check{
			ID: "AD-USR-001", Title: "Kerberos pre-authentication disabled (AS-REP roastable)",
			Category: "User", Severity: High,
			Description: "The account does not require Kerberos pre-authentication.",
			Risk:        "An attacker can request an AS-REP and crack the account password offline.",
			Remediation: "Enable Kerberos pre-authentication (clear DONT_REQ_PREAUTH) on the account.",
			Fn:          (*Snapshot).ruleASREPRoast,
		},
		check{
			ID: "AD-USR-002", Title: "Service account is Kerberoastable",
			Category: "User", Severity: Medium,
			Description: "An enabled user account has a servicePrincipalName and is therefore Kerberoastable.",
			Risk:        "An attacker can request a service ticket and crack the account password offline.",
			Remediation: "Use group-managed service accounts (gMSA) or enforce long, random passwords with AES.",
			Fn:          (*Snapshot).ruleKerberoastable,
		},
		check{
			ID: "AD-USR-005", Title: "Account has password-not-required flag",
			Category: "User", Severity: Medium,
			Description: "The account is configured with PASSWD_NOTREQD, allowing an empty password.",
			Risk:        "The account may have a blank or trivially short password.",
			Remediation: "Clear the PASSWD_NOTREQD flag and enforce the domain password policy.",
			Fn:          (*Snapshot).rulePasswordNotRequired,
		},
		check{
			ID: "AD-USR-006", Title: "Privileged account password never expires",
			Category: "User", Severity: Medium,
			Description: "A privileged account is set so its password never expires.",
			Risk:        "Long-lived static credentials on privileged accounts increase compromise impact.",
			Remediation: "Remove DONT_EXPIRE_PASSWORD and rotate privileged credentials regularly.",
			Fn:          (*Snapshot).rulePrivPwdNeverExpires,
		},
		check{
			ID: "AD-USR-009", Title: "Account uses DES encryption only",
			Category: "User", Severity: High,
			Description: "The account is configured to use DES keys only.",
			Risk:        "DES is cryptographically broken and trivially crackable.",
			Remediation: "Clear USE_DES_KEY_ONLY and require AES encryption types.",
			Fn:          (*Snapshot).ruleDESOnly,
		},
		check{
			ID: "AD-USR-011", Title: "Privileged account has a stale password",
			Category: "User", Severity: Medium,
			Description: "A privileged account's password is older than the recommended maximum age.",
			Risk:        "Old privileged credentials are more likely to have been captured or reused.",
			Remediation: "Rotate the privileged account password and enforce a maximum age.",
			Fn:          (*Snapshot).rulePrivStalePassword,
		},
		check{
			ID: "AD-KCL-001", Title: "Key Credential (shadow credential) on a privileged account",
			Category: "User", Severity: High,
			Description: "A privileged account has a populated msDS-KeyCredentialLink.",
			Risk:        "An attacker-planted key credential enables certificate-based impersonation of the account.",
			Remediation: "Verify the key credential is legitimate; remove unexpected entries.",
			Fn:          (*Snapshot).ruleKeyCredentialLink,
		},

		// --- Computers ---
		check{
			ID: "AD-CMP-006", Title: "Unconstrained delegation enabled",
			Category: "Computer", Severity: High,
			Description: "A computer (non-DC) is trusted for unconstrained Kerberos delegation.",
			Risk:        "Any user authenticating to the host leaks a forwardable TGT, enabling impersonation.",
			Remediation: "Replace unconstrained delegation with constrained or resource-based delegation.",
			Fn:          (*Snapshot).ruleUnconstrainedDelegation,
		},
		check{
			ID: "AD-CMP-008", Title: "Resource-based constrained delegation configured",
			Category: "Computer", Severity: Medium,
			Description: "A computer has msDS-AllowedToActOnBehalfOfOtherIdentity populated.",
			Risk:        "If the referenced principal is attacker-controlled, it enables impersonation to the host.",
			Remediation: "Confirm the delegating principals are approved; remove unexpected RBCD entries.",
			Fn:          (*Snapshot).ruleRBCD,
		},
		check{
			ID: "AD-CMP-011", Title: "Stale computer account",
			Category: "Computer", Severity: Low,
			Description: "An enabled computer account has not authenticated within the stale threshold.",
			Risk:        "Dormant accounts expand the attack surface and may be reused.",
			Remediation: "Disable or remove computer accounts that are no longer in use.",
			Fn:          (*Snapshot).ruleStaleComputer,
		},
		check{
			ID: "AD-CMP-012", Title: "Legacy / unsupported operating system",
			Category: "Computer", Severity: Medium,
			Description: "An enabled computer runs an operating system that is no longer supported.",
			Risk:        "Unsupported systems no longer receive security updates.",
			Remediation: "Decommission or isolate legacy systems and upgrade to a supported OS.",
			Fn:          (*Snapshot).ruleLegacyOS,
		},

		// --- Groups / membership ---
		check{
			ID: "AD-GRP-009", Title: "Foreign security principal in a privileged group",
			Category: "Group", Severity: Medium,
			Description: "A privileged group contains a foreign security principal (member from another domain/forest).",
			Risk:        "Cross-domain privileged membership can bypass forest trust boundaries.",
			Remediation: "Review and remove unexpected foreign members from privileged groups.",
			Fn:          (*Snapshot).ruleForeignPrivMember,
		},
		check{
			ID: "AD-GRP-020", Title: "Privileged membership via primaryGroupID",
			Category: "Group", Severity: Medium,
			Description: "An account's primaryGroupID grants privileged group membership that is hidden from the group's member list.",
			Risk:        "Primary-group membership is easily overlooked during privileged-access reviews.",
			Remediation: "Reset primaryGroupID to Domain Users (513) and manage membership explicitly.",
			Fn:          (*Snapshot).rulePrimaryGroupID,
		},

		// --- Trusts ---
		check{
			ID: "AD-TRU-001", Title: "Trust without SID filtering (quarantine disabled)",
			Category: "Trust", Severity: High,
			Description: "A domain trust does not have SID filtering / quarantine enabled.",
			Risk:        "SID history injection across the trust can escalate to privileged access.",
			Remediation: "Enable SID filtering (quarantine) on the trust unless explicitly required.",
			Fn:          (*Snapshot).ruleTrustSIDFilter,
		},
		check{
			ID: "AD-TRU-003", Title: "Trust with SID history enabled",
			Category: "Trust", Severity: Medium,
			Description: "A domain trust has the SID history attribute enabled.",
			Risk:        "SID history over a trust can be abused to inherit privileged SIDs.",
			Remediation: "Disable SID history on the trust unless there is a migration requirement.",
			Fn:          (*Snapshot).ruleTrustSIDHistory,
		},

		// --- DNS ---
		check{
			ID: "AD-DNS-003", Title: "WPAD record present or spoofable",
			Category: "DNS", Severity: Medium,
			Description: "A WPAD DNS record exists (or the name is unprotected), enabling proxy auto-config abuse.",
			Risk:        "WPAD spoofing enables man-in-the-middle and credential relay attacks.",
			Remediation: "Block wpad via the DNS global query block list unless explicitly required.",
			Fn:          (*Snapshot).ruleWPAD,
		},
		check{
			ID: "AD-DNS-004", Title: "ISATAP record present",
			Category: "DNS", Severity: Low,
			Description: "An ISATAP DNS record exists.",
			Risk:        "ISATAP name resolution can be abused for tunnelling and relay.",
			Remediation: "Remove ISATAP from the DNS global query block list exclusions unless required.",
			Fn:          (*Snapshot).ruleISATAP,
		},

		// --- Integrity / SID history ---
		check{
			ID: "AD-INT-005", Title: "SID history contains a privileged SID",
			Category: "Integrity", Severity: High,
			Description: "An account's sIDHistory includes a privileged SID.",
			Risk:        "Privileged SID history injection grants hidden privileged access.",
			Remediation: "Remove privileged SIDs from sIDHistory after verifying they are not needed.",
			Fn:          (*Snapshot).ruleSIDHistoryPrivileged,
		},
	)
}

// --- Domain ---

func (s *Snapshot) ruleMachineAccountQuota() []Finding {
	q := intOf(s.Domain, "ms-DS-MachineAccountQuota")
	if q <= 0 || s.Domain == nil {
		return nil
	}
	return []Finding{finding(
		Affected{DistinguishedName: txt(s.Domain, "distinguishedName")},
		map[string]string{"ms-DS-MachineAccountQuota": strconv.FormatInt(q, 10)})}
}

// pwdProperties bit for reversible encryption (DOMAIN_PASSWORD_STORE_CLEARTEXT).
const pwdPropStoreCleartext = 0x10

func (s *Snapshot) ruleReversibleDomain() []Finding {
	p := intOf(s.Domain, "pwdProperties")
	if p&pwdPropStoreCleartext == 0 {
		return nil
	}
	return []Finding{finding(
		Affected{DistinguishedName: txt(s.Domain, "distinguishedName")},
		map[string]string{"pwdProperties": strconv.FormatInt(p, 10)})}
}

func (s *Snapshot) ruleKrbtgtAge() []Finding {
	for _, u := range s.Users {
		if !strings.EqualFold(txt(u, "sAMAccountName"), "krbtgt") {
			continue
		}
		age, ok := s.pwdAgeDays(u)
		if !ok || age <= int64(s.Cfg.KrbtgtMaxAgeDays) {
			return nil
		}
		return []Finding{finding(affectedOf(u),
			map[string]string{"password_age_days": strconv.FormatInt(age, 10),
				"threshold_days": strconv.Itoa(s.Cfg.KrbtgtMaxAgeDays)})}
	}
	return nil
}

// --- Users ---

func (s *Snapshot) ruleASREPRoast() (out []Finding) {
	for _, u := range s.Users {
		uac := uacOf(u)
		if uac.Enabled && uac.DoesNotRequirePreAuth {
			out = append(out, finding(affectedOf(u),
				map[string]string{"userAccountControl": txt(u, "userAccountControl")}))
		}
	}
	return out
}

func (s *Snapshot) ruleKerberoastable() (out []Finding) {
	for _, u := range s.Users {
		if !uacOf(u).Enabled || !has(u, "servicePrincipalName") {
			continue
		}
		if strings.EqualFold(txt(u, "sAMAccountName"), "krbtgt") {
			continue
		}
		sev := Medium
		if isPrivilegedUser(u) {
			sev = High
		}
		out = append(out, Finding{
			Severity: sev,
			Affected: []Affected{affectedOf(u)},
			Evidence: map[string]string{"servicePrincipalName": strings.Join(textVals(u, "servicePrincipalName"), "; ")},
		})
	}
	return out
}

func (s *Snapshot) rulePasswordNotRequired() (out []Finding) {
	for _, u := range s.Users {
		uac := uacOf(u)
		if uac.Enabled && uac.PasswordNotRequired {
			out = append(out, finding(affectedOf(u),
				map[string]string{"userAccountControl": txt(u, "userAccountControl")}))
		}
	}
	return out
}

func (s *Snapshot) rulePrivPwdNeverExpires() (out []Finding) {
	for _, u := range s.Users {
		if !isPrivilegedUser(u) {
			continue
		}
		uac := uacOf(u)
		if uac.Enabled && uac.PasswordNeverExpires {
			out = append(out, finding(affectedOf(u),
				map[string]string{"userAccountControl": txt(u, "userAccountControl")}))
		}
	}
	return out
}

func (s *Snapshot) ruleDESOnly() (out []Finding) {
	for _, u := range s.Users {
		if uacOf(u).UseDESKeyOnly {
			out = append(out, finding(affectedOf(u),
				map[string]string{"userAccountControl": txt(u, "userAccountControl")}))
		}
	}
	return out
}

func (s *Snapshot) rulePrivStalePassword() (out []Finding) {
	for _, u := range s.Users {
		if !isPrivilegedUser(u) || !uacOf(u).Enabled {
			continue
		}
		age, ok := s.pwdAgeDays(u)
		if !ok || age <= int64(s.Cfg.PrivPwdMaxAgeDays) {
			continue
		}
		out = append(out, finding(affectedOf(u),
			map[string]string{"password_age_days": strconv.FormatInt(age, 10),
				"threshold_days": strconv.Itoa(s.Cfg.PrivPwdMaxAgeDays)}))
	}
	return out
}

func (s *Snapshot) ruleKeyCredentialLink() (out []Finding) {
	for _, u := range s.Users {
		if isPrivilegedUser(u) && has(u, "msDS-KeyCredentialLink") {
			out = append(out, finding(affectedOf(u),
				map[string]string{"key_credentials": strconv.Itoa(len(u.Attributes["msDS-KeyCredentialLink"]))}))
		}
	}
	return out
}

// --- Computers ---

func (s *Snapshot) ruleUnconstrainedDelegation() (out []Finding) {
	for _, c := range s.Computers {
		uac := uacOf(c)
		if !uac.Enabled || !uac.TrustedForDelegation {
			continue
		}
		// Domain controllers legitimately hold this flag; skip SERVER_TRUST_ACCOUNT (0x2000).
		if uac.Raw&0x2000 != 0 {
			continue
		}
		out = append(out, finding(affectedOf(c),
			map[string]string{"userAccountControl": txt(c, "userAccountControl")}))
	}
	return out
}

func (s *Snapshot) ruleRBCD() (out []Finding) {
	for _, c := range s.Computers {
		if !has(c, "msDS-AllowedToActOnBehalfOfOtherIdentity") {
			continue
		}
		ev := map[string]string{}
		if d := parseSD2(c, "msDS-AllowedToActOnBehalfOfOtherIdentity"); d != nil && d.DACL != nil {
			var names []string
			for _, ace := range d.DACL.ACEs {
				names = append(names, s.principalName(ace.SID))
			}
			ev["allowed_principals"] = strings.Join(names, "; ")
		}
		out = append(out, Finding{Affected: []Affected{affectedOf(c)}, Evidence: ev})
	}
	return out
}

func (s *Snapshot) ruleStaleComputer() (out []Finding) {
	for _, c := range s.Computers {
		if !uacOf(c).Enabled {
			continue
		}
		t, ok := addecode.ParseFileTime(txt(c, "lastLogonTimestamp"))
		if !ok || t.Year() == 1601 {
			continue
		}
		days := int64(s.Cfg.Now.Sub(t) / (24 * time.Hour))
		if days <= int64(s.Cfg.StaleDays) {
			continue
		}
		out = append(out, finding(affectedOf(c),
			map[string]string{"days_since_logon": strconv.FormatInt(days, 10),
				"threshold_days": strconv.Itoa(s.Cfg.StaleDays)}))
	}
	return out
}

var legacyOSMarkers = []string{
	"2000", "2003", "2008", "xp", "vista", "windows 7", "windows 8", "windows server 2012",
}

func (s *Snapshot) ruleLegacyOS() (out []Finding) {
	for _, c := range s.Computers {
		if !uacOf(c).Enabled {
			continue
		}
		os := strings.ToLower(txt(c, "operatingSystem"))
		if os == "" {
			continue
		}
		for _, m := range legacyOSMarkers {
			if strings.Contains(os, m) {
				out = append(out, finding(affectedOf(c),
					map[string]string{"operatingSystem": txt(c, "operatingSystem")}))
				break
			}
		}
	}
	return out
}

// --- Groups ---

func (s *Snapshot) ruleForeignPrivMember() (out []Finding) {
	for _, g := range s.Groups {
		if intOf(g, "adminCount") != 1 {
			continue
		}
		for _, m := range textVals(g, "member") {
			if strings.Contains(strings.ToLower(m), "cn=foreignsecurityprincipals") {
				out = append(out, finding(affectedOf(g),
					map[string]string{"member": m, "group": txt(g, "name")}))
			}
		}
	}
	return out
}

func (s *Snapshot) rulePrimaryGroupID() (out []Finding) {
	// Privileged RIDs that may appear as primaryGroupID.
	privRIDs := map[int64]bool{512: true, 516: true, 518: true, 519: true, 520: true, 521: true, 498: true, 517: true}
	scan := func(set []*adws.Object) {
		for _, o := range set {
			rid := intOf(o, "primaryGroupID")
			if rid == 0 || rid == 513 || rid == 515 || rid == 514 || !privRIDs[rid] {
				continue
			}
			// Domain controllers legitimately have primaryGroupID 516 (Domain
			// Controllers) and RODCs 521 (Read-only Domain Controllers); skip
			// those to avoid false positives.
			uac := uacOf(o)
			if rid == 516 && uac.Raw&0x2000 != 0 { // SERVER_TRUST_ACCOUNT
				continue
			}
			if rid == 521 && uac.Raw&0x04000000 != 0 { // PARTIAL_SECRETS_ACCOUNT (RODC)
				continue
			}
			out = append(out, finding(affectedOf(o),
				map[string]string{"primaryGroupID": strconv.FormatInt(rid, 10)}))
		}
	}
	scan(s.Users)
	scan(s.Computers)
	return out
}

// --- Trusts ---

// trustAttributes bits (MS-ADTS).
const (
	trustAttrQuarantinedDomain = 0x00000004 // SID filtering enabled
	trustAttrWithinForest      = 0x00000020
	trustAttrTreatAsExternal   = 0x00000040 // permits SID history across the trust
)

func (s *Snapshot) ruleTrustSIDFilter() (out []Finding) {
	for _, t := range s.Trusts {
		attrs := intOf(t, "trustAttributes")
		// Within-forest trusts are implicitly filtered; only flag cross-forest/external.
		if attrs&trustAttrWithinForest != 0 || attrs&trustAttrQuarantinedDomain != 0 {
			continue
		}
		out = append(out, finding(
			Affected{DistinguishedName: txt(t, "distinguishedName")},
			map[string]string{"trustPartner": txt(t, "trustPartner"),
				"trustAttributes": strconv.FormatInt(attrs, 10)}))
	}
	return out
}

func (s *Snapshot) ruleTrustSIDHistory() (out []Finding) {
	for _, t := range s.Trusts {
		attrs := intOf(t, "trustAttributes")
		if attrs&trustAttrTreatAsExternal != 0 {
			out = append(out, finding(
				Affected{DistinguishedName: txt(t, "distinguishedName")},
				map[string]string{"trustPartner": txt(t, "trustPartner"),
					"trustAttributes": strconv.FormatInt(attrs, 10)}))
		}
	}
	return out
}

// --- DNS ---

func (s *Snapshot) ruleWPAD() (out []Finding) {
	for _, n := range s.DNSNodes {
		if strings.EqualFold(txt(n, "name"), "wpad") {
			out = append(out, finding(
				Affected{DistinguishedName: txt(n, "distinguishedName")},
				map[string]string{"name": "wpad"}))
		}
	}
	return out
}

func (s *Snapshot) ruleISATAP() (out []Finding) {
	for _, n := range s.DNSNodes {
		if strings.EqualFold(txt(n, "name"), "isatap") {
			out = append(out, finding(
				Affected{DistinguishedName: txt(n, "distinguishedName")},
				map[string]string{"name": "isatap"}))
		}
	}
	return out
}

// --- Integrity ---

func (s *Snapshot) ruleSIDHistoryPrivileged() (out []Finding) {
	scan := func(set []*adws.Object) {
		for _, o := range set {
			for _, b := range binVals(o, "sIDHistory") {
				sid := addecode.SIDToString(b)
				if s.isPrivilegedSID(sid) {
					out = append(out, finding(affectedOf(o),
						map[string]string{"sid_history": sid, "resolved": s.principalName(sid)}))
				}
			}
		}
	}
	scan(s.Users)
	scan(s.Computers)
	return out
}

// parseSD2 parses a security descriptor from an arbitrary binary attribute.
func parseSD2(o *adws.Object, attr string) *sd.SecurityDescriptor {
	if b := firstBin(o, attr); b != nil {
		if d, err := sd.Parse(b); err == nil {
			return d
		}
	}
	return nil
}
