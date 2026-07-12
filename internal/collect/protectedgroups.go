package collect

import (
	"strings"

	"adit/internal/addecode"
	"adit/internal/adws"
)

// protectedGroupSet is the set of well-known AdminSDHolder-protected groups.
var protectedGroupSet = toSet([]string{
	"Account Operators", "Administrators", "Backup Operators", "Domain Admins",
	"Domain Controllers", "Enterprise Admins", "Print Operators",
	"Read-only Domain Controllers", "Replicator", "Schema Admins", "Server Operators",
	"Key Admins", "Enterprise Key Admins", "Cert Publishers", "DnsAdmins",
	"Group Policy Creator Owners", "Incoming Forest Trust Builders",
	"Network Configuration Operators", "Windows Authorization Access Group",
	"Terminal Server License Servers", "RAS and IAS Servers",
	"Allowed RODC Password Replication Group", "Denied RODC Password Replication Group",
	"Cloneable Domain Controllers", "Protected Users", "Cryptographic Operators",
})

// tier0Groups are the highest-privilege groups whose members should be in
// Protected Users.
var tier0Groups = toSet([]string{"Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"})

// ProtectedGroups collects objects with adminCount=1 (AdminSDHolder-protected)
// and assesses whether privileged principals are hardened via Protected Users.
func (c *Collector) ProtectedGroups() (*Table, error) {
	objects, err := c.q.Query(c.baseDN,
		"(&(adminCount=1)(|(objectCategory=person)(objectCategory=group)))",
		[]string{"sAMAccountName", "name", "objectCategory", "distinguishedName",
			"memberOf", "objectSid", "whenChanged", "lastLogonTimestamp"})
	if err != nil {
		return nil, err
	}
	t := &Table{Name: "ProtectedGroups", Headers: []string{
		"Name", "SAM Account Name", "Type", "Status", "Last Logon", "In Protected Users Group",
		"Risk Level", "Recommendations", "AdminSDHolder Protected Group Membership",
		"Security Analysis", "SID", "Last Modified", "Distinguished Name",
	}}

	for _, o := range objects {
		t.Rows = append(t.Rows, assessProtected(o))
	}
	return t, nil
}

func assessProtected(o *adws.Object) []string {
	isUser := strings.Contains(strings.ToLower(text(o, "objectCategory")), "person")
	name := text(o, "name")
	sam := text(o, "sAMAccountName")
	sid := sidText(o, "objectSid")

	objType := "Group"
	if isUser {
		objType = "User"
	}

	isBuiltinAdministrator := strings.HasSuffix(sid, "-500")
	isProtectedGroupObject := !isUser && protectedGroupSet[name]
	samLower := strings.ToLower(sam)
	isBuiltinAccount := isUser && (samLower == "krbtgt" || samLower == "administrator")
	isServiceExclusion := isUser && samLower == "krbtgt"

	var membership []string
	inProtectedGroup, inTier0, inProtectedUsers := false, false, false
	if isUser {
		for _, g := range groupsOf(o) {
			if protectedGroupSet[g] {
				inProtectedGroup = true
				membership = append(membership, g)
			}
			if tier0Groups[g] {
				inTier0 = true
			}
			if g == "Protected Users" {
				inProtectedUsers = true
			}
		}
	}

	status := statusFor(isUser, isProtectedGroupObject, isBuiltinAccount, inProtectedGroup)
	risk, recs, notes := protectedRisk(protectedFacts{
		isUser: isUser, isProtectedGroupObject: isProtectedGroupObject,
		isServiceExclusion: isServiceExclusion, isBuiltinAdministrator: isBuiltinAdministrator,
		isBuiltinAccount: isBuiltinAccount, inTier0: inTier0, inProtectedGroup: inProtectedGroup,
		inProtectedUsers: inProtectedUsers,
	})

	lastLogon := "N/A"
	if isUser {
		if t, ok := addecode.ParseFileTime(text(o, "lastLogonTimestamp")); ok && t.Year() != 1601 {
			lastLogon = addecode.FormatDateTime(t, true)
		} else {
			lastLogon = "Never"
		}
	}

	var r row
	r.str(name)
	r.str(sam)
	r.str(objType)
	r.str(status)
	r.str(lastLogon)
	r.str(yesNo(inProtectedUsers))
	r.str(risk)
	r.str(joinOrNone(recs, "; "))
	r.str(joinOrNone(membership, "; "))
	r.str(joinOrNA(notes))
	r.str(sid)
	r.str(whenStr(o, "whenChanged"))
	r.str(text(o, "distinguishedName"))
	return r.cells
}

func statusFor(isUser, isProtectedGroupObject, isBuiltinAccount, inProtectedGroup bool) string {
	switch {
	case isProtectedGroupObject:
		return "AdminSDHolder Protected Group (Built-in)"
	case isBuiltinAccount:
		return "Built-in Account"
	case isUser && inProtectedGroup:
		return "Member of AdminSDHolder Protected Group(s)"
	case isUser && !inProtectedGroup:
		return "Orphaned AdminCount (not in protected groups)"
	default:
		return "Non-Standard Group with AdminCount=1"
	}
}

type protectedFacts struct {
	isUser, isProtectedGroupObject, isServiceExclusion, isBuiltinAdministrator bool
	isBuiltinAccount, inTier0, inProtectedGroup, inProtectedUsers              bool
}

// protectedRisk replicates the reference's risk/recommendation/security-note
// state machine.
func protectedRisk(f protectedFacts) (risk string, recs, notes []string) {
	risk = "Low"
	switch {
	case f.isProtectedGroupObject:
		risk = "Info"
		recs = []string{"Built-in AdminSDHolder protected group - Review members for Protected Users group inclusion"}
		notes = []string{"This is a GROUP object, not a user account"}
	case f.isServiceExclusion:
		risk = "Info"
		recs = []string{"Service account - Cannot be in 'Protected Users' group (incompatible)"}
		notes = []string{"Service accounts need NTLM/RC4 which Protected Users blocks"}
	case f.isBuiltinAdministrator:
		if !f.inProtectedUsers {
			risk = "Medium"
			recs = []string{"ADD to 'Protected Users' group ONLY if emergency access doesn't require NTLM/RC4/delegation"}
			notes = []string{"Built-in Admin (RID 500) - Consider Protected Users for hardening, but ensure emergency DSRM access is maintained"}
		} else {
			recs = []string{"Properly secured in 'Protected Users' group"}
			notes = []string{"Enhanced authentication security enabled (no NTLM/RC4/delegation)"}
		}
	case f.isBuiltinAccount:
		if !f.inProtectedUsers {
			risk = "Medium"
			recs = []string{"ADD to 'Protected Users' group for enhanced security"}
			notes = []string{"Built-in account lacks Protected Users hardening"}
		} else {
			recs = []string{"Properly secured in 'Protected Users' group"}
			notes = []string{"Enhanced authentication security enabled"}
		}
	case f.isUser && (f.inTier0 || f.inProtectedGroup):
		if !f.inProtectedUsers {
			risk = "HIGH"
			recs = []string{"CRITICAL: ADD to 'Protected Users' group immediately - Blocks Pass-the-Hash, NTLM relay, delegation attacks"}
			notes = []string{"HIGH-VALUE TARGET: Tier-0 privileged user WITHOUT Protected Users hardening - Vulnerable to credential theft (Pass-the-Hash, NTLM relay, Kerberos delegation, RC4 downgrade)"}
		} else {
			recs = []string{"GOOD: Tier-0 account properly secured in 'Protected Users' group"}
			notes = []string{"Optimal security: Protected Users hardening active (NTLM blocked, only AES Kerberos, no delegation, 4hr TGT)"}
		}
	case f.isUser && !f.inProtectedGroup:
		if !f.inProtectedUsers {
			risk = "Medium"
			recs = []string{"INVESTIGATE: Orphaned AdminCount=1 - Verify if user still has privileges, add to Protected Users if needed"}
			notes = []string{"Orphaned AdminSDHolder attribute - User may have been removed from privileged groups. Missing Protected Users protection"}
		} else {
			recs = []string{"In Protected Users group - Secure"}
			notes = []string{"Has Protected Users hardening despite orphaned adminCount"}
		}
	case !f.isUser && !f.isProtectedGroupObject:
		risk = "Info"
		recs = []string{"REVIEW: Non-standard group with AdminCount=1 - Verify members are in Protected Users group"}
		notes = []string{"Custom group with adminCount=1 - Review membership for privileged users"}
	}
	return risk, recs, notes
}

func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}

func joinOrNA(ss []string) string {
	if len(ss) == 0 {
		return "N/A"
	}
	return strings.Join(ss, "; ")
}
