package audit

import (
	"strings"

	"adit/internal/adws"
	"adit/internal/sd"
)

// Attribute / extended-right GUIDs used to classify dangerous ACEs.
const (
	guidSPN          = "f3a64788-5306-11d1-a9c5-0000f80367c1" // servicePrincipalName
	guidKeyCredLink  = "5b47d60f-6090-40b2-9f37-2a4de88f3063" // msDS-KeyCredentialLink
	guidAllowedToAct = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79" // msDS-AllowedToActOnBehalfOfOtherIdentity
)

// wellKnownAdminSIDs are principals whose control over privileged objects is
// expected (and therefore not reported).
var wellKnownAdminSIDs = map[string]bool{
	"S-1-5-18":     true, // Local System
	"S-1-5-9":      true, // Enterprise Domain Controllers
	"S-1-5-10":     true, // SELF
	"S-1-3-0":      true, // Creator Owner
	"S-1-5-32-544": true, "S-1-5-32-548": true, "S-1-5-32-549": true,
	"S-1-5-32-550": true, "S-1-5-32-551": true, "S-1-5-32-552": true,
}

// isExpectedController reports whether a principal is an expected controller of
// privileged objects (privileged group / well-known admin / the object itself).
func (s *Snapshot) isExpectedController(sid, ownSID string) bool {
	return sid == ownSID || s.isPrivilegedSID(sid) || wellKnownAdminSIDs[sid]
}

// aclRight describes a dangerous right an ACE grants, mapped to a rule id.
type aclRight struct {
	kind   string
	ruleID string
	title  string
}

// classifyDangerous returns the dangerous right an ALLOW ace grants over a
// privileged object, or ok=false.
func classifyDangerous(ace sd.ACE) (aclRight, bool) {
	if ace.Type != sd.AceTypeAccessAllowed && ace.Type != sd.AceTypeAccessAllowedObject {
		return aclRight{}, false
	}
	// An INHERIT_ONLY ACE grants nothing on the object itself (it only seeds
	// child objects), so it does not confer control over this object.
	if ace.Flags&sd.AceFlagInheritOnly != 0 {
		return aclRight{}, false
	}
	switch {
	case ace.Mask&sd.RightGenericAll != 0:
		return aclRight{"GenericAll", "AD-ACL-001", "GenericAll over privileged object"}, true
	case ace.Mask&sd.RightWriteDACL != 0:
		return aclRight{"WriteDACL", "AD-ACL-006", "WriteDACL over privileged object"}, true
	case ace.Mask&sd.RightWriteOwner != 0:
		return aclRight{"WriteOwner", "AD-ACL-007", "WriteOwner over privileged object"}, true
	case ace.Mask&sd.RightControlAccess != 0:
		switch {
		case eqGUID(ace.ObjectType, sd.GUIDResetPassword):
			return aclRight{"ForceChangePassword", "AD-ACL-012", "Force-Change-Password over privileged object"}, true
		case ace.ObjectType == "":
			return aclRight{"AllExtendedRights", "AD-ACL-011", "All Extended Rights over privileged object"}, true
		}
	case ace.Mask&sd.RightGenericWrite != 0:
		return aclRight{"GenericWrite", "AD-ACL-005", "GenericWrite over privileged object"}, true
	case ace.Mask&sd.RightDSWriteProp != 0:
		switch {
		case eqGUID(ace.ObjectType, sd.GUIDWriteMember):
			return aclRight{"WriteMember", "AD-ACL-016", "Write member over privileged group"}, true
		case eqGUID(ace.ObjectType, guidSPN):
			return aclRight{"WriteSPN", "AD-ACL-013", "Write servicePrincipalName over privileged object"}, true
		case eqGUID(ace.ObjectType, guidKeyCredLink):
			return aclRight{"WriteKeyCredentialLink", "AD-ACL-014", "Write msDS-KeyCredentialLink over privileged object"}, true
		case eqGUID(ace.ObjectType, guidAllowedToAct):
			return aclRight{"WriteAllowedToAct", "AD-ACL-015", "Write msDS-AllowedToActOnBehalfOfOtherIdentity"}, true
		case ace.ObjectType == "":
			return aclRight{"WriteAllProperties", "AD-ACL-005", "Write all properties over privileged object"}, true
		}
	}
	return aclRight{}, false
}

func eqGUID(a, b string) bool { return strings.EqualFold(a, b) }

func parseSD(o *adws.Object) *sd.SecurityDescriptor {
	if b := firstBin(o, "nTSecurityDescriptor"); b != nil {
		if d, err := sd.Parse(b); err == nil {
			return d
		}
	}
	return nil
}

func init() {
	addChecks(
		// AD-ACL-* — dangerous control over a privileged object by an
		// unexpected (non-Tier-0) principal. Emits per-right rule IDs.
		check{
			Category:    "ACL",
			Description: "A non-Tier-0 principal has a dangerous control right over a privileged object, allowing takeover or privilege escalation.",
			Risk:        "The principal can take over the privileged identity or grant itself further control.",
			Remediation: "Remove the ACE or restrict the right to approved Tier-0 principals.",
			Fn:          (*Snapshot).ruleDangerousPrivilegedACL,
		},
		// AD-DOM-010 — DCSync-capable principals on the domain root.
		check{
			ID: "AD-DOM-010", Title: "Unexpected DCSync (replication) rights on the domain",
			Category: "Domain", Severity: Critical,
			Description: "A non-approved principal can replicate directory changes (DS-Replication-Get-Changes-All), enabling DCSync.",
			Risk:        "DCSync allows extraction of password hashes for any account, including krbtgt — full domain compromise.",
			Remediation: "Remove replication rights from non-approved principals; review delegated synchronisation accounts.",
			Fn:          (*Snapshot).ruleDCSync,
		},
		// AD-SDH-001/002 — AdminSDHolder ACL / owner.
		check{
			ID: "AD-SDH-001", Title: "Unexpected control over AdminSDHolder",
			Category: "AdminSDHolder", Severity: Critical,
			Description: "A non-Tier-0 principal can modify AdminSDHolder, whose ACL is propagated to all protected privileged objects.",
			Risk:        "Control of AdminSDHolder yields persistent control over every AdminSDHolder-protected principal.",
			Remediation: "Restore the default AdminSDHolder ACL and remove unexpected ACEs/owner.",
			Fn:          (*Snapshot).ruleAdminSDHolder,
		},
	)
}

// ruleDangerousPrivilegedACL flags dangerous rights over privileged users/groups.
func (s *Snapshot) ruleDangerousPrivilegedACL() (out []Finding) {
	targets := []*adws.Object{}
	for _, u := range s.Users {
		if isPrivilegedUser(u) {
			targets = append(targets, u)
		}
	}
	for _, g := range s.Groups {
		if intOf(g, "adminCount") == 1 {
			targets = append(targets, g)
		}
	}

	for _, o := range targets {
		d := parseSD(o)
		if d == nil || d.DACL == nil {
			continue
		}
		ownSID := objSID(o)
		seen := map[string]bool{}
		for _, ace := range d.DACL.ACEs {
			if s.isExpectedController(ace.SID, ownSID) {
				continue
			}
			r, ok := classifyDangerous(ace)
			if !ok {
				continue
			}
			key := ace.SID + "|" + r.kind
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Finding{
				RuleID:   r.ruleID,
				Title:    r.title,
				Severity: Critical,
				Affected: []Affected{affectedOf(o)},
				Evidence: map[string]string{
					"right":     r.kind,
					"principal": s.principalName(ace.SID),
					"target":    txt(o, "distinguishedName"),
				},
			})
		}
	}
	return out
}

// ruleDCSync flags principals with replication rights on the domain root.
func (s *Snapshot) ruleDCSync() (out []Finding) {
	d := parseSD(s.Domain)
	if d == nil || d.DACL == nil {
		return nil
	}
	// Collect the replication-related rights per principal.
	getChanges := map[string]bool{}
	getChangesAll := map[string]bool{}
	genericAll := map[string]bool{}
	for _, ace := range d.DACL.ACEs {
		if ace.Type != sd.AceTypeAccessAllowed && ace.Type != sd.AceTypeAccessAllowedObject {
			continue
		}
		if ace.Flags&sd.AceFlagInheritOnly != 0 {
			continue // applies to child objects only, not the domain head
		}
		if ace.Mask&sd.RightGenericAll != 0 {
			genericAll[ace.SID] = true
		}
		if ace.Mask&sd.RightControlAccess != 0 {
			switch {
			case eqGUID(ace.ObjectType, sd.GUIDDSReplGetChanges):
				getChanges[ace.SID] = true
			case eqGUID(ace.ObjectType, sd.GUIDDSReplGetChangesAll):
				getChangesAll[ace.SID] = true
			case ace.ObjectType == "":
				// A ControlAccess ACE with no ObjectType grants *all* extended
				// rights, which includes both replication rights.
				getChanges[ace.SID] = true
				getChangesAll[ace.SID] = true
			}
		}
	}
	// DCSync requires BOTH DS-Replication-Get-Changes and Get-Changes-All (or
	// GenericAll, which subsumes them). Get-Changes-All alone cannot replicate.
	dcsync := map[string]bool{}
	for sid := range getChangesAll {
		if getChanges[sid] {
			dcsync[sid] = true
		}
	}
	for sid := range genericAll {
		dcsync[sid] = true
	}
	for sid := range dcsync {
		if s.isExpectedController(sid, "") {
			continue
		}
		out = append(out, finding(
			Affected{ObjectSID: sid, SAMAccountName: s.principalName(sid)},
			map[string]string{
				"principal":                      s.principalName(sid),
				"DS-Replication-Get-Changes":     boolStr(getChanges[sid] || genericAll[sid]),
				"DS-Replication-Get-Changes-All": boolStr(getChangesAll[sid] || genericAll[sid]),
			}))
	}
	return out
}

// ruleAdminSDHolder flags dangerous control over AdminSDHolder.
func (s *Snapshot) ruleAdminSDHolder() (out []Finding) {
	d := parseSD(s.AdminSDHolder)
	if d == nil {
		return nil
	}
	// Unexpected owner.
	if d.Owner != "" && !s.isExpectedController(d.Owner, "") {
		out = append(out, Finding{
			RuleID: "AD-SDH-002", Title: "Unexpected owner of AdminSDHolder",
			Affected: []Affected{{DistinguishedName: txt(s.AdminSDHolder, "distinguishedName"), ObjectSID: d.Owner}},
			Evidence: map[string]string{"owner": s.principalName(d.Owner)},
		})
	}
	if d.DACL == nil {
		return out
	}
	seen := map[string]bool{}
	for _, ace := range d.DACL.ACEs {
		if s.isExpectedController(ace.SID, "") {
			continue
		}
		r, ok := classifyDangerous(ace)
		if !ok || seen[ace.SID+r.kind] {
			continue
		}
		seen[ace.SID+r.kind] = true
		out = append(out, finding(
			Affected{DistinguishedName: txt(s.AdminSDHolder, "distinguishedName")},
			map[string]string{"right": r.kind, "principal": s.principalName(ace.SID)}))
	}
	return out
}

// principalName resolves a SID to a friendly name from the snapshot, else the SID.
func (s *Snapshot) principalName(sid string) string {
	if o := s.sidToObj[sid]; o != nil {
		if n := txt(o, "sAMAccountName"); n != "" {
			return n
		}
		if n := txt(o, "name"); n != "" {
			return n
		}
	}
	return sid
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
