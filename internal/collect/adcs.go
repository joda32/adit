package collect

import (
	"fmt"
	"strings"

	"adit/internal/adws"
	"adit/internal/sd"
)

// Certificate-Enrollment and Certificate-AutoEnrollment extended-right GUIDs.
const (
	guidEnrollment     = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
	guidAutoEnrollment = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
)

// EKU OIDs used in ESC checks.
const (
	ekuClientAuth      = "1.3.6.1.5.5.7.3.2"
	ekuAnyPurpose      = "2.5.29.37.0"
	ekuEnrollmentAgent = "1.3.6.1.4.1.311.20.2.1"
)

// wellKnownSIDs maps well-known SIDs to display names for principal resolution.
var wellKnownSIDs = map[string]string{
	"S-1-1-0": "Everyone", "S-1-5-7": "Anonymous", "S-1-5-9": "Enterprise Domain Controllers",
	"S-1-5-10": "Principal Self", "S-1-5-11": "Authenticated Users", "S-1-5-18": "Local System",
	"S-1-5-19": "Local Service", "S-1-5-20": "Network Service",
	"S-1-5-32-544": "Administrators", "S-1-5-32-545": "Users", "S-1-5-32-546": "Guests",
	"S-1-5-32-548": "Account Operators", "S-1-5-32-549": "Server Operators",
	"S-1-5-32-550": "Print Operators", "S-1-5-32-551": "Backup Operators",
}

// builtinRIDs maps domain RIDs to their built-in group names.
var builtinRIDs = map[string]string{
	"498": "Enterprise Read-Only Domain Controllers", "512": "Domain Admins", "513": "Domain Users",
	"514": "Domain Guests", "515": "Domain Computers", "516": "Domain Controllers",
	"517": "Cert Publishers", "518": "Schema Admins", "519": "Enterprise Admins",
	"520": "Group Policy Creator Owners", "521": "Read-Only Domain Controllers",
	"526": "Key Admins", "527": "Enterprise Key Admins", "553": "RAS and IAS Servers",
}

// adminKeywords are substrings (lower-cased) identifying administrative
// principals, mirroring the reference's only-admins-can-enroll check.
var adminKeywords = []string{
	"domain admins", "enterprise admins", "schema admins", "administrator",
	"builtin\\administrators", "account operators", "server operators", "backup operators",
	"print operators", "group policy creator owners", "ras and ias servers", "cert publishers",
	"cryptographic operators", "network configuration operators", "dnsadmins", "dns admins",
	"domain controllers", "enterprise read-only domain controllers", "key admins",
	"enterprise key admins", "protected users",
	"s-1-5-9", "s-1-5-18", "s-1-5-19", "s-1-5-20", "s-1-5-32-544", "s-1-5-32-548",
	"s-1-5-32-549", "s-1-5-32-550", "s-1-5-32-551",
}

// resolvePrincipal maps a SID to a display name (well-known SID, built-in RID,
// or the raw SID for unknown principals).
func resolvePrincipal(s string) string {
	if n, ok := wellKnownSIDs[s]; ok {
		return n
	}
	if strings.HasPrefix(s, "S-1-5-21-") {
		if i := strings.LastIndexByte(s, '-'); i >= 0 {
			if n, ok := builtinRIDs[s[i+1:]]; ok {
				return n
			}
		}
	}
	return s
}

func isLowPrivSID(sid, domainSID string) bool {
	switch sid {
	case "S-1-1-0", "S-1-5-11", "S-1-5-7", "S-1-5-32-545", "S-1-5-32-546":
		return true
	}
	if domainSID != "" {
		for _, rid := range []string{"513", "514", "515"} {
			if sid == domainSID+"-"+rid {
				return true
			}
		}
	}
	return false
}

func isAdminName(name string) bool {
	l := strings.ToLower(name)
	for _, k := range adminKeywords {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}

// principal pairs a SID with its resolved name.
type principal struct{ sid, name string }

// dangerousWriteMask flags WriteDACL, WriteOwner, GenericWrite or GenericAll.
const dangerousWriteMask = sd.RightWriteDACL | sd.RightWriteOwner | sd.RightGenericWrite | sd.RightGenericAll

// parseTemplateACL extracts enrollment/auto-enrollment/write principals and the
// owner from a template's security descriptor. [ESC1–ESC4/ESC9 inputs.]
func parseTemplateACL(descriptor *sd.SecurityDescriptor) (enroll, autoEnroll, write []principal, owner principal) {
	owner = principal{sid: descriptor.Owner, name: resolvePrincipal(descriptor.Owner)}
	if descriptor.DACL == nil {
		return nil, nil, nil, owner
	}
	seen := func(list []principal, name string) bool {
		for _, p := range list {
			if p.name == name {
				return true
			}
		}
		return false
	}
	for _, ace := range descriptor.DACL.ACEs {
		if ace.Type != sd.AceTypeAccessAllowed && ace.Type != sd.AceTypeAccessAllowedObject {
			continue // ALLOW ACEs only
		}
		p := principal{sid: ace.SID, name: resolvePrincipal(ace.SID)}

		// Enrollment (extended right).
		if ace.Mask&sd.RightControlAccess != 0 {
			switch {
			case ace.Type == sd.AceTypeAccessAllowedObject && ace.ObjectType != "":
				if strings.EqualFold(ace.ObjectType, guidEnrollment) && !seen(enroll, p.name) {
					enroll = append(enroll, p)
				}
				if strings.EqualFold(ace.ObjectType, guidAutoEnrollment) && !seen(autoEnroll, p.name) {
					autoEnroll = append(autoEnroll, p)
				}
			default: // object ACE with no GUID, or a plain ACE: all extended rights
				if !seen(enroll, p.name) {
					enroll = append(enroll, p)
				}
			}
		}

		// Dangerous write (ESC4).
		if aceIsDangerousWrite(ace) && !seen(write, p.name) {
			write = append(write, p)
		}
	}
	return enroll, autoEnroll, write, owner
}

// aceIsDangerousWrite reports whether an ALLOW ACE grants a write that could
// take over the object: WriteDACL/WriteOwner/GenericWrite/GenericAll, or a
// non-object-specific WriteProperty.
func aceIsDangerousWrite(ace sd.ACE) bool {
	if ace.Type != sd.AceTypeAccessAllowed && ace.Type != sd.AceTypeAccessAllowedObject {
		return false
	}
	if ace.Mask&dangerousWriteMask != 0 {
		return true
	}
	return ace.Mask&sd.RightDSWriteProp != 0 &&
		(ace.Type == sd.AceTypeAccessAllowed || ace.ObjectType == "")
}

// dangerousWritePrincipals returns the deduplicated principals with dangerous
// write access in a descriptor's DACL.
func dangerousWritePrincipals(descriptor *sd.SecurityDescriptor) []principal {
	if descriptor == nil || descriptor.DACL == nil {
		return nil
	}
	var out []principal
	seen := map[string]bool{}
	for _, ace := range descriptor.DACL.ACEs {
		if !aceIsDangerousWrite(ace) {
			continue
		}
		name := resolvePrincipal(ace.SID)
		if !seen[name] {
			seen[name] = true
			out = append(out, principal{sid: ace.SID, name: name})
		}
	}
	return out
}

// CertificateTemplates collects ADCS templates and flags ESC1–4/9.
func (c *Collector) CertificateTemplates() (*Table, error) {
	t := &Table{Name: "CertificateTemplates", Headers: certTemplateHeaders()}
	if c.cfg.ConfigDN == "" {
		return t, nil
	}
	domainSID := ""
	if d, _ := c.queryFirst(c.baseDN, "(objectCategory=domainDNS)", []string{"objectSid"}); d != nil {
		domainSID = sidText(d, "objectSid")
	}

	base := "CN=Certificate Templates,CN=Public Key Services,CN=Services," + c.cfg.ConfigDN
	objects, err := c.q.Query(base, "(objectClass=pKICertificateTemplate)", []string{
		"cn", "displayName", "distinguishedName", "whenCreated", "whenChanged",
		"pKIExtendedKeyUsage", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
		"msPKI-Private-Key-Flag", "msPKI-RA-Signature", "nTSecurityDescriptor",
		"msPKI-Template-Schema-Version",
	})
	if err != nil {
		return nil, err
	}

	for _, o := range objects {
		t.Rows = append(t.Rows, c.assessTemplate(o, domainSID))
	}
	return t, nil
}

func certTemplateHeaders() []string {
	return []string{
		"Template Name", "Display Name", "Distinguished Name", "Owner", "Schema Version",
		"Created", "Modified", "Extended Key Usage", "Enrollee Supplies Subject", "Allows SAN",
		"Client Authentication", "Any Purpose EKU", "Enrollment Agent", "Exportable Key",
		"Auto-Enrollment", "Requires Manager Approval", "Authorized Signatures Required",
		"Enrollment Flag", "Certificate Name Flag", "Private Key Flag", "Enrollment Rights",
		"Auto-Enrollment Rights", "Write Permissions", "ESC Vulnerabilities", "Risk Level", "Risk Factors",
	}
}

// Principal pairs a SID with its resolved display name.
type Principal struct{ SID, Name string }

// TemplateAssessment is the decoded facts and ESC1–4/9 evaluation of one
// pKICertificateTemplate. It is the single source of truth shared by the
// CertificateTemplates CSV collector and the audit engine's AD-CS rules.
type TemplateAssessment struct {
	EnrolleeSuppliesSubject bool
	AllowsSAN               bool
	HasClientAuth           bool
	HasAnyPurpose           bool
	HasEnrollmentAgent      bool
	ExportableKey           bool
	AutoEnroll              bool
	ManagerApproval         bool
	RASignature             int64
	EnrollFlag              int64
	NameFlag                int64
	KeyFlag                 int64
	EKUs                    string
	Enroll                  []Principal
	AutoEnrollP             []Principal
	Write                   []Principal
	Owner                   Principal
	ESC                     []string // e.g. ["ESC1","ESC4"]
	Risk                    string   // CRITICAL / HIGH / MEDIUM / Medium / Low / None
	Factors                 []string
}

// AssessTemplate decodes a pKICertificateTemplate object and runs the ESC1–4/9
// assessment. Side-effect free.
func AssessTemplate(o *adws.Object, domainSID string) TemplateAssessment {
	enrollFlag := intText(o, "msPKI-Enrollment-Flag")
	nameFlag := intText(o, "msPKI-Certificate-Name-Flag")
	keyFlag := intText(o, "msPKI-Private-Key-Flag")
	raSig := intText(o, "msPKI-RA-Signature")

	a := TemplateAssessment{
		EnrolleeSuppliesSubject: nameFlag&0x00000001 != 0,
		AllowsSAN:               nameFlag&0x00010000 != 0,
		AutoEnroll:              enrollFlag&0x00000020 != 0,
		ManagerApproval:         enrollFlag&0x00000002 != 0,
		ExportableKey:           keyFlag&0x00000010 != 0,
		RASignature:             raSig,
		EnrollFlag:              enrollFlag,
		NameFlag:                nameFlag,
		KeyFlag:                 keyFlag,
	}
	noSecurityExtension := enrollFlag&0x80000000 != 0
	authorizedSignatures := raSig > 0

	var ekus []string
	for _, v := range o.Attributes["pKIExtendedKeyUsage"] {
		ekus = append(ekus, v.Text)
	}
	a.EKUs = strings.Join(ekus, ", ")
	a.HasClientAuth = a.EKUs == "" || strings.Contains(a.EKUs, ekuClientAuth)
	a.HasAnyPurpose = strings.Contains(a.EKUs, ekuAnyPurpose)
	a.HasEnrollmentAgent = strings.Contains(a.EKUs, ekuEnrollmentAgent)

	// Parse the ACL.
	var enroll, autoEnrollP, write []principal
	var owner principal
	if v := o.Attributes["nTSecurityDescriptor"]; len(v) > 0 && v[0].IsBinary {
		if descriptor, err := sd.Parse(v[0].Binary); err == nil {
			enroll, autoEnrollP, write, owner = parseTemplateACL(descriptor)
		}
	}

	lowPrivEnroll := anyLowPriv(enroll, domainSID)
	onlyAdmins := false
	if len(enroll) > 0 && !lowPrivEnroll {
		onlyAdmins = allAdmins(enroll)
	}
	lowPrivWrite := anyLowPriv(write, domainSID)

	a.ESC, a.Risk, a.Factors = assessESC(escInput{
		enrolleeSuppliesSubject: a.EnrolleeSuppliesSubject,
		allowsSAN:               a.AllowsSAN,
		hasClientAuth:           a.HasClientAuth,
		hasAnyPurpose:           a.HasAnyPurpose,
		hasEnrollmentAgent:      a.HasEnrollmentAgent,
		noSecurityExtension:     noSecurityExtension,
		managerApproval:         a.ManagerApproval,
		authorizedSignatures:    authorizedSignatures,
		exportableKey:           a.ExportableKey,
		haveEnrollees:           len(enroll) > 0,
		lowPrivEnroll:           lowPrivEnroll,
		onlyAdmins:              onlyAdmins,
		lowPrivWrite:            lowPrivWrite,
		ownerLowPriv:            owner.sid != "" && isLowPrivSID(owner.sid, domainSID),
	})
	a.Enroll = toPrincipals(enroll)
	a.AutoEnrollP = toPrincipals(autoEnrollP)
	a.Write = toPrincipals(write)
	a.Owner = Principal{SID: owner.sid, Name: owner.name}
	return a
}

// assessTemplate produces one CSV row (with ESC assessment) for a template.
func (c *Collector) assessTemplate(o *adws.Object, domainSID string) []string {
	a := AssessTemplate(o, domainSID)

	var r row
	r.str(text(o, "cn"))
	r.str(text(o, "displayName"))
	r.str(text(o, "distinguishedName"))
	r.str(orUnknown(a.Owner.Name))
	r.str(text(o, "msPKI-Template-Schema-Version"))
	r.str(whenStr(o, "whenCreated"))
	r.str(whenStr(o, "whenChanged"))
	r.str(a.EKUs)
	r.boolean(a.EnrolleeSuppliesSubject)
	r.boolean(a.AllowsSAN)
	r.boolean(a.HasClientAuth)
	r.boolean(a.HasAnyPurpose)
	r.boolean(a.HasEnrollmentAgent)
	r.boolean(a.ExportableKey)
	r.boolean(a.AutoEnroll)
	r.boolean(a.ManagerApproval)
	r.intv(a.RASignature)
	r.str(fmt.Sprintf("0x%x", a.EnrollFlag))
	r.str(fmt.Sprintf("0x%x", a.NameFlag))
	r.str(fmt.Sprintf("0x%x", a.KeyFlag))
	r.str(joinPrincipalsP(a.Enroll))
	r.str(joinPrincipalsP(a.AutoEnrollP))
	r.str(joinPrincipalsP(a.Write))
	r.str(joinOrNone(a.ESC, ", ")) // ESC vulnerabilities
	r.str(a.Risk)
	r.str(joinOrNone(a.Factors, "; ")) // risk factors
	return r.cells
}

// CertificateAuthorities collects ADCS enrollment services (CAs).
func (c *Collector) CertificateAuthorities() (*Table, error) {
	t := &Table{Name: "CertificateAuthorities", Headers: []string{
		"CA Name", "Display Name", "DNS Hostname", "Distinguished Name", "Created",
		"Modified", "Certificate Templates", "Template Count",
	}}
	if c.cfg.ConfigDN == "" {
		return t, nil
	}
	base := "CN=Enrollment Services,CN=Public Key Services,CN=Services," + c.cfg.ConfigDN
	objects, err := c.q.Query(base, "(objectClass=pKIEnrollmentService)",
		[]string{"cn", "displayName", "distinguishedName", "dNSHostName",
			"whenCreated", "whenChanged", "certificateTemplates"})
	if err != nil {
		return nil, err
	}
	for _, o := range objects {
		templates := o.Attributes["certificateTemplates"]
		var names []string
		for _, v := range templates {
			names = append(names, v.Text)
		}
		var r row
		r.str(text(o, "cn"))
		r.str(text(o, "displayName"))
		r.str(text(o, "dNSHostName"))
		r.str(text(o, "distinguishedName"))
		r.str(whenStr(o, "whenCreated"))
		r.str(whenStr(o, "whenChanged"))
		r.str(orNone(strings.Join(names, ", ")))
		r.intv(int64(len(templates)))
		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

// --- helpers ---

func anyLowPriv(ps []principal, domainSID string) bool {
	for _, p := range ps {
		if isLowPrivSID(p.sid, domainSID) {
			return true
		}
	}
	return false
}

func allAdmins(ps []principal) bool {
	for _, p := range ps {
		if !isAdminName(p.name) {
			return false
		}
	}
	return true
}

func toPrincipals(ps []principal) []Principal {
	if len(ps) == 0 {
		return nil
	}
	out := make([]Principal, len(ps))
	for i, p := range ps {
		out[i] = Principal{SID: p.sid, Name: p.name}
	}
	return out
}

func joinPrincipalsP(ps []Principal) string {
	if len(ps) == 0 {
		return "None"
	}
	names := make([]string, len(ps))
	for i, p := range ps {
		names[i] = p.Name
	}
	return strings.Join(names, "; ")
}

func orUnknown(s string) string {
	if s == "" {
		return "Unknown"
	}
	return s
}

func joinOrNone(ss []string, sep string) string {
	if len(ss) == 0 {
		return "None"
	}
	return strings.Join(ss, sep)
}
