package collect

import (
	"strings"

	"adit/internal/addecode"
	"adit/internal/adws"
	"adit/internal/sd"
)

// lapsAttribute is the legacy Microsoft LAPS password attribute.
const lapsAttribute = "ms-Mcs-AdmPwd"

// lapsHighPriv are principals whose LAPS-read access is expected (filtered out
// of the reader list, matching the reference).
var lapsHighPriv = map[string]bool{
	"local system": true, "administrators": true, "domain admins": true,
	"enterprise admins": true, "schema admins": true, "account operators": true,
	"backup operators": true, "server operators": true, "domain controllers": true,
	"enterprise domain controllers": true,
}

// LAPS collects legacy LAPS (ms-Mcs-AdmPwd) passwords and, from each computer's
// DACL, who can read them.
func (c *Collector) LAPS() (*Table, error) {
	t := &Table{Name: "LAPS", Headers: []string{
		"Hostname", "Enabled", "Stored", "Readable", "Password", "Expiration", "Readers",
	}}
	if c.cfg.SchemaDN == "" {
		return t, nil // cannot verify LAPS / resolve the attribute GUID
	}
	// LAPS installed?
	if installed, _ := c.queryFirst(c.cfg.SchemaDN, "(name="+lapsAttribute+")", []string{"name"}); installed == nil {
		return t, nil
	}
	lapsGUID := c.schemaGUID(lapsAttribute)

	attrs := []string{"name", "sAMAccountName", "dNSHostName", lapsAttribute,
		"ms-Mcs-AdmPwdExpirationTime", "userAccountControl", "nTSecurityDescriptor"}
	filters := []string{
		"(objectCategory=computer)",
		"(&(objectCategory=person)(objectClass=user)(sAMAccountName=*$))",
		"(objectClass=msDS-ManagedServiceAccount)",
	}
	var objects []*adws.Object
	for _, f := range filters {
		part, err := c.q.Query(c.baseDN, f, attrs)
		if err != nil {
			return nil, err
		}
		objects = append(objects, part...)
	}

	for _, o := range objects {
		password := text(o, lapsAttribute)
		expExists := intText(o, "ms-Mcs-AdmPwdExpirationTime") != 0
		expStr := ""
		if exp, ok := addecode.ParseFileTime(text(o, "ms-Mcs-AdmPwdExpirationTime")); ok {
			expStr = exp.Format("2006-01-02 15:04:05")
		}

		hostname := text(o, "dNSHostName")
		if hostname == "" {
			if sam := text(o, "sAMAccountName"); sam != "" {
				hostname = strings.TrimSuffix(sam, "$")
			} else {
				hostname = text(o, "name")
			}
		}

		var r row
		r.str(hostname)
		r.str(enabledStr(o))
		r.boolean(expExists)
		r.boolean(password != "")
		r.str(password)
		r.str(expStr)
		r.str(formatLAPSReaders(o, lapsGUID))
		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

// schemaGUID returns the canonical schemaIDGUID for a schema attribute, or "".
func (c *Collector) schemaGUID(attributeName string) string {
	o, _ := c.queryFirst(c.cfg.SchemaDN, "(name="+attributeName+")", []string{"schemaIDGUID"})
	if o == nil {
		return ""
	}
	if v := o.Attributes["schemaIDGUID"]; len(v) > 0 && v[0].IsBinary && len(v[0].Binary) == 16 {
		return addecode.GUIDToString(v[0].Binary)
	}
	return ""
}

// formatLAPSReaders renders the non-default-admin readers of a computer's LAPS
// password, mirroring the reference's formatting and filtering.
func formatLAPSReaders(o *adws.Object, lapsGUID string) string {
	v := o.Attributes["nTSecurityDescriptor"]
	if len(v) == 0 || !v[0].IsBinary || lapsGUID == "" {
		if lapsGUID == "" {
			return ""
		}
		return "None detected"
	}
	descriptor, err := sd.Parse(v[0].Binary)
	if err != nil {
		return "None detected"
	}
	readers := lapsReaders(descriptor, lapsGUID)
	if len(readers) == 0 {
		return "None detected"
	}

	var formatted []string
	for _, rd := range readers {
		if lapsHighPriv[strings.ToLower(rd.principal)] {
			continue
		}
		formatted = append(formatted, rd.principal+" (Principal) - "+simplifyWhy(rd.why))
	}
	if len(formatted) == 0 {
		return "Only default admins"
	}
	return strings.Join(formatted, ", ")
}

// lapsReader is one principal that can read the LAPS password.
type lapsReader struct{ principal, why string }

// lapsReaders finds DACL principals that can read the LAPS attribute: holders of
// GenericAll/WriteDACL/WriteOwner on the computer, CONTROL_ACCESS on the whole
// object, or object-specific CONTROL_ACCESS for the LAPS attribute GUID.
func lapsReaders(descriptor *sd.SecurityDescriptor, lapsGUID string) []lapsReader {
	if descriptor.DACL == nil {
		return nil
	}
	var out []lapsReader
	seen := map[string]bool{}
	add := func(name, why string) {
		if key := name + "|" + why; !seen[key] {
			seen[key] = true
			out = append(out, lapsReader{name, why})
		}
	}
	const fullControl = sd.RightGenericAll | sd.RightWriteDACL | sd.RightWriteOwner
	for _, ace := range descriptor.DACL.ACEs {
		if ace.Type != sd.AceTypeAccessAllowed && ace.Type != sd.AceTypeAccessAllowedObject {
			continue
		}
		name := resolvePrincipal(ace.SID)
		switch {
		case ace.Mask&fullControl != 0:
			add(name, "High privilege on computer ("+strings.Join(maskToRights(ace.Mask), ", ")+")")
		case ace.Type == sd.AceTypeAccessAllowed:
			if ace.Mask&sd.RightControlAccess != 0 {
				add(name, "CONTROL_ACCESS on object (confidential attributes readable)")
			}
		default: // object ACE
			appliesToLAPS := ace.ObjectType == "" || strings.EqualFold(ace.ObjectType, lapsGUID)
			if appliesToLAPS && ace.Mask&sd.RightControlAccess != 0 {
				add(name, "Object-specific CONTROL_ACCESS for ms-Mcs-AdmPwd")
			}
		}
	}
	return out
}

// maskToRights decodes the access-mask bits the reference reports for readers.
func maskToRights(mask uint32) []string {
	var rights []string
	if mask&sd.RightDSReadProp != 0 {
		rights = append(rights, "READ_PROP")
	}
	if mask&sd.RightControlAccess != 0 {
		rights = append(rights, "CONTROL_ACCESS")
	}
	if mask&sd.RightGenericRead != 0 {
		rights = append(rights, "GENERIC_READ")
	}
	if mask&sd.RightGenericAll != 0 {
		rights = append(rights, "GENERIC_ALL")
	}
	if mask&sd.RightWriteDACL != 0 {
		rights = append(rights, "WRITE_DAC")
	}
	if mask&sd.RightWriteOwner != 0 {
		rights = append(rights, "WRITE_OWNER")
	}
	return rights
}

// simplifyWhy shortens a reader's reason string, matching the reference.
func simplifyWhy(why string) string {
	switch {
	case strings.Contains(why, "Object-specific CONTROL_ACCESS for ms-Mcs-AdmPwd"):
		return "Explicit LAPS read permission"
	case strings.Contains(why, "CONTROL_ACCESS on object"):
		return "General read permission on computer"
	case strings.Contains(why, "High privilege on computer"):
		return "High-level access to computer"
	default:
		return why
	}
}
