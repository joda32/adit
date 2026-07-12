package collect

import "strings"

// fsmoRoles holds the (upper-cased) DC name for each FSMO role, "" if unknown.
type fsmoRoles struct {
	pdc, rid, infra, schema, naming string
}

// collectFSMO best-effort reads the five FSMO role owners from their well-known
// containers. Failures leave the corresponding role empty.
func (c *Collector) collectFSMO() fsmoRoles {
	var f fsmoRoles
	owner := func(base, filter string) string {
		o, err := c.queryFirst(base, filter, []string{"fSMORoleOwner"})
		if err != nil || o == nil {
			return ""
		}
		return fsmoDCName(text(o, "fSMORoleOwner"))
	}
	f.pdc = owner(c.baseDN, "(objectCategory=domainDNS)")
	f.rid = owner("CN=RID Manager$,CN=System,"+c.baseDN, "(objectClass=*)")
	f.infra = owner("CN=Infrastructure,"+c.baseDN, "(objectClass=*)")
	if c.cfg.SchemaDN != "" {
		f.schema = owner(c.cfg.SchemaDN, "(objectClass=dMD)")
	}
	if c.cfg.ConfigDN != "" {
		f.naming = owner("CN=Partitions,"+c.cfg.ConfigDN, "(objectClass=crossRefContainer)")
	}
	return f
}

// DomainControllers collects domain controllers and their FSMO roles.
//
// The reference's IPv4 and SMB-protocol columns require the DNS collector and
// live SMB probing respectively; they are omitted here (the SMB columns are
// hard-coded placeholders in the reference, not real detection).
func (c *Collector) DomainControllers() (*Table, error) {
	fsmo := c.collectFSMO()

	objects, err := c.q.Query(c.baseDN,
		"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
		[]string{"name", "dNSHostName", "operatingSystem", "serverReferenceBL"})
	if err != nil {
		return nil, err
	}

	t := &Table{Name: "DomainControllers", Headers: []string{
		"Domain", "Site", "Name", "Operating System", "Hostname",
		"Infra", "Naming", "Schema", "RID", "PDC",
	}}
	domain := dnToFQDN(c.baseDN)
	for _, o := range objects {
		dcName := strings.ToUpper(text(o, "name"))
		var r row
		r.str(domain)
		r.str(siteFromServerRef(text(o, "serverReferenceBL")))
		r.str(strings.ToLower(dcName))
		r.str(text(o, "operatingSystem"))
		r.str(text(o, "dNSHostName"))
		r.str(boolTrueFalse(fsmo.infra == dcName))
		r.str(boolTrueFalse(fsmo.naming == dcName))
		r.str(boolTrueFalse(fsmo.schema == dcName))
		r.str(boolTrueFalse(fsmo.rid == dcName))
		r.str(boolTrueFalse(fsmo.pdc == dcName))
		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

// siteFromServerRef extracts the site name from a serverReferenceBL DN, whose
// path passes through CN=<site>,CN=Sites,...
func siteFromServerRef(ref string) string {
	parts := strings.Split(ref, ",")
	for i, p := range parts {
		if strings.HasPrefix(p, "CN=Sites") {
			if i > 0 {
				return strings.TrimPrefix(parts[i-1], "CN=")
			}
			return ""
		}
	}
	return ""
}

// boolTrueFalse renders a bool as the upper-case "TRUE"/"FALSE" the reference
// uses for these columns.
func boolTrueFalse(b bool) string {
	if b {
		return "TRUE"
	}
	return "FALSE"
}
