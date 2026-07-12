package collect

import "strings"

// OUs collects organizational units.
func (c *Collector) OUs() (*Table, error) {
	objects, err := c.q.Query(c.baseDN, "(objectCategory=organizationalUnit)",
		[]string{"name", "distinguishedName", "description", "gPLink", "whenCreated", "whenChanged"})
	if err != nil {
		return nil, err
	}
	t := &Table{Name: "OUs", Headers: []string{
		"Name", "Depth", "Description", "whenCreated", "whenChanged", "DistinguishedName",
	}}
	for _, o := range objects {
		dn := text(o, "distinguishedName")
		var r row
		r.str(text(o, "name"))
		r.intv(int64(strings.Count(dn, "OU=")))
		r.str(text(o, "description"))
		r.str(whenStr(o, "whenCreated"))
		r.str(whenStr(o, "whenChanged"))
		r.str(dn)
		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

// GPOs collects Group Policy objects.
func (c *Collector) GPOs() (*Table, error) {
	objects, err := c.q.Query(c.baseDN, "(objectCategory=groupPolicyContainer)",
		[]string{"displayName", "name", "distinguishedName", "gPCFileSysPath", "whenCreated", "whenChanged", "flags"})
	if err != nil {
		return nil, err
	}
	t := &Table{Name: "GPOs", Headers: []string{
		"DisplayName", "GUID", "whenCreated", "whenChanged", "DistinguishedName", "FilePath",
	}}
	for _, o := range objects {
		var r row
		r.str(text(o, "displayName"))
		r.str(text(o, "name"))
		r.str(whenStr(o, "whenCreated"))
		r.str(whenStr(o, "whenChanged"))
		r.str(text(o, "distinguishedName"))
		r.str(text(o, "gPCFileSysPath"))
		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

var trustDirection = map[int64]string{0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
var trustType = map[int64]string{1: "Downlevel", 2: "Uplevel", 3: "MIT", 4: "DCE"}

// trustAttributeFlags maps trustAttributes bits to names, in bit order.
var trustAttributeFlags = []struct {
	bit  int64
	name string
}{
	{0x01, "Non Transitive"}, {0x02, "UpLevel"}, {0x04, "Quarantined"},
	{0x08, "Forest Transitive"}, {0x10, "Cross Organization"}, {0x20, "Within Forest"},
	{0x40, "Treat as External"}, {0x80, "Uses RC4 Encryption"}, {0x200, "No TGT Delegation"},
}

// Trusts collects domain trust relationships.
func (c *Collector) Trusts() (*Table, error) {
	objects, err := c.q.Query(c.baseDN, "(objectCategory=trustedDomain)",
		[]string{"distinguishedName", "trustPartner", "trustDirection", "trustType",
			"trustAttributes", "whenCreated", "whenChanged", "securityIdentifier"})
	if err != nil {
		return nil, err
	}
	t := &Table{Name: "Trusts", Headers: []string{
		"Source Domain", "Target Domain", "Trust Direction", "Trust Type", "Attributes",
		"whenCreated", "whenChanged",
	}}
	for _, o := range objects {
		attrs := intText(o, "trustAttributes")
		var names []string
		for _, f := range trustAttributeFlags {
			if attrs&f.bit != 0 {
				names = append(names, f.name)
			}
		}
		var r row
		r.str(dnToFQDN(text(o, "distinguishedName")))
		r.str(text(o, "trustPartner"))
		r.str(lookupOr(trustDirection, intText(o, "trustDirection"), "Unknown"))
		r.str(lookupOr(trustType, intText(o, "trustType"), "Unknown"))
		r.str(strings.Join(names, ", "))
		r.str(whenStr(o, "whenCreated"))
		r.str(whenStr(o, "whenChanged"))
		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

// Sites collects AD sites (under the configuration NC).
func (c *Collector) Sites() (*Table, error) {
	if c.cfg.ConfigDN == "" {
		return &Table{Name: "Sites", Headers: siteHeaders()}, nil
	}
	objects, err := c.q.Query("CN=Sites,"+c.cfg.ConfigDN, "(objectCategory=site)",
		[]string{"name", "description", "whenCreated", "whenChanged"})
	if err != nil {
		return nil, err
	}
	t := &Table{Name: "Sites", Headers: siteHeaders()}
	for _, o := range objects {
		var r row
		r.str(text(o, "name"))
		r.str(text(o, "description"))
		r.str(whenStr(o, "whenCreated"))
		r.str(whenStr(o, "whenChanged"))
		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

func siteHeaders() []string {
	return []string{"Name", "Description", "whenCreated", "whenChanged"}
}

// Subnets collects AD subnets (under the configuration NC).
func (c *Collector) Subnets() (*Table, error) {
	headers := []string{"Site", "Name", "Description", "whenCreated", "whenChanged"}
	if c.cfg.ConfigDN == "" {
		return &Table{Name: "Subnets", Headers: headers}, nil
	}
	objects, err := c.q.Query("CN=Subnets,CN=Sites,"+c.cfg.ConfigDN, "(objectCategory=subnet)",
		[]string{"name", "description", "siteObject", "whenCreated", "whenChanged"})
	if err != nil {
		return nil, err
	}
	t := &Table{Name: "Subnets", Headers: headers}
	for _, o := range objects {
		var r row
		r.str(cnOf(text(o, "siteObject")))
		r.str(text(o, "name"))
		r.str(text(o, "description"))
		r.str(whenStr(o, "whenCreated"))
		r.str(whenStr(o, "whenChanged"))
		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

func lookupOr(m map[int64]string, k int64, def string) string {
	if v, ok := m[k]; ok {
		return v
	}
	return def
}
