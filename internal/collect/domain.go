package collect

import (
	"fmt"
	"strconv"
	"strings"
)

// kvTable is a two-column Category/Value table used by Domain and Forest.
type kvTable struct{ t *Table }

func newKV(name string) *kvTable {
	return &kvTable{t: &Table{Name: name, Headers: []string{"Category", "Value"}}}
}
func (k *kvTable) add(category, value string) {
	k.t.Rows = append(k.t.Rows, []string{category, value})
}

// Domain collects domain-wide properties (functional level, SID, MAQ, RID pool).
func (c *Collector) Domain() (*Table, error) {
	kv := newKV("Domain")
	obj, err := c.queryFirst(c.baseDN, "(objectCategory=domainDNS)",
		[]string{"msDS-Behavior-Version", "objectSid", "name", "whenCreated",
			"ms-DS-MachineAccountQuota", "distinguishedName"})
	if err != nil {
		return nil, err
	}
	if obj == nil {
		return kv.t, nil
	}

	fl := lookupOr(domainFunctionalLevels, intText(obj, "msDS-Behavior-Version"), "Unknown")
	kv.add("Name", dnToFQDN(c.baseDN))
	kv.add("NetBIOS", text(obj, "name"))
	kv.add("Functional Level", fl+"Domain")
	kv.add("DomainSID", sidText(obj, "objectSid"))
	kv.add("Creation Date", whenStr(obj, "whenCreated"))
	maq := text(obj, "ms-DS-MachineAccountQuota")
	if maq == "" {
		maq = "10"
	}
	kv.add("ms-DS-MachineAccountQuota", maq)

	if rid, _ := c.queryFirst("CN=RID Manager$,CN=System,"+c.baseDN, "(objectClass=*)", []string{"rIDAvailablePool"}); rid != nil {
		if pool := intText(rid, "rIDAvailablePool"); pool != 0 {
			total := pool >> 32
			issued := pool & 0xFFFFFFFF
			kv.add("RIDs Issued", strconv.FormatInt(issued, 10))
			kv.add("RIDs Remaining", strconv.FormatInt(total-issued, 10))
		}
	}
	return kv.t, nil
}

// Forest collects forest-wide properties and the forest-level FSMO holders.
func (c *Collector) Forest() (*Table, error) {
	kv := newKV("Forest")
	forestName := dnToFQDN(c.cfg.RootDomainDN)
	if forestName == "" {
		forestName = dnToFQDN(c.baseDN)
	}

	if c.cfg.ConfigDN != "" {
		part, err := c.queryFirst("CN=Partitions,"+c.cfg.ConfigDN, "(objectClass=crossRefContainer)",
			[]string{"msDS-Behavior-Version", "fSMORoleOwner"})
		if err != nil {
			return nil, err
		}
		if part != nil {
			fl := lookupOr(domainFunctionalLevels, intText(part, "msDS-Behavior-Version"), "Unknown")
			kv.add("Name", forestName)
			kv.add("Functional Level", fl+"Forest")
			if owner := text(part, "fSMORoleOwner"); owner != "" {
				kv.add("Domain Naming Master", fsmoMasterFQDN(owner, forestName))
			}
		}
	}
	if c.cfg.SchemaDN != "" {
		schema, err := c.queryFirst(c.cfg.SchemaDN, "(objectClass=dMD)", []string{"fSMORoleOwner"})
		if err != nil {
			return nil, err
		}
		if schema != nil {
			if owner := text(schema, "fSMORoleOwner"); owner != "" {
				kv.add("Schema Master", fsmoMasterFQDN(owner, forestName))
			}
		}
	}
	return kv.t, nil
}

// PasswordPolicy collects the default domain password policy with CIS/PCI
// benchmarks, matching the reference's fixed row set.
func (c *Collector) PasswordPolicy() (*Table, error) {
	obj, err := c.queryFirst(c.baseDN, "(objectCategory=domainDNS)",
		[]string{"minPwdLength", "pwdHistoryLength", "pwdProperties", "maxPwdAge",
			"minPwdAge", "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow"})
	if err != nil {
		return nil, err
	}
	t := &Table{Name: "PasswordPolicy", Headers: []string{
		"Policy", "Current Value", "CIS Benchmark 2024-25", "PCI DSS v4.0.1", "PCI DSS Requirement",
	}}
	if obj == nil {
		return t, nil
	}

	props := intText(obj, "pwdProperties")
	boolProp := func(bit int64) string {
		if props&bit != 0 {
			return "TRUE"
		}
		return "FALSE"
	}
	rows := [][5]string{
		{"Enforce password history (passwords)", text(obj, "pwdHistoryLength"), "24 or more passwords", "4", "Req. 8.3.7"},
		{"Maximum password age (d h m s)", formatInterval(text(obj, "maxPwdAge"), "days"), "1 to 365 days", "90 days", "Req. 8.3.9"},
		{"Minimum password age (d h m s)", formatInterval(text(obj, "minPwdAge"), "days"), "1 or more days", "N/A", "-"},
		{"Minimum password length (characters)", text(obj, "minPwdLength"), "14 or more chars", "12 chars", "Req. 8.3.6"},
		{"Password must meet complexity requirements", boolProp(1), "TRUE", "TRUE", "Req. 8.3.6"},
		{"Store password using reversible encryption for all users in the domain", boolProp(16), "FALSE", "N/A", "-"},
		{"Account lockout duration (d h m s)", formatInterval(text(obj, "lockoutDuration"), "days"), "15 mins or more", "0 (manual unlock) or 30 mins", "Req. 8.3.4"},
		{"Account lockout threshold (attempts)", text(obj, "lockoutThreshold"), "1 to 5 attempts", "1 to 10 attempts", "Req. 8.3.4"},
		{"Reset account lockout counter after (mins)", formatInterval(text(obj, "lockOutObservationWindow"), "minutes"), "15 or more mins", "N/A", "-"},
	}
	for _, r := range rows {
		t.Rows = append(t.Rows, r[:])
	}
	return t, nil
}

// formatInterval renders an AD time interval (100-ns ticks, usually negative)
// as "Xd Yh Zm Ws" (days) or total minutes ("minutes"). Empty/invalid yields a
// zero interval.
func formatInterval(raw, unit string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "0d 0h 0m 0s"
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return "0d 0h 0m 0s"
	}
	if n < 0 {
		n = -n
	}
	total := n / 10_000_000 // seconds
	if unit == "minutes" {
		return strconv.FormatInt((total+30)/60, 10) // round to nearest minute
	}
	return fmt.Sprintf("%dd %dh %dm %ds",
		total/86400, (total%86400)/3600, (total%3600)/60, total%60)
}

// FGPP collects fine-grained (PSO) password policies.
func (c *Collector) FGPP() (*Table, error) {
	objects, err := c.q.Query("CN=Password Settings Container,CN=System,"+c.baseDN,
		"(objectCategory=msDS-PasswordSettings)",
		[]string{"name", "msDS-PasswordSettingsPrecedence", "msDS-MinimumPasswordLength",
			"msDS-PasswordHistoryLength", "msDS-PasswordComplexityEnabled",
			"msDS-PasswordReversibleEncryptionEnabled", "msDS-LockoutThreshold", "msDS-PSOAppliesTo"})
	if err != nil {
		return nil, err
	}
	t := &Table{Name: "FineGrainedPasswordPolicy", Headers: []string{
		"Name", "Precedence", "Min Password Length", "Password History",
		"Complexity Enabled", "Reversible Encryption", "Lockout Threshold", "Applies To",
	}}
	for _, o := range objects {
		var r row
		r.str(text(o, "name"))
		r.str(text(o, "msDS-PasswordSettingsPrecedence"))
		r.str(text(o, "msDS-MinimumPasswordLength"))
		r.str(text(o, "msDS-PasswordHistoryLength"))
		r.str(capitalizeBool(text(o, "msDS-PasswordComplexityEnabled")))
		r.str(capitalizeBool(text(o, "msDS-PasswordReversibleEncryptionEnabled")))
		r.str(text(o, "msDS-LockoutThreshold"))
		r.str(listText(o, "msDS-PSOAppliesTo"))
		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

// capitalizeBool renders "TRUE"/"FALSE" (any case) as "True"/"False", leaving
// other values unchanged.
func capitalizeBool(s string) string {
	switch strings.ToUpper(s) {
	case "TRUE":
		return "True"
	case "FALSE":
		return "False"
	default:
		return s
	}
}

// SchemaHistory collects schema objects (classes/attributes) with timestamps.
func (c *Collector) SchemaHistory() (*Table, error) {
	if c.cfg.SchemaDN == "" {
		return &Table{Name: "SchemaHistory", Headers: schemaHeaders()}, nil
	}
	objects, err := c.q.Query(c.cfg.SchemaDN, "(objectCategory=*)",
		[]string{"name", "objectClass", "whenCreated", "whenChanged", "distinguishedName"})
	if err != nil {
		return nil, err
	}
	t := &Table{Name: "SchemaHistory", Headers: schemaHeaders()}
	for _, o := range objects {
		var r row
		r.str(listText(o, "objectClass"))
		r.str(text(o, "name"))
		r.str(whenStr(o, "whenCreated"))
		r.str(whenStr(o, "whenChanged"))
		r.str(text(o, "distinguishedName"))
		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

func schemaHeaders() []string {
	return []string{"ObjectClass", "Name", "whenCreated", "whenChanged", "DistinguishedName"}
}

// DNSZones collects DNS zones from the domain, DomainDnsZones and
// ForestDnsZones partitions.
func (c *Collector) DNSZones() (*Table, error) {
	bases := []string{c.baseDN, "DC=DomainDnsZones," + c.baseDN}
	if c.cfg.RootDomainDN != "" {
		bases = append(bases, "DC=ForestDnsZones,"+c.cfg.RootDomainDN)
	}
	t := &Table{Name: "DNSZones", Headers: []string{"Name", "whenCreated", "whenChanged", "DistinguishedName"}}
	for _, base := range bases {
		objects, err := c.q.Query(base, "(objectCategory=dnsZone)",
			[]string{"name", "distinguishedName", "whenCreated", "whenChanged"})
		if err != nil {
			continue // a missing partition is not fatal
		}
		for _, o := range objects {
			var r row
			r.str(text(o, "name"))
			r.str(whenStr(o, "whenCreated"))
			r.str(whenStr(o, "whenChanged"))
			r.str(text(o, "distinguishedName"))
			t.Rows = append(t.Rows, r.cells)
		}
	}
	return t, nil
}
