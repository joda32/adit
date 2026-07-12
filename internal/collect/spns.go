package collect

import (
	"strings"

	"adit/internal/adws"
)

// UserSPNs collects user accounts with servicePrincipalName, one row per SPN.
func (c *Collector) UserSPNs() (*Table, error) {
	filter := "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
	if c.cfg.OnlyEnabled {
		filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)" + onlyEnabledClause() + ")"
	}
	objects, err := c.q.Query(c.baseDN, filter,
		[]string{"sAMAccountName", "name", "description", "info", "memberOf",
			"servicePrincipalName", "primaryGroupID", "pwdLastSet", "userAccountControl"})
	if err != nil {
		return nil, err
	}
	t := &Table{Name: "UserSPNs", Headers: []string{
		"UserName", "Name", "Enabled", "Service", "Host", "Password Last Set",
		"Description", "Info", "Primary GroupID", "Memberof",
	}}
	for _, o := range objects {
		_, _, pwdSetStr := c.pwdAge(o)
		groups := strings.Join(groupsOf(o), ", ")
		for _, spn := range o.Attributes["servicePrincipalName"] {
			service, host := splitSPN(spn.Text)
			var r row
			r.str(text(o, "sAMAccountName"))
			r.str(text(o, "name"))
			r.str(enabledStr(o))
			r.str(service)
			r.str(host)
			r.str(pwdSetStr)
			r.str(text(o, "description"))
			r.str(text(o, "info"))
			r.str(text(o, "primaryGroupID"))
			r.str(groups)
			t.Rows = append(t.Rows, r.cells)
		}
	}
	return t, nil
}

// ComputerSPNs collects computer/MSA SPNs, grouped by (account, name, service)
// with hosts joined.
func (c *Collector) ComputerSPNs() (*Table, error) {
	compFilter := "(&(objectCategory=computer)(servicePrincipalName=*))"
	msaFilter := "(objectClass=msDS-ManagedServiceAccount)"
	if c.cfg.OnlyEnabled {
		compFilter = "(&(objectCategory=computer)(servicePrincipalName=*)" + onlyEnabledClause() + ")"
		msaFilter = "(&(objectClass=msDS-ManagedServiceAccount)" + onlyEnabledClause() + ")"
	}

	var objects []*adws.Object
	for _, f := range []string{compFilter, msaFilter} {
		part, err := c.q.Query(c.baseDN, f, []string{"name", "sAMAccountName", "servicePrincipalName"})
		if err != nil {
			return nil, err
		}
		objects = append(objects, part...)
	}

	// Group by (sAMAccountName, name, service) preserving first-seen order.
	type key struct{ account, name, service string }
	order := []key{}
	hosts := map[key][]string{}
	seenHost := map[key]map[string]bool{}

	for _, o := range objects {
		account := text(o, "sAMAccountName")
		name := text(o, "name")
		for _, spn := range o.Attributes["servicePrincipalName"] {
			service, host := splitSPN(spn.Text)
			if i := strings.IndexByte(host, ':'); i >= 0 { // strip :port
				host = host[:i]
			}
			k := key{account, name, service}
			if _, ok := hosts[k]; !ok {
				order = append(order, k)
				seenHost[k] = map[string]bool{}
			}
			if host != "" && !seenHost[k][host] {
				seenHost[k][host] = true
				hosts[k] = append(hosts[k], host)
			}
		}
	}

	t := &Table{Name: "ComputerSPNs", Headers: []string{"UserName", "Name", "Service", "Host"}}
	for _, k := range order {
		var r row
		r.str(k.account)
		r.str(k.name)
		r.str(k.service)
		r.str(strings.Join(hosts[k], ","))
		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

// splitSPN splits "service/host[/realm]" into service and host.
func splitSPN(spn string) (service, host string) {
	parts := strings.Split(spn, "/")
	if len(parts) > 0 {
		service = parts[0]
	}
	if len(parts) > 1 {
		host = parts[1]
	}
	return service, host
}
