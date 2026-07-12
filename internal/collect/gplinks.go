package collect

import (
	"regexp"
	"strconv"
	"strings"

	"adit/internal/adws"
)

// gpLinkRe matches each [LDAP://<dn>;<options>] entry in a gPLink value.
var gpLinkRe = regexp.MustCompile(`(?i)\[LDAP://([^;]+);(\d+)\]`)

// gpoGUIDRe extracts the {GUID} from a policy DN.
var gpoGUIDRe = regexp.MustCompile(`(?i)cn=(\{[^}]+\})`)

// GPLinks collects the GPO links (scope of management) on the domain, OUs and
// sites, resolving each linked GPO to its display name.
func (c *Collector) GPLinks() (*Table, error) {
	// GPO GUID (lower-case) -> display name, for resolution.
	gpoNames := map[string]string{}
	gpos, err := c.q.Query(c.baseDN, "(objectCategory=groupPolicyContainer)", []string{"name", "displayName"})
	if err != nil {
		return nil, err
	}
	for _, g := range gpos {
		if name := strings.ToLower(text(g, "name")); name != "" {
			gpoNames[name] = text(g, "displayName")
		}
	}

	// Domain + OUs, then sites (under the configuration NC).
	objects, err := c.q.Query(c.baseDN,
		"(|(objectCategory=domainDNS)(objectCategory=organizationalUnit))",
		[]string{"name", "distinguishedName", "gPLink", "gPOptions"})
	if err != nil {
		return nil, err
	}
	if c.cfg.ConfigDN != "" {
		sites, err := c.q.Query("CN=Sites,"+c.cfg.ConfigDN, "(objectCategory=site)",
			[]string{"name", "distinguishedName", "gPLink", "gPOptions"})
		if err == nil {
			objects = append(objects, sites...)
		}
	}

	t := &Table{Name: "gPLinks", Headers: []string{
		"Name", "Depth", "DistinguishedName", "Link Order", "GPO", "Enforced",
		"Link Enabled", "BlockInheritance", "gPLink", "gPOptions",
	}}
	for _, o := range objects {
		appendGPLinkRows(t, o, gpoNames)
	}
	return t, nil
}

func appendGPLinkRows(t *Table, o *adws.Object, gpoNames map[string]string) {
	dn := text(o, "distinguishedName")
	name := text(o, "name")
	depth := int64(strings.Count(dn, "OU="))
	gpOptions := text(o, "gPOptions")
	blockInheritance := boolStr(intText(o, "gPOptions")&1 != 0)
	gpLink := text(o, "gPLink")

	links := gpLinkRe.FindAllStringSubmatch(gpLink, -1)
	if len(links) == 0 {
		t.Rows = append(t.Rows, []string{name, strconv.FormatInt(depth, 10), dn, "", "", "", "", blockInheritance, "", gpOptions})
		return
	}

	total := len(links)
	for idx, m := range links {
		opts, _ := strconv.Atoi(m[2])
		enforced := opts&2 != 0
		disabled := opts&1 != 0
		linkOrder := total - idx // reversed: first link has the highest order

		gpo := ""
		if gm := gpoGUIDRe.FindStringSubmatch(m[1]); gm != nil {
			guid := gm[1]
			if display, ok := gpoNames[strings.ToLower(guid)]; ok {
				gpo = display
			} else {
				gpo = guid
			}
		}
		t.Rows = append(t.Rows, []string{
			name, strconv.FormatInt(depth, 10), dn, strconv.Itoa(linkOrder), gpo,
			boolStr(enforced), boolStr(!disabled), blockInheritance, gpLink, gpOptions,
		})
	}
}
