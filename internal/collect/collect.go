// Package collect implements ADRecon collection modules on top of the ADWS
// query client. Each collector runs a specific LDAP filter, decodes the raw
// attributes (see internal/addecode), and produces a Table that can be written
// as CSV. Column names and semantics follow PyADRecon-ADWS.
package collect

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"adit/internal/addecode"
	"adit/internal/adws"
)

// Querier issues an ADWS query; satisfied by *adws.Client.
type Querier interface {
	Query(baseDN, filter string, attributes []string) ([]*adws.Object, error)
}

// Config holds the thresholds, naming contexts and reference time shared by
// collectors.
type Config struct {
	DormantDays     int
	PasswordAgeDays int
	OnlyEnabled     bool
	ConfigDN        string    // configurationNamingContext (sites/subnets/partitions)
	SchemaDN        string    // schemaNamingContext (schema history / FSMO)
	RootDomainDN    string    // rootDomainNamingContext (forest name / ForestDnsZones)
	Now             time.Time // reference "now" (UTC); zero means time.Now().
}

// Collector runs collection modules against a base DN.
type Collector struct {
	q      Querier
	baseDN string
	cfg    Config
}

// New returns a Collector. A zero cfg.Now is filled with the current UTC time.
func New(q Querier, baseDN string, cfg Config) *Collector {
	if cfg.Now.IsZero() {
		cfg.Now = time.Now().UTC()
	}
	if cfg.DormantDays == 0 {
		cfg.DormantDays = 90
	}
	if cfg.PasswordAgeDays == 0 {
		cfg.PasswordAgeDays = 180
	}
	return &Collector{q: q, baseDN: baseDN, cfg: cfg}
}

// Table is a named set of rows with a fixed header.
type Table struct {
	Name    string
	Headers []string
	Rows    [][]string
}

// WriteCSV writes the table to dir/<Name>.csv.
func (t *Table) WriteCSV(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, t.Name+".csv")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	if err := w.Write(t.Headers); err != nil {
		return "", err
	}
	if err := w.WriteAll(t.Rows); err != nil {
		return "", err
	}
	w.Flush()
	return path, w.Error()
}

// row accumulates cells in header order.
type row struct{ cells []string }

func (r *row) str(s string)   { r.cells = append(r.cells, s) }
func (r *row) boolean(b bool) { r.cells = append(r.cells, boolStr(b)) }
func (r *row) intv(n int64)   { r.cells = append(r.cells, strconv.FormatInt(n, 10)) }

// optInt renders an integer or "" when absent (matching the reference's use of
// "" for missing numeric fields).
func (r *row) optInt(n int64, present bool) {
	if present {
		r.intv(n)
	} else {
		r.str("")
	}
}

func boolStr(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

// --- attribute helpers over *adws.Object ---

func text(o *adws.Object, attr string) string { return o.First(attr) }

func intText(o *adws.Object, attr string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(o.First(attr)), 10, 64)
	return n
}

// sidText decodes a binary SID attribute.
func sidText(o *adws.Object, attr string) string {
	if vs := o.Attributes[attr]; len(vs) > 0 && vs[0].IsBinary {
		return addecode.SIDToString(vs[0].Binary)
	}
	return ""
}

// sidListText joins a multi-valued binary SID attribute (e.g. sIDHistory).
func sidListText(o *adws.Object, attr string) string {
	var out []string
	for _, v := range o.Attributes[attr] {
		if v.IsBinary {
			if s := addecode.SIDToString(v.Binary); s != "" {
				out = append(out, s)
			}
		}
	}
	return strings.Join(out, ", ")
}

// listText joins a multi-valued text attribute.
func listText(o *adws.Object, attr string) string {
	vs := o.Attributes[attr]
	parts := make([]string, 0, len(vs))
	for _, v := range vs {
		parts = append(parts, v.Text)
	}
	return strings.Join(parts, ", ")
}

func has(o *adws.Object, attr string) bool { return len(o.Attributes[attr]) > 0 }

// daysBetween returns the whole days from t to now (floor), matching Python's
// timedelta.days for the common (now >= t) case.
func daysBetween(now, t time.Time) int64 {
	return int64(now.Sub(t) / (24 * time.Hour))
}

// cnOf extracts the CN component of a DN, or returns the input unchanged.
func cnOf(dn string) string {
	if dn == "" {
		return ""
	}
	first := strings.SplitN(dn, ",", 2)[0]
	if strings.HasPrefix(strings.ToUpper(first), "CN=") {
		return first[3:]
	}
	return dn
}

// dnToFQDN turns a DN's DC= components into a dotted domain name.
func dnToFQDN(dn string) string {
	var parts []string
	for _, p := range strings.Split(dn, ",") {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(strings.ToUpper(p), "DC=") {
			parts = append(parts, p[3:])
		}
	}
	return strings.Join(parts, ".")
}

// pwdAge decodes a pwdLastSet FILETIME string and returns the age in days and
// the formatted set time, treating 0 / 1601 / absent as "not set".
func (c *Collector) pwdAge(o *adws.Object) (age int64, present bool, setStr string) {
	t, ok := addecode.ParseFileTime(text(o, "pwdLastSet"))
	if !ok || t.Year() == 1601 {
		return 0, false, ""
	}
	return daysBetween(c.cfg.Now, t), true, addecode.FormatDateTime(t, true)
}

// logonAge decodes a lastLogonTimestamp FILETIME string similarly.
func (c *Collector) logonAge(o *adws.Object) (age int64, present bool, logonStr string) {
	t, ok := addecode.ParseFileTime(text(o, "lastLogonTimestamp"))
	if !ok || t.Year() == 1601 {
		return 0, false, ""
	}
	return daysBetween(c.cfg.Now, t), true, addecode.FormatDateTime(t, true)
}

// enabledStr renders the Enabled flag from userAccountControl as "True"/"False".
func enabledStr(o *adws.Object) string {
	return boolStr(addecode.ParseUAC(uint32(intText(o, "userAccountControl"))).Enabled)
}

// whenStr formats a GeneralizedTime attribute.
func whenStr(o *adws.Object, attr string) string {
	return addecode.FormatDateTime(addecode.GeneralizedTimeToTime(text(o, attr)))
}

// groupsOf returns the CN of each memberOf DN.
func groupsOf(o *adws.Object) []string {
	var out []string
	for _, v := range o.Attributes["memberOf"] {
		out = append(out, cnOf(v.Text))
	}
	return out
}

// queryFirst runs a query and returns the first object, or nil if none.
func (c *Collector) queryFirst(base, filter string, attrs []string) (*adws.Object, error) {
	objs, err := c.q.Query(base, filter, attrs)
	if err != nil {
		return nil, err
	}
	if len(objs) == 0 {
		return nil, nil
	}
	return objs[0], nil
}

// domainFunctionalLevels maps msDS-Behavior-Version to a level name.
var domainFunctionalLevels = map[int64]string{
	0: "Windows2000", 1: "Windows2003Mixed", 2: "Windows2003", 3: "Windows2008",
	4: "Windows2008R2", 5: "Windows2012", 6: "Windows2012R2", 7: "Windows2016",
}

// fsmoDCName extracts the (upper-cased) DC name from an fSMORoleOwner DN, whose
// second RDN is the server: CN=NTDS Settings,CN=DC1,... -> "DC1".
func fsmoDCName(ownerDN string) string {
	parts := strings.Split(ownerDN, ",")
	if len(parts) < 2 {
		return ""
	}
	return strings.ToUpper(strings.TrimPrefix(parts[1], "CN="))
}

// fsmoMasterFQDN renders an fSMORoleOwner DN as "<dc>.<domain>", falling back to
// the given domain when the owner DN carries no DC= components.
func fsmoMasterFQDN(ownerDN, fallbackDomain string) string {
	parts := strings.Split(ownerDN, ",")
	if len(parts) < 2 {
		return ""
	}
	dc := strings.ToLower(strings.TrimPrefix(parts[1], "CN="))
	domain := dnToFQDN(ownerDN)
	if domain == "" {
		domain = fallbackDomain
	}
	return dc + "." + domain
}

// onlyEnabledClause returns the UAC "not disabled" LDAP matching-rule clause.
func onlyEnabledClause() string {
	return "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
}

// thresholdHeader builds a "Label (> N days)" column name.
func thresholdHeader(label string, n int) string {
	return fmt.Sprintf("%s (> %d days)", label, n)
}
