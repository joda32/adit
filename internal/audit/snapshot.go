package audit

import (
	"strconv"
	"strings"
	"time"

	"adit/internal/addecode"
	"adit/internal/adws"
)

// Querier issues an ADWS query; satisfied by *adws.Client.
type Querier interface {
	Query(base, filter string, attrs []string) ([]*adws.Object, error)
}

// Config holds the thresholds the rules compare against.
type Config struct {
	Now               time.Time
	KrbtgtMaxAgeDays  int
	PrivPwdMaxAgeDays int
	StaleDays         int
}

func (c *Config) defaults() {
	if c.Now.IsZero() {
		c.Now = time.Now().UTC()
	}
	if c.KrbtgtMaxAgeDays == 0 {
		c.KrbtgtMaxAgeDays = 180
	}
	if c.PrivPwdMaxAgeDays == 0 {
		c.PrivPwdMaxAgeDays = 365
	}
	if c.StaleDays == 0 {
		c.StaleDays = 90
	}
}

// Snapshot is the pre-loaded directory data rules evaluate against.
type Snapshot struct {
	Cfg      Config
	BaseDN   string
	ConfigDN string

	DomainSID     string
	Domain        *adws.Object
	AdminSDHolder *adws.Object
	Users         []*adws.Object
	Computers     []*adws.Object
	Groups        []*adws.Object
	Trusts        []*adws.Object
	DNSNodes      []*adws.Object
	CertTemplates []*adws.Object // ADCS pKICertificateTemplate (Configuration NC)
	CAs           []*adws.Object // ADCS enrollment services (pKIEnrollmentService)
	PKIObjects    []*adws.Object // PKI objects whose DACL matters for ESC5

	privileged map[string]bool // SIDs considered privileged (Tier-0 groups)
	dnToObj    map[string]*adws.Object
	sidToObj   map[string]*adws.Object
}

var userAttrs = []string{
	"sAMAccountName", "distinguishedName", "objectSid", "userAccountControl", "adminCount",
	"servicePrincipalName", "sIDHistory", "pwdLastSet", "lastLogonTimestamp", "memberOf",
	"primaryGroupID", "msDS-SupportedEncryptionTypes", "msDS-KeyCredentialLink",
	"msDS-AllowedToDelegateTo", "userPrincipalName", "mail", "whenCreated", "nTSecurityDescriptor",
	// Readable attributes that can leak credentials (AD-USR-020/021).
	"description", "info", "comment", "userPassword", "unixUserPassword",
}

var computerAttrs = []string{
	"sAMAccountName", "distinguishedName", "objectSid", "userAccountControl", "servicePrincipalName",
	"sIDHistory", "pwdLastSet", "lastLogonTimestamp", "operatingSystem", "operatingSystemVersion",
	"dNSHostName", "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-KeyCredentialLink",
	"msDS-SupportedEncryptionTypes", "adminCount", "primaryGroupID", "whenCreated", "nTSecurityDescriptor",
	"description", "info", "comment",
}

var groupAttrs = []string{
	"name", "distinguishedName", "objectSid", "adminCount", "member", "memberOf",
	"sIDHistory", "managedBy", "nTSecurityDescriptor",
}

var trustAttrs = []string{
	"trustPartner", "trustDirection", "trustType", "trustAttributes", "distinguishedName", "whenCreated",
}

var domainAttrs = []string{
	"objectSid", "msDS-Behavior-Version", "ms-DS-MachineAccountQuota", "pwdProperties",
	"minPwdLength", "maxPwdAge", "lockoutThreshold", "nTSecurityDescriptor", "distinguishedName", "name",
}

var certTemplateAttrs = []string{
	"cn", "displayName", "distinguishedName", "pKIExtendedKeyUsage",
	"msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "msPKI-Private-Key-Flag",
	"msPKI-RA-Signature", "nTSecurityDescriptor",
}

var caAttrs = []string{
	"cn", "dNSHostName", "distinguishedName", "certificateTemplates", "nTSecurityDescriptor",
}

var pkiACLAttrs = []string{"cn", "name", "distinguishedName", "nTSecurityDescriptor"}

// Load queries the directory and builds a Snapshot.
func Load(q Querier, baseDN, configDN string, cfg Config) (*Snapshot, error) {
	cfg.defaults()
	s := &Snapshot{Cfg: cfg, BaseDN: baseDN, ConfigDN: configDN}

	if d, err := queryFirst(q, baseDN, "(objectCategory=domainDNS)", domainAttrs); err != nil {
		return nil, err
	} else {
		s.Domain = d
		if d != nil {
			s.DomainSID = objSID(d)
		}
	}
	s.AdminSDHolder, _ = queryFirst(q, "CN=AdminSDHolder,CN=System,"+baseDN, "(objectClass=*)",
		[]string{"nTSecurityDescriptor", "name", "distinguishedName"})

	var err error
	if s.Users, err = q.Query(baseDN, "(&(objectCategory=person)(objectClass=user))", userAttrs); err != nil {
		return nil, err
	}
	if s.Computers, err = q.Query(baseDN, "(objectCategory=computer)", computerAttrs); err != nil {
		return nil, err
	}
	if s.Groups, err = q.Query(baseDN, "(objectCategory=group)", groupAttrs); err != nil {
		return nil, err
	}
	s.Trusts, _ = q.Query(baseDN, "(objectCategory=trustedDomain)", trustAttrs)
	s.DNSNodes, _ = q.Query(baseDN, "(&(objectClass=dnsNode)(|(name=wpad)(name=isatap)))",
		[]string{"name", "distinguishedName", "nTSecurityDescriptor"})

	// ADCS objects live in the Configuration NC's Public Key Services container.
	if configDN != "" {
		pki := "CN=Public Key Services,CN=Services," + configDN
		s.CertTemplates, _ = q.Query("CN=Certificate Templates,"+pki,
			"(objectClass=pKICertificateTemplate)", certTemplateAttrs)
		s.CAs, _ = q.Query("CN=Enrollment Services,"+pki,
			"(objectClass=pKIEnrollmentService)", caAttrs)
		// Objects whose DACL, if writable by a non-Tier-0 principal, is an ESC5
		// escalation: NTAuthCertificates and the Certification Authorities store.
		for _, dn := range []string{"CN=NTAuthCertificates," + pki, "CN=Certification Authorities," + pki} {
			if o, _ := queryFirst(q, dn, "(objectClass=*)", pkiACLAttrs); o != nil {
				s.PKIObjects = append(s.PKIObjects, o)
			}
		}
		s.PKIObjects = append(s.PKIObjects, s.CAs...)
	}

	s.build()
	return s, nil
}

// build populates the derived maps and the privileged-SID set.
func (s *Snapshot) build() {
	s.dnToObj = map[string]*adws.Object{}
	s.sidToObj = map[string]*adws.Object{}
	for _, set := range [][]*adws.Object{s.Users, s.Computers, s.Groups} {
		for _, o := range set {
			if dn := txt(o, "distinguishedName"); dn != "" {
				s.dnToObj[strings.ToLower(dn)] = o
			}
			if sid := objSID(o); sid != "" {
				s.sidToObj[sid] = o
			}
		}
	}

	// Privileged group SIDs: well-known RIDs off the domain SID, plus built-in.
	s.privileged = map[string]bool{}
	// 500 = built-in Administrator; the rest are built-in privileged groups.
	for _, rid := range []string{"500", "512", "516", "518", "519", "520", "521", "498", "517", "526", "527"} {
		if s.DomainSID != "" {
			s.privileged[s.DomainSID+"-"+rid] = true
		}
	}
	for _, b := range []string{"544", "548", "549", "550", "551", "552"} {
		s.privileged["S-1-5-32-"+b] = true
	}
	// Any object flagged by AdminSDHolder (adminCount=1) is also privileged —
	// groups *and* users (e.g. named Tier-0 admins), so their control over other
	// privileged objects is expected rather than reported as a takeover.
	for _, g := range s.Groups {
		if intOf(g, "adminCount") == 1 {
			if sid := objSID(g); sid != "" {
				s.privileged[sid] = true
			}
		}
	}
	for _, u := range s.Users {
		if intOf(u, "adminCount") == 1 {
			if sid := objSID(u); sid != "" {
				s.privileged[sid] = true
			}
		}
	}
}

// isPrivilegedUser reports whether a user is AdminSDHolder-protected.
func isPrivilegedUser(o *adws.Object) bool { return intOf(o, "adminCount") == 1 }

// isPrivilegedSID reports whether a SID is a known privileged principal.
func (s *Snapshot) isPrivilegedSID(sid string) bool { return s.privileged[sid] }

// --- object accessors ---

func txt(o *adws.Object, attr string) string {
	if o == nil {
		return ""
	}
	return o.First(attr)
}

func intOf(o *adws.Object, attr string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(txt(o, attr)), 10, 64)
	return n
}

func firstBin(o *adws.Object, attr string) []byte {
	if o == nil {
		return nil
	}
	if v := o.Attributes[attr]; len(v) > 0 && v[0].IsBinary {
		return v[0].Binary
	}
	return nil
}

func binVals(o *adws.Object, attr string) [][]byte {
	if o == nil {
		return nil
	}
	var out [][]byte
	for _, v := range o.Attributes[attr] {
		if v.IsBinary {
			out = append(out, v.Binary)
		}
	}
	return out
}

func textVals(o *adws.Object, attr string) []string {
	if o == nil {
		return nil
	}
	var out []string
	for _, v := range o.Attributes[attr] {
		out = append(out, v.Text)
	}
	return out
}

func has(o *adws.Object, attr string) bool { return o != nil && len(o.Attributes[attr]) > 0 }

func sidText(o *adws.Object, attr string) string {
	if b := firstBin(o, attr); b != nil {
		return addecode.SIDToString(b)
	}
	return ""
}

func objSID(o *adws.Object) string { return sidText(o, "objectSid") }

func uacOf(o *adws.Object) addecode.UAC {
	return addecode.ParseUAC(uint32(intOf(o, "userAccountControl")))
}

// affectedOf builds an Affected from an object.
func affectedOf(o *adws.Object) Affected {
	return Affected{
		DistinguishedName: txt(o, "distinguishedName"),
		ObjectSID:         objSID(o),
		SAMAccountName:    txt(o, "sAMAccountName"),
	}
}

// pwdAgeDays returns the age of pwdLastSet in days and whether it is set.
func (s *Snapshot) pwdAgeDays(o *adws.Object) (int64, bool) {
	t, ok := addecode.ParseFileTime(txt(o, "pwdLastSet"))
	if !ok || t.Year() == 1601 {
		return 0, false
	}
	return int64(s.Cfg.Now.Sub(t) / (24 * time.Hour)), true
}

func queryFirst(q Querier, base, filter string, attrs []string) (*adws.Object, error) {
	objs, err := q.Query(base, filter, attrs)
	if err != nil {
		return nil, err
	}
	if len(objs) == 0 {
		return nil, nil
	}
	return objs[0], nil
}
