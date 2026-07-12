// Command adit is the entry point for the Go reimplementation of
// PyADRecon-ADWS: Active Directory reconnaissance over ADWS (TCP/9389).
//
// Implemented: MC-NMF framing, the MS-NNS (NTLM) security upgrade, the
// MC-NBFS/NBFSE binary-XML codec, the WS-Enumeration SOAP layer, and the first
// collectors (users, groups, computers) with CSV output. The tool
// authenticates, reads the RootDSE, and can either run a raw LDAP query or run
// collection modules that write ADRecon-style CSV files.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"adit/internal/adws"
	"adit/internal/audit"
	"adit/internal/collect"
	"adit/internal/nbfx"
	"adit/internal/nmf"
	"adit/internal/nns"
	"adit/internal/proxy"
	"adit/internal/report"
)

// version is set at build time via -ldflags "-X main.version=…".
var version = "dev"

// collectorNames is the run order for -collect all and -list-modules.
var collectorNames = []string{
	"forest", "domain", "trusts", "sites", "subnets", "schemahistory", "dcs",
	"users", "userspns", "groups", "computers", "computerspns", "ous", "gpos",
	"gplinks", "passwordpolicy", "fgpp", "dnszones", "dnsrecords", "printers",
	"kerberoastable", "asreproastable", "krbtgt", "gmsa", "dmsa", "adcs", "cas",
	"laps", "bitlocker", "protectedgroups", "groupmembers",
}

func main() {
	var (
		dc        = flag.String("dc", "", "domain controller hostname or IP (required)")
		fqdn      = flag.String("fqdn", "", "DC FQDN for the net.tcp via URI (defaults to -dc)")
		domain    = flag.String("d", "", "domain (e.g. DOMAIN.LOCAL)")
		user      = flag.String("u", "", "username")
		password  = flag.String("p", "", "password")
		ws        = flag.String("workstation", "", "NTLM workstation name (default empty)")
		authMode  = flag.String("auth", "ntlm", "authentication method: ntlm or kerberos")
		spn       = flag.String("spn", "", "Kerberos SPN override (default HTTP/<fqdn>)")
		ccache    = flag.String("ccache", "", "Kerberos credential cache path (or set KRB5CCNAME)")
		keytab    = flag.String("keytab", "", "Kerberos keytab path")
		krb5conf  = flag.String("krb5conf", "", "krb5.conf path (default KRB5_CONFIG or /etc/krb5.conf)")
		port      = flag.Int("port", 9389, "ADWS port")
		proxyURL  = flag.String("proxy", "", "route ADWS via a proxy: socks5://[user:pass@]host:port, socks4://, socks4a://, http://[user:pass@]host:port or https://")
		query     = flag.String("query", "", "raw LDAP filter to run (e.g. \"(objectClass=user)\")")
		attrs     = flag.String("attrs", "distinguishedName,sAMAccountName,objectClass", "comma-separated attributes for -query")
		base      = flag.String("base", "", "search base DN (defaults to RootDSE defaultNamingContext)")
		modules   = flag.String("collect", "", "comma-separated collectors, or 'all' (see -list-modules)")
		listMods  = flag.Bool("list-modules", false, "print the available collector names and exit")
		showVer   = flag.Bool("version", false, "print the version and exit")
		output    = flag.String("o", "", "output directory for CSV files (default: adit-<timestamp>)")
		noExcel   = flag.Bool("no-excel", false, "skip the XLSX workbook after collection")
		noHTML    = flag.Bool("no-html", false, "skip the HTML dashboard after collection")
		genExcel  = flag.String("generate-excel-from", "", "build an XLSX from an existing CSV directory and exit")
		genHTML   = flag.String("generate-html-from", "", "build the HTML dashboard from an existing CSV directory and exit")
		dormant   = flag.Int("dormant-days", 90, "lastLogon older than N days is dormant")
		pwdAge    = flag.Int("password-age", 180, "pwdLastSet older than N days is an old password")
		onlyEn    = flag.Bool("only-enabled", false, "only collect enabled users/computers")
		audit     = flag.Bool("audit", false, "run the read-only security audit engine and write findings")
		krbtgtAge = flag.Int("krbtgt-max-age", 180, "audit: krbtgt password older than N days is stale")
		privAge   = flag.Int("priv-pwd-max-age", 365, "audit: privileged password older than N days is stale")
		staleDays = flag.Int("stale-days", 90, "audit: account with no logon in N days is stale")
		pageSize  = flag.Int("page-size", 256, "ADWS Pull page size")
		timeout   = flag.Duration("timeout", 15*time.Second, "dial/handshake timeout")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("adit %s (%s/%s, %s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return
	}

	if *listMods {
		fmt.Println("available collectors:")
		fmt.Println("  " + strings.Join(collectorNames, ", "))
		return
	}

	if *genExcel != "" {
		out := *output
		if out == "" {
			out = "Adit-Report.xlsx"
		}
		if err := report.WriteXLSXFromCSV(*genExcel, out); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] wrote %s\n", out)
		return
	}

	if *genHTML != "" {
		out := *output
		if out == "" {
			out = "Adit-Report.html"
		}
		if err := report.WriteHTMLFromCSV(*genHTML, out, report.Meta{Domain: *domain, DC: *fqdn}); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] wrote %s\n", out)
		return
	}

	if *dc == "" {
		fmt.Fprintln(os.Stderr, "error: -dc is required")
		flag.Usage()
		os.Exit(2)
	}
	via := *fqdn
	if via == "" {
		via = *dc
	}

	cfg := config{
		host: *dc, fqdn: via, port: *port,
		domain: *domain, user: *user, password: *password, workstation: *ws,
		authMode: *authMode, spn: *spn, ccache: *ccache, keytab: *keytab, krb5conf: *krb5conf,
		query: *query, attrs: splitAttrs(*attrs), base: *base,
		modules: splitList(*modules), output: *output, noExcel: *noExcel, noHTML: *noHTML,
		dormantDays: *dormant, passwordAge: *pwdAge, onlyEnabled: *onlyEn,
		pageSize: *pageSize, timeout: *timeout, proxy: *proxyURL,
		audit: *audit, krbtgtMaxAge: *krbtgtAge, privPwdMaxAge: *privAge, staleDays: *staleDays,
	}
	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

type config struct {
	host, fqdn            string
	port                  int
	domain, user          string
	password, workstation string
	authMode, spn         string
	ccache, keytab        string
	krb5conf              string
	query, base           string
	attrs                 []string
	modules               []string
	output                string
	noExcel               bool
	noHTML                bool
	dormantDays           int
	passwordAge           int
	onlyEnabled           bool
	pageSize              int
	timeout               time.Duration
	proxy                 string
	dial                  nmf.DialFunc
	audit                 bool
	krbtgtMaxAge          int
	privPwdMaxAge         int
	staleDays             int
}

func run(cfg config) error {
	auth, err := authenticator(cfg)
	if err != nil {
		return err
	}
	dialer, err := proxy.New(cfg.proxy, cfg.timeout)
	if err != nil {
		return err
	}
	cfg.dial = dialer.Dial
	fmt.Printf("[*] connecting to %s:%d (%s auth, via %q)\n", cfg.host, cfg.port, cfg.authMode, cfg.fqdn)
	if cfg.proxy != "" {
		fmt.Printf("[*] tunnelling through %s\n", dialer.Describe())
	}

	// RootDSE is a WS-Transfer Get on the Resource endpoint. WCF's AddressFilter
	// requires the SOAP To to match the connected endpoint, so RootDSE and the
	// Enumerate/Pull queries use separate connections.
	resConn, err := dialConnect(cfg, auth, "Windows/Resource")
	if err != nil {
		return err
	}
	fmt.Println("[+] authenticated (NMF + NNS handshake complete)")
	rd, err := adws.NewClient(resConn, cfg.fqdn, cfg.pageSize).RootDSE()
	resConn.Close()
	if err != nil {
		return fmt.Errorf("RootDSE: %w", err)
	}
	fmt.Printf("[+] RootDSE:\n    defaultNamingContext:       %s\n    configurationNamingContext: %s\n    schemaNamingContext:        %s\n",
		rd.DefaultNamingContext, rd.ConfigurationNamingContext, rd.SchemaNamingContext)

	base := cfg.base
	if base == "" {
		base = rd.DefaultNamingContext
	}

	// The Enumeration endpoint serves Enumerate/Pull for queries and collectors.
	conn, err := dialConnect(cfg, auth, "Windows/Enumeration")
	if err != nil {
		return err
	}
	defer conn.Close()
	client := adws.NewClient(conn, cfg.fqdn, cfg.pageSize)

	switch {
	case len(cfg.modules) > 0:
		outDir := resolveOutDir(cfg)
		var extra []*collect.Table
		if cfg.audit {
			t, err := runAudit(client, base, rd, cfg, outDir)
			if err != nil {
				return err
			}
			extra = append(extra, t)
		}
		return runCollectors(client, base, rd, cfg, outDir, extra)
	case cfg.audit:
		_, err := runAudit(client, base, rd, cfg, resolveOutDir(cfg))
		return err
	case cfg.query != "":
		return runQuery(client, base, cfg)
	default:
		fmt.Println("    (pass -collect, -audit or -query to gather data)")
		return nil
	}
}

// resolveOutDir returns the configured output directory, or a timestamped default.
func resolveOutDir(cfg config) string {
	if cfg.output != "" {
		return cfg.output
	}
	return "adit-" + time.Now().Format("20060102-150405")
}

// runAudit loads a directory snapshot over ADWS and evaluates the read-only
// audit rules, writing a JSON findings report and printing a summary. It
// returns the findings as a table for inclusion in the dashboard/workbook.
func runAudit(client *adws.Client, base string, rd *adws.RootDSE, cfg config, outDir string) (*collect.Table, error) {
	fmt.Println("[*] running read-only security audit")
	snap, err := audit.Load(client, base, rd.ConfigurationNamingContext, audit.Config{
		KrbtgtMaxAgeDays:  cfg.krbtgtMaxAge,
		PrivPwdMaxAgeDays: cfg.privPwdMaxAge,
		StaleDays:         cfg.staleDays,
	})
	if err != nil {
		return nil, fmt.Errorf("audit load: %w", err)
	}
	res := audit.Run(snap)

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	path := outDir + "/Adit-Audit.json"
	rep := audit.NewReport(version, cfg.domain, base, time.Now().UTC(), res)
	if err := rep.WriteJSON(path); err != nil {
		return nil, fmt.Errorf("write audit json: %w", err)
	}

	c := res.Counts
	fmt.Printf("[+] audit complete: %d findings from %d rules (Critical %d, High %d, Medium %d, Low %d)\n",
		c.Total, res.Rules, c.Critical, c.High, c.Medium, c.Low)
	fmt.Printf("[+] audit report: %s\n", path)
	return auditTable(res), nil
}

// auditTable converts audit findings into a report table. The "Risk Level"
// column drives the dashboard's severity badges.
func auditTable(res audit.Result) *collect.Table {
	t := &collect.Table{
		Name:    "Audit Findings",
		Headers: []string{"Risk Level", "Rule", "Title", "Category", "Object", "Evidence", "Remediation"},
	}
	for _, f := range res.Findings {
		obj := ""
		if len(f.Affected) > 0 {
			a := f.Affected[0]
			switch {
			case a.SAMAccountName != "":
				obj = a.SAMAccountName
			case a.DistinguishedName != "":
				obj = a.DistinguishedName
			default:
				obj = a.ObjectSID
			}
		}
		var ev []string
		for k, v := range f.Evidence {
			ev = append(ev, k+"="+v)
		}
		sort.Strings(ev)
		t.Rows = append(t.Rows, []string{
			severityLabel(f.Severity), f.RuleID, f.Title, f.Category,
			obj, strings.Join(ev, "; "), f.Remediation,
		})
	}
	return t
}

// severityLabel maps a severity to the uppercase label the dashboard colours.
func severityLabel(s audit.Severity) string {
	switch s {
	case audit.Critical:
		return "CRITICAL"
	case audit.High:
		return "HIGH"
	case audit.Medium:
		return "MEDIUM"
	case audit.Low:
		return "LOW"
	default:
		return "INFO"
	}
}

// dialConnect dials the DC, performs the NMF preamble + NNS auth for the given
// endpoint resource, and clears the handshake deadline for long-running work.
func dialConnect(cfg config, auth nmf.Authenticator, resource string) (*nmf.Conn, error) {
	conn, err := nmf.Dial(cfg.host, cfg.port, cfg.fqdn, auth, nbfx.New(nbfx.NBFSE), cfg.timeout, cfg.dial)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(cfg.timeout))
	if err := conn.Connect(resource); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// authenticator builds the NMF authenticator for the configured auth method.
func authenticator(cfg config) (nmf.Authenticator, error) {
	switch strings.ToLower(cfg.authMode) {
	case "", "ntlm":
		if cfg.user == "" {
			return nil, fmt.Errorf("-u is required for NTLM auth")
		}
		return nns.NewNTLM(cfg.domain, cfg.user, cfg.password, cfg.workstation), nil
	case "kerberos":
		return nns.NewKerberos(nns.KerberosConfig{
			Realm: cfg.domain, Username: cfg.user, Password: cfg.password,
			KDC: cfg.host, FQDN: cfg.fqdn, SPN: cfg.spn,
			CCachePath: cfg.ccache, KeytabPath: cfg.keytab, ConfigPath: cfg.krb5conf,
		}), nil
	default:
		return nil, fmt.Errorf("unknown -auth %q (want ntlm or kerberos)", cfg.authMode)
	}
}

func runQuery(client *adws.Client, base string, cfg config) error {
	fmt.Printf("[*] querying %q under %s ...\n", cfg.query, base)
	objects, err := client.Query(base, cfg.query, cfg.attrs)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	fmt.Printf("[+] %d object(s):\n", len(objects))
	for _, obj := range objects {
		printObject(obj, cfg.attrs)
	}
	return nil
}

func runCollectors(client *adws.Client, base string, rd *adws.RootDSE, cfg config, outDir string, extra []*collect.Table) error {
	col := collect.New(client, base, collect.Config{
		DormantDays:     cfg.dormantDays,
		PasswordAgeDays: cfg.passwordAge,
		OnlyEnabled:     cfg.onlyEnabled,
		ConfigDN:        rd.ConfigurationNamingContext,
		SchemaDN:        rd.SchemaNamingContext,
		RootDomainDN:    rd.RootDomainNamingContext,
	})
	registry := map[string]func() (*collect.Table, error){
		"forest":          col.Forest,
		"domain":          col.Domain,
		"trusts":          col.Trusts,
		"sites":           col.Sites,
		"subnets":         col.Subnets,
		"schemahistory":   col.SchemaHistory,
		"dcs":             col.DomainControllers,
		"users":           col.Users,
		"userspns":        col.UserSPNs,
		"groups":          col.Groups,
		"computers":       col.Computers,
		"computerspns":    col.ComputerSPNs,
		"ous":             col.OUs,
		"gpos":            col.GPOs,
		"gplinks":         col.GPLinks,
		"passwordpolicy":  col.PasswordPolicy,
		"fgpp":            col.FGPP,
		"dnszones":        col.DNSZones,
		"kerberoastable":  col.Kerberoastable,
		"asreproastable":  col.ASREPRoastable,
		"krbtgt":          col.KRBTGT,
		"adcs":            col.CertificateTemplates,
		"cas":             col.CertificateAuthorities,
		"laps":            col.LAPS,
		"protectedgroups": col.ProtectedGroups,
		"groupmembers":    col.GroupMembers,
		"dnsrecords":      col.DNSRecords,
		"gmsa":            col.GMSA,
		"dmsa":            col.DMSA,
		"printers":        col.Printers,
		"bitlocker":       col.BitLocker,
	}
	order := collectorNames

	modules := cfg.modules
	if len(modules) == 1 && modules[0] == "all" {
		modules = order
	}

	csvDir := outDir + "/CSV-Files"

	var tables []*collect.Table
	for _, m := range modules {
		fn, ok := registry[strings.ToLower(m)]
		if !ok {
			fmt.Printf("[!] unknown collector %q (have: %s)\n", m, strings.Join(order, ", "))
			continue
		}
		fmt.Printf("[*] collecting %s ...\n", m)
		tbl, err := fn()
		if err != nil {
			return fmt.Errorf("collect %s: %w", m, err)
		}
		path, err := tbl.WriteCSV(csvDir)
		if err != nil {
			return fmt.Errorf("write %s: %w", m, err)
		}
		tables = append(tables, tbl)
		fmt.Printf("[+] %s: %d rows -> %s\n", tbl.Name, len(tbl.Rows), path)
	}

	// Audit findings (and any other extra tables) join the same report.
	for _, tbl := range extra {
		if _, err := tbl.WriteCSV(csvDir); err != nil {
			return fmt.Errorf("write %s: %w", tbl.Name, err)
		}
		tables = append(tables, tbl)
	}

	if !cfg.noExcel && len(tables) > 0 {
		xlsx := outDir + "/Adit-Report.xlsx"
		if err := report.WriteXLSX(tables, xlsx); err != nil {
			return fmt.Errorf("write xlsx: %w", err)
		}
		fmt.Printf("[+] workbook:  %s\n", xlsx)
	}
	if !cfg.noHTML && len(tables) > 0 {
		htmlPath := outDir + "/Adit-Report.html"
		if err := report.WriteHTML(tables, report.Meta{Domain: cfg.domain, DC: cfg.fqdn}, htmlPath); err != nil {
			return fmt.Errorf("write html: %w", err)
		}
		fmt.Printf("[+] dashboard: %s\n", htmlPath)
	}
	return nil
}

func printObject(obj *adws.Object, attrs []string) {
	fmt.Printf("  - %s\n", obj.DN())
	for _, a := range attrs {
		if a == "distinguishedName" {
			continue
		}
		vals := obj.Attributes[a]
		if len(vals) == 0 {
			continue
		}
		parts := make([]string, len(vals))
		for i, v := range vals {
			if v.IsBinary {
				parts[i] = fmt.Sprintf("<%d bytes>", len(v.Binary))
			} else {
				parts[i] = v.Text
			}
		}
		fmt.Printf("      %s: %s\n", a, strings.Join(parts, ", "))
	}
}

// splitList parses a comma-separated, whitespace-trimmed list.
func splitList(s string) []string {
	var out []string
	for _, a := range strings.Split(s, ",") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// splitAttrs parses the comma-separated attribute list and guarantees
// distinguishedName is selected (as the reference always does).
func splitAttrs(s string) []string {
	out := []string{"distinguishedName"}
	seen := map[string]bool{"distinguishedName": true}
	for _, a := range strings.Split(s, ",") {
		if a = strings.TrimSpace(a); a != "" && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}
