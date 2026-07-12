# adit

**adit** is a single-binary Active Directory reconnaissance **and** read-only
security-audit tool that talks to a Domain Controller over **ADWS (Active
Directory Web Services, TCP/9389)** instead of LDAP.

An *adit* is the horizontal entrance to a mine — the quiet way in. Querying AD
through ADWS rather than LDAP/389 means the traffic is WCF `net.tcp` framed,
binary-XML SOAP over an uncommon port, so it is far less likely to be inspected,
filtered, or signatured than classic LDAP — while still returning the same
directory data. adit implements the full ADWS protocol stack in Go, with no
external runtime dependencies.

```
┌────────────┐   net.tcp/9389   ┌──────────────┐
│   adit     │ ───────────────▶ │  ADWS on DC  │ ──▶ local LDAP
│  (Linux)   │   NMF · NNS ·    │  (port 9389) │
│            │   NBFSE · SOAP   └──────────────┘
└────────────┘
```

- **Recon** — 31 collectors export the directory to CSV, a styled XLSX workbook,
  and a self-contained HTML dashboard.
- **Audit** — a read-only findings engine evaluates 24 rules (DCSync, dangerous
  ACLs, AdminSDHolder, delegation, roasting, stale/legacy objects, …) and emits
  a severity-ranked JSON report that also leads the dashboard.
- **Reach** — route the whole thing through an HTTP CONNECT or SOCKS4/4a/5 proxy
  to audit a DC that is only reachable through a jump host.
- **Auth** — NTLM or Kerberos, fully hand-rolled (NTLMv2 sign+seal, RFC 4121
  sealed GSS Wrap), validated byte-for-byte against impacket.

> adit is a defensive/audit and authorized-assessment tool. Only run it against
> directories you are authorized to assess.

## Functionality

| Capability | Details |
|---|---|
| Transport | ADWS over WCF `net.tcp` (TCP/9389) — MC-NMF framing, MS-NNS handshake, MC-NBFS/NBFSE binary XML, WS-Enumeration/WS-Transfer SOAP |
| Authentication | NTLMv2 (sign + seal) and Kerberos (ccache / keytab / password; RFC 4121 sealed GSS) |
| Recon collectors | 31 modules (see below) → per-module CSV |
| Reporting | Styled multi-sheet **XLSX** workbook + self-contained **HTML dashboard** (search/sort, severity badges, scroll-spy) |
| Security audit | 24 read-only rules → severity-ranked **JSON**, also surfaced in the dashboard |
| Proxy / jump host | HTTP CONNECT, SOCKS5/5h, SOCKS4/4a (with proxy auth + remote DNS) |
| Paging | Server-side WS-Enumeration Pull paging, configurable page size |
| Offline reporting | Rebuild XLSX/HTML from previously collected CSVs, no DC needed |
| Dependencies | Pure Go; no LDAP library, no .NET, no external services |

### Collectors

`forest`, `domain`, `trusts`, `sites`, `subnets`, `schemahistory`, `dcs`,
`users`, `userspns`, `groups`, `computers`, `computerspns`, `ous`, `gpos`,
`gplinks`, `passwordpolicy`, `fgpp`, `dnszones`, `dnsrecords`, `kerberoastable`,
`asreproastable`, `krbtgt`, `adcs`, `cas`, `laps`, `protectedgroups`,
`groupmembers`, `gmsa`, `dmsa`, `printers`, `bitlocker`

ADCS (`adcs`) flags ESC1–ESC4/ESC9; `laps` reports who can read each password;
`protectedgroups` audits Protected Users. Run `adit -list-modules` for the
current list.

## Audit checks

`-audit` runs 24 read-only rules. Findings carry a rule id, severity, affected
objects, evidence, and remediation, and are written to `Adit-Audit.json` (and,
when combined with `-collect`, an "Audit Findings" section that leads the
dashboard). The engine never reads secret attribute values (LAPS / gMSA /
BitLocker), even though the recon collectors can.

| Rule | Severity | What it flags |
|---|---|---|
| AD-DOM-010 | Critical | DCSync (replication) rights held by a non-Tier-0 principal |
| AD-ACL-001/005/006/007/011–016 | Critical | Dangerous control (GenericAll/Write, WriteDACL/Owner, ForceChangePassword, Write SPN / KeyCredentialLink / member / AllowedToAct) over a privileged object |
| AD-SDH-001/002 | Critical | Unexpected control / owner of AdminSDHolder |
| AD-DOM-008 | High | Reversible password encryption enabled domain-wide |
| AD-USR-001 | High | Kerberos pre-auth disabled (AS-REP roastable) |
| AD-USR-009 | High | Account uses DES encryption only |
| AD-CMP-006 | High | Unconstrained delegation on a non-DC |
| AD-KCL-001 | High | Key Credential (shadow credential) on a privileged account |
| AD-KRB-001 | High | krbtgt password is stale |
| AD-DOM-005 | Medium | Machine Account Quota > 0 (any user can join computers) |
| AD-USR-002 | Medium | Kerberoastable service account (High if privileged) |
| AD-USR-005 | Medium | PASSWD_NOTREQD set |
| AD-USR-006 | Medium | Privileged account password never expires |
| AD-USR-011 | Medium | Privileged account password is stale |
| AD-CMP-008 | Medium | Resource-based constrained delegation configured |
| AD-CMP-012 | Medium | Legacy / unsupported operating system |
| AD-GRP-009 | Medium | Foreign security principal in a privileged group |
| AD-GRP-020 | Medium | Hidden privileged membership via primaryGroupID |
| AD-TRU-001/003 | High/Medium | Trust without SID filtering / with SID history |
| AD-DNS-003/004 | Medium/Low | WPAD / ISATAP record present |
| AD-CMP-011 | Low | Stale computer account |
| AD-INT-005 | High | sIDHistory contains a privileged SID |

Thresholds are tunable: `-krbtgt-max-age`, `-priv-pwd-max-age`, `-stale-days`.

## Getting it going

Requires **Go 1.26+**. No other build dependencies.

```bash
# Build the binary
go build -o adit ./cmd/adit
./adit -version

# …or run without installing
go run ./cmd/adit -h

# Cross-compile release archives for linux/windows/darwin (amd64+arm64) into dist/
bash scripts/build-release.sh
```

`-fqdn` must be the DC's **real FQDN** (not its IP): the ADWS SOAP `To` header is
matched against the endpoint by WCF's AddressFilter. Find it with, e.g.,
`nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain> <dc-ip>`.

## Usage

```
adit -dc <host> -fqdn <dc-fqdn> -d <DOMAIN> -u <user> -p <pass> [flags]
```

### Recon

```bash
# RootDSE handshake only (verifies auth + the full protocol stack)
adit -dc 10.0.0.10 -fqdn dc01.example.local -d EXAMPLE.LOCAL -u user -p 'pass'

# Run every collector -> ./report/CSV-Files/*.csv + Adit-Report.{xlsx,html}
adit -dc 10.0.0.10 -fqdn dc01.example.local -d EXAMPLE.LOCAL -u user -p 'pass' \
  -collect all -o ./report

# A subset of collectors
adit -dc 10.0.0.10 -fqdn dc01.example.local -d EXAMPLE.LOCAL -u user -p 'pass' \
  -collect users,groups,computers,kerberoastable
```

### Security audit

```bash
# Audit only -> Adit-Audit.json
adit -dc 10.0.0.10 -fqdn dc01.example.local -d EXAMPLE.LOCAL -u user -p 'pass' -audit

# Recon + audit: findings lead the XLSX + HTML dashboard
adit -dc 10.0.0.10 -fqdn dc01.example.local -d EXAMPLE.LOCAL -u user -p 'pass' \
  -collect all -audit -o ./report
```

### Kerberos

```bash
# Password (synthesises a krb5.conf from the domain + DC if none is present)
adit -dc 10.0.0.10 -fqdn dc01.example.local -d EXAMPLE.LOCAL -u user -p 'pass' -auth kerberos

# Existing ticket cache
KRB5CCNAME=/tmp/krb5cc_1000 adit -dc 10.0.0.10 -fqdn dc01.example.local \
  -d EXAMPLE.LOCAL -u user -auth kerberos -ccache /tmp/krb5cc_1000
```

### Through a jump host / proxy

ADWS is a *web service* but not HTTP — it rides raw TCP on 9389 — yet a proxy
still tunnels that TCP stream. Where the protocol allows (SOCKS5/4a, HTTP
CONNECT) the DC name is resolved **at the proxy**, so an internal-only name works.

```bash
# SSH dynamic forward = a local SOCKS5 proxy
ssh -D 1080 -N jump-host &
adit -dc dc01.corp.internal -fqdn dc01.corp.internal -d CORP.INTERNAL \
  -u user -p 'pass' -proxy socks5://127.0.0.1:1080 -collect all -audit -o ./report

# Other proxy forms
-proxy socks5://user:pass@127.0.0.1:1080   # SOCKS5 with username/password auth
-proxy socks4a://10.0.0.5:1080             # SOCKS4a (remote DNS)
-proxy http://user:pass@proxy.corp:8080    # HTTP CONNECT (Basic auth)
-proxy https://proxy.corp:8443             # HTTP CONNECT over TLS to the proxy
```

With `-auth kerberos` + password the KDC exchange still goes direct; over a jump
host obtain a ticket first and pass `-ccache` / `KRB5CCNAME`.

### Ad-hoc query & offline reporting

```bash
# Raw LDAP-filter query over ADWS, selecting attributes (paged automatically)
adit -dc 10.0.0.10 -fqdn dc01.example.local -d EXAMPLE.LOCAL -u user -p 'pass' \
  -query '(&(objectClass=user)(objectCategory=person))' \
  -attrs sAMAccountName,userAccountControl,objectSid

# Rebuild the workbook / dashboard from existing CSVs (no DC needed)
adit -generate-excel-from ./report/CSV-Files -o report.xlsx
adit -generate-html-from  ./report/CSV-Files -o report.html
```

Run `adit -h` for the full flag list.

## Layout

```
cmd/adit/          CLI entry point
internal/nmf/       MC-NMF framing: preamble, upgrade, sized envelopes
internal/ntlm/      NTLMv2 responses, key derivation, sign+seal session
internal/spnego/    SPNEGO NegTokenInit/Resp for carrying NTLM
internal/nns/       MS-NNS handshake + sealed transport (NTLM + Kerberos)
internal/krb5/      RFC 4121 GSS sealed Wrap/Unwrap (Kerberos message sealing)
internal/nbfx/      .NET Binary XML codec (MC-NBFS/NBFSE), encode + decode
internal/proxy/     HTTP CONNECT + SOCKS4/4a/5 dialer (route ADWS via a jump host)
internal/adws/      WS-Enumeration SOAP: RootDSE + Enumerate/Pull paging
internal/addecode/  attribute decoders: SID, GUID, FILETIME, UAC, groupType
internal/sd/        security-descriptor / ACL / ACE parser ([MS-DTYP])
internal/collect/   31 collection modules + CSV output
internal/audit/     read-only findings engine (24 rules) + JSON report
internal/report/    styled XLSX workbook + self-contained HTML dashboard
contrib/lab-seed/   optional: seed a throwaway lab with misconfigs to exercise -audit
```

## Testing

```bash
go build ./...
go test ./...
```

Every wire-format layer is validated **byte-for-byte against its reference** —
NTLM/NNS crypto against impacket, the NBFX codec against a reference encoder —
so security and serialization are verified without a live DC.

## Acknowledgements

adit reimplements, over ADWS and in Go, ideas from the AD-recon lineage —
[ADRecon](https://github.com/adrecon/ADRecon) for the collector/report model and
the SOAP/ADWS work of SoaPy, SOAPHound and SharpADWS. The audit rule set draws on
common AD misconfiguration research; lab-seed's techniques come from
[vulnerable-AD](https://github.com/safebuffer/vulnerable-AD).

## License

MIT — see [LICENSE](LICENSE).
