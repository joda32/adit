# lab-seed — deliberately break a test domain

Seeds a **disposable test DC** with intentional AD misconfigurations so
`adit -audit` has a messy directory to detect. Techniques are drawn from
[vulnerable-AD](https://github.com/safebuffer/vulnerable-AD) and mapped
one-to-one onto the audit rules.

> **Authorized lab use only.** This writes attacker-grade misconfigurations
> (DCSync rights, AdminSDHolder control, unconstrained delegation, …) into a
> live domain. Only run it against a throwaway lab you own.

## Configuration

Nothing about the target is hard-coded — it is read from the environment:

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `ADIT_DC` | yes | — | DC IP or hostname |
| `ADIT_DOMAIN` | yes | — | domain FQDN, e.g. `lab.example` (BASE DN is derived) |
| `ADIT_PASS` | yes | — | password for the admin account |
| `ADIT_USER` | no | `administrator` | admin account used to write |
| `ADIT_SEED_PASS` | no | built-in | password set on created seed accounts |

## Usage

```bash
export ADIT_DC=10.0.0.10 ADIT_DOMAIN=lab.example ADIT_PASS='<password>'
./run.sh seed.py      # introduce the misconfigurations
./run.sh revert.py    # undo everything (restore DACLs, pwdProperties, delete seed objects)
```

`run.sh` sets `OPENSSL_CONF` to enable OpenSSL 3's *legacy* provider — impacket's
NTLM needs MD4, which is disabled by default on modern OpenSSL. Everything runs
from Linux; if the DC has no LDAPS certificate, writes go over impacket's NTLM
LDAP (389), password-required steps are avoided via the `PASSWD_NOTREQD` enable
trick (users) and `addcomputer -method SAMR` (computers).

Requires impacket's example scripts on `PATH`/`~/.local/bin`
(`dacledit.py`, `rbcd.py`, `addcomputer.py`).

## What it introduces → which rule fires

| Object / change | Audit rule | Severity |
|---|---|---|
| `seed_lowpriv` granted DS-Replication-Get-Changes-All on domain root | AD-DOM-010 (DCSync) | Critical |
| `seed_lowpriv` FullControl on Domain Admins + Administrator | AD-ACL-006 (WriteDACL)\* | Critical |
| `seed_lowpriv` FullControl on AdminSDHolder | AD-SDH-001 | Critical |
| domain `pwdProperties` reversible-encryption bit | AD-DOM-008 | High |
| `seed_asrep` DONT_REQ_PREAUTH | AD-USR-001 | High |
| `seed_deskey` USE_DES_KEY_ONLY | AD-USR-009 | High |
| `SEED-UNCON$` TRUSTED_FOR_DELEGATION | AD-CMP-006 | High |
| `SEED-RBCD$` msDS-AllowedToActOnBehalfOfOtherIdentity | AD-CMP-008 | Medium |
| `SEED-LEGACY$` operatingSystem = Windows Server 2003 | AD-CMP-012 | Medium |
| `seed_pgid` member of Domain Admins + primaryGroupID=512 | AD-GRP-020 | Medium |
| `seed_svc` servicePrincipalName | AD-USR-002 | Medium |
| enabled seed users carry PASSWD_NOTREQD (enable trick side effect) | AD-USR-005 | Medium |

\* `dacledit`'s "FullControl" mask expands to `0xF01FF`, which the engine
classifies as WriteDACL rather than the generic-all bit — still a Critical
dangerous-control finding on a privileged object.

## Files

- `seed.py` / `revert.py` — apply / undo
- `run.sh` — wrapper that enables the OpenSSL legacy provider
- `openssl-legacy.cnf` — legacy + default provider config
- `state.json` — records what was changed (written by seed, read by revert; git-ignored)
- `backups/*.bak` — original DACLs captured before each ACL edit (git-ignored)
