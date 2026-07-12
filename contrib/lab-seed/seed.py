#!/usr/bin/env python3
"""
Seed a test domain with deliberate AD misconfigurations so that
go-adrecon's read-only audit engine has a "messy" directory to detect.

Techniques are drawn from the well-known vulnerable-AD project
(https://github.com/safebuffer/vulnerable-AD) and mapped one-to-one onto the
audit rules (rule IDs noted inline).

Transport notes (all from Linux, no LDAPS — this lab DC has no ADCS cert):
  * Object/attribute writes and DACL edits go over impacket's NTLM LDAP (389).
  * unicodePwd writes need a confidential channel we don't have, so enabled
    USERS are enabled via the PASSWD_NOTREQD trick (no password needed), and
    COMPUTERS that must be enabled are created with addcomputer.py -method SAMR
    (password handled inside the SMB/SAMR layer).
  * impacket's NTLM needs OpenSSL's legacy provider (MD4) — run via ./run.sh.

FOR AUTHORIZED LAB USE ONLY.
"""
import json
import os
import subprocess
import sys

from impacket.ldap import ldap, ldapasn1, ldaptypes

def _require(name):
    v = os.environ.get(name)
    if not v:
        sys.exit(
            "error: set the target via environment variables:\n"
            "  ADIT_DC=<dc-ip-or-host> ADIT_DOMAIN=<domain.fqdn> ADIT_PASS=<password> \\\n"
            "  [ADIT_USER=administrator] [ADIT_SEED_PASS=...] ./run.sh seed.py"
        )
    return v


# Target read from the environment — nothing about the lab is hard-coded.
DC_IP = _require("ADIT_DC")
DOMAIN = _require("ADIT_DOMAIN")
USER = os.environ.get("ADIT_USER", "administrator")
PW = _require("ADIT_PASS")
SEED_PW = os.environ.get("ADIT_SEED_PASS", "Seedp@ss!" + "2026")
BASE = ",".join("DC=%s" % p for p in DOMAIN.split("."))

HERE = os.path.dirname(os.path.abspath(__file__))
BACKUP_DIR = os.path.join(HERE, "backups")
STATE_FILE = os.path.join(HERE, "state.json")
DACLEDIT = os.path.expanduser("~/.local/bin/dacledit.py")
RBCD = os.path.expanduser("~/.local/bin/rbcd.py")
ADDCOMPUTER = os.path.expanduser("~/.local/bin/addcomputer.py")
IDENT = "%s/%s:%s" % (DOMAIN, USER, PW)

# userAccountControl flag values.
UAC_DISABLED = 0x0002
UAC_NORMAL = 0x0200
UAC_WORKSTATION = 0x1000
UAC_PASSWD_NOTREQD = 0x0020
UAC_TRUSTED_FOR_DELEG = 0x80000
UAC_USE_DES_KEY_ONLY = 0x200000
UAC_DONT_REQ_PREAUTH = 0x400000
# "Enabled without a password" = NORMAL + PASSWD_NOTREQD, disabled bit clear.
UAC_ENABLED_NOPW = UAC_NORMAL | UAC_PASSWD_NOTREQD

state = {"users": [], "computers": [], "acls": [], "domain": {}}


def connect():
    l = ldap.LDAPConnection("ldap://%s" % DC_IP, baseDN=BASE)
    l.login(user=USER, password=PW, domain=DOMAIN)
    return l


def search(l, filt, attrs, base=BASE):
    out = []
    for item in l.search(searchBase=base, searchFilter=filt, attributes=attrs):
        if not isinstance(item, ldapasn1.SearchResultEntry):
            continue
        d = {"dn": str(item["objectName"])}
        for a in item["attributes"]:
            d[str(a["type"])] = [bytes(v) for v in a["vals"]]
        out.append(d)
    return out


def sid_str(raw):
    s = ldaptypes.LDAP_SID()
    s.fromString(raw)
    return s.formatCanonical()


def exists(l, sam):
    return bool(search(l, "(sAMAccountName=%s)" % sam, ["distinguishedName"]))


def log(msg):
    print("  " + msg)


def add_user(l, sam, uac, spn=None):
    dn = "CN=%s,CN=Users,%s" % (sam, BASE)
    if exists(l, sam):
        log("user %s exists — reusing" % sam)
    else:
        l.add(dn, ("top", "person", "organizationalPerson", "user"),
              {"sAMAccountName": sam, "userPrincipalName": "%s@%s" % (sam, DOMAIN),
               "displayName": sam})
        log("created user %s" % sam)
    if dn not in state["users"]:
        state["users"].append(dn)
    l.modify(dn, {"userAccountControl": [(2, uac)]})
    if spn:
        l.modify(dn, {"servicePrincipalName": [(2, spn)]})
    return dn


def run(cmd, quiet=False):
    r = subprocess.run(cmd, capture_output=True, text=True, env=os.environ.copy())
    if r.returncode != 0 and not quiet:
        print(r.stdout)
        print(r.stderr, file=sys.stderr)
        raise SystemExit("command failed: %s" % " ".join(cmd))
    return r.stdout


def add_computer(l, sam, extra_uac=0, os_name=None):
    dn = "CN=%s,CN=Computers,%s" % (sam[:-1], BASE)
    if not exists(l, sam):
        run([sys.executable, ADDCOMPUTER, "-computer-name", sam, "-computer-pass", SEED_PW,
             "-method", "SAMR", "-dc-ip", DC_IP, IDENT])
        log("created computer %s (SAMR)" % sam)
    else:
        log("computer %s exists — reusing" % sam)
    if dn not in state["computers"]:
        state["computers"].append(dn)
    if extra_uac:
        l.modify(dn, {"userAccountControl": [(2, UAC_WORKSTATION | extra_uac)]})
    if os_name:
        l.modify(dn, {"operatingSystem": [(2, os_name)],
                      "operatingSystemVersion": [(2, "5.2 (3790)")]})
    return dn


def dacl_grant(l, target_dn, rights, tag):
    backup = os.path.join(BACKUP_DIR, "%s.bak" % tag)
    run([sys.executable, DACLEDIT, "-action", "backup", "-target-dn", target_dn,
         "-file", backup, "-dc-ip", DC_IP, IDENT])
    run([sys.executable, DACLEDIT, "-action", "write", "-principal", "seed_lowpriv",
         "-target-dn", target_dn, "-rights", rights, "-dc-ip", DC_IP, IDENT])
    state["acls"].append({"target_dn": target_dn, "rights": rights, "backup": backup})
    log("granted seed_lowpriv %s on %s" % (rights, target_dn.split(",")[0]))


def main():
    print("[*] connecting to %s (impacket NTLM LDAP)…" % DC_IP)
    l = connect()
    dom = search(l, "(objectClass=domainDNS)", ["objectSid", "pwdProperties"])[0]
    print("[+] domain SID %s" % sid_str(dom["objectSid"][0]))

    print("[*] AD-DOM-008: reversible password encryption domain-wide")
    orig = int(dom["pwdProperties"][0].decode())
    state["domain"]["pwdProperties_orig"] = orig
    l.modify(BASE, {"pwdProperties": [(2, orig | 0x10)]})
    log("pwdProperties %d -> %d" % (orig, orig | 0x10))

    print("[*] creating seed principals")
    add_user(l, "seed_lowpriv", UAC_ENABLED_NOPW)                                    # ACL/DCSync grantee
    add_user(l, "seed_svc", UAC_ENABLED_NOPW, spn=["HTTP/seed-svc." + DOMAIN])       # AD-USR-002
    add_user(l, "seed_asrep", UAC_ENABLED_NOPW | UAC_DONT_REQ_PREAUTH)               # AD-USR-001
    add_user(l, "seed_notreqd", UAC_ENABLED_NOPW)                                    # AD-USR-005
    add_user(l, "seed_deskey", UAC_NORMAL | UAC_DISABLED | UAC_USE_DES_KEY_ONLY)     # AD-USR-009
    pgid_dn = add_user(l, "seed_pgid", UAC_ENABLED_NOPW)                             # AD-GRP-020

    print("[*] AD-GRP-020: hidden Domain Admin via primaryGroupID")
    da_dn = "CN=Domain Admins,CN=Users,%s" % BASE
    try:
        l.modify(da_dn, {"member": [(0, pgid_dn)]})
        log("added seed_pgid to Domain Admins")
    except ldap.LDAPSessionError as e:
        log("Domain Admins membership: %s" % e)
    l.modify(pgid_dn, {"primaryGroupID": [(2, 512)]})
    log("set seed_pgid primaryGroupID=512")

    print("[*] creating seed computers")
    add_computer(l, "SEED-UNCON$", extra_uac=UAC_TRUSTED_FOR_DELEG)                  # AD-CMP-006
    add_computer(l, "SEED-RBCD$")                                                    # AD-CMP-008
    add_computer(l, "SEED-LEGACY$", os_name="Windows Server 2003")                   # AD-CMP-012

    print("[*] AD-CMP-008: resource-based constrained delegation on SEED-RBCD$")
    run([sys.executable, RBCD, "-delegate-to", "SEED-RBCD$", "-delegate-from", "SEED-UNCON$",
         "-action", "write", "-dc-ip", DC_IP, IDENT])
    log("SEED-UNCON$ may act on behalf of others to SEED-RBCD$")

    print("[*] granting dangerous control to seed_lowpriv (DACLs backed up first)")
    dacl_grant(l, BASE, "DCSync", "domain-root")                                     # AD-DOM-010
    dacl_grant(l, da_dn, "FullControl", "domain-admins")                             # AD-ACL-001
    dacl_grant(l, "CN=Administrator,CN=Users,%s" % BASE, "FullControl", "administrator")  # AD-ACL-001
    dacl_grant(l, "CN=AdminSDHolder,CN=System,%s" % BASE, "FullControl", "adminsdholder")  # AD-SDH-001

    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)
    l.close()
    print("[+] done. state -> %s" % STATE_FILE)
    print("[+] revert any time with:  ./run.sh revert.py")


if __name__ == "__main__":
    main()
