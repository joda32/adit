#!/usr/bin/env python3
"""
Undo seed.py:
  - restore each modified DACL from its backup (dacledit -action restore)
  - restore the domain pwdProperties value from state.json
  - delete every seed object (matched by name prefix, so partial runs clean up too)

Run via ./run.sh revert.py (sets OPENSSL_CONF for impacket's MD4).
FOR AUTHORIZED LAB USE ONLY.
"""
import json
import os
import subprocess
import sys

from impacket.ldap import ldap, ldapasn1

def _require(name):
    v = os.environ.get(name)
    if not v:
        sys.exit(
            "error: set the target via environment variables:\n"
            "  ADIT_DC=<dc-ip-or-host> ADIT_DOMAIN=<domain.fqdn> ADIT_PASS=<password> \\\n"
            "  [ADIT_USER=administrator] ./run.sh revert.py"
        )
    return v


DC_IP = _require("ADIT_DC")
DOMAIN = _require("ADIT_DOMAIN")
USER = os.environ.get("ADIT_USER", "administrator")
PW = _require("ADIT_PASS")
BASE = ",".join("DC=%s" % p for p in DOMAIN.split("."))
IDENT = "%s/%s:%s" % (DOMAIN, USER, PW)

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(HERE, "state.json")
DACLEDIT = os.path.expanduser("~/.local/bin/dacledit.py")


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, env=os.environ.copy())
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr, file=sys.stderr)
        print("  [!] failed (continuing): %s" % " ".join(cmd))


def find_seed_dns(l):
    dns = []
    flt = "(|(sAMAccountName=seed_*)(sAMAccountName=SEED-*))"
    for item in l.search(searchBase=BASE, searchFilter=flt, attributes=["distinguishedName"]):
        if isinstance(item, ldapasn1.SearchResultEntry):
            dns.append(str(item["objectName"]))
    return dns


def main():
    state = {}
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            state = json.load(f)

    l = ldap.LDAPConnection("ldap://%s" % DC_IP, baseDN=BASE)
    l.login(user=USER, password=PW, domain=DOMAIN)
    print("[*] connected")

    print("[*] restoring modified DACLs")
    for acl in state.get("acls", []):
        if os.path.exists(acl["backup"]):
            run([sys.executable, DACLEDIT, "-action", "restore", "-target-dn", acl["target_dn"],
                 "-file", acl["backup"], "-dc-ip", DC_IP, IDENT])
            print("  restored DACL on %s" % acl["target_dn"].split(",")[0])

    if "pwdProperties_orig" in state.get("domain", {}):
        orig = state["domain"]["pwdProperties_orig"]
        l.modify(BASE, {"pwdProperties": [(2, orig)]})
        print("[*] restored domain pwdProperties -> %d" % orig)

    print("[*] deleting seed objects")
    for dn in find_seed_dns(l):
        try:
            l.delete(dn)
            print("  deleted %s" % dn.split(",")[0])
        except ldap.LDAPSessionError as e:
            print("  [!] could not delete %s: %s" % (dn.split(",")[0], e))

    l.close()
    print("[+] revert complete")


if __name__ == "__main__":
    main()
