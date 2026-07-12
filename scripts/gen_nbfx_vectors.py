"""Generate NBFS/NBFX golden vectors from the PyADRecon-ADWS reference encoder.

Usage: point PYADRECON at a checkout of PyADRecon-ADWS, then run:
    PYADRECON=/path/to/PyADRecon-ADWS python3 scripts/gen_nbfx_vectors.py
The hex/xml it prints is copied into internal/nbfx/nbfx_test.go.
"""
import os, sys, binascii
sys.path.insert(0, os.environ.get("PYADRECON", "/home/willem/lab/tools/adrecon/PyADRecon-ADWS"))
from helpers.adws.encoder import Encoder

H = lambda b: binascii.hexlify(b).decode()
enc = Encoder(0x08)  # NBFSE, as used on the wire

UUID = "11111111-2222-3333-4444-555555555555"
FQDN = "dc01.domain.local"

# Real templates (trimmed to the exact strings the reference formats & sends).
from helpers.adws.soap_templates import (
    LDAP_ROOT_DSE_FSTRING, LDAP_QUERY_FSTRING, LDAP_PULL_FSTRING,
)

rootdse = LDAP_ROOT_DSE_FSTRING.format(uuid=UUID, fqdn=FQDN)

attrs = "".join(
    f"<ad:SelectionProperty>addata:{a}</ad:SelectionProperty>\n"
    for a in ["distinguishedName", "objectClass", "sAMAccountName"]
)
query = LDAP_QUERY_FSTRING.format(
    uuid=UUID, fqdn=FQDN, query="(objectClass=user)",
    attributes=attrs, baseobj="DC=domain,DC=local",
)
pull = LDAP_PULL_FSTRING.format(
    uuid=UUID, fqdn=FQDN, enum_ctx="00000000-0000-0000-0000-000000000000", max_elements=256,
)

cases = {
    "simple": "<a>hello</a>",
    "nested": "<Envelope><Header></Header><Body>x</Body></Envelope>",
    "attrs": '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body></s:Body></s:Envelope>',
    "base64val": '<ad:controlValue>MIQAAAADAgEH</ad:controlValue>',
    "intval": "<n>1234</n>",
    "rootdse": rootdse,
    "query": query,
    "pull": pull,
}

print("# name | encoded-hex | decoded-xml")
for name, xml in cases.items():
    encoded = enc.encode(xml)
    # decode uses a fresh encoder to avoid the print() side effects interfering
    decoded = Encoder(0x08).decode(encoded)
    print(f"CASE {name}")
    print(f"  XML {xml!r}")
    print(f"  ENC {H(encoded)}")
    print(f"  DEC {decoded!r}")
