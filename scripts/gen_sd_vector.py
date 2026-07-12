"""Generate the security-descriptor golden vector in internal/sd/sd_test.go.

Builds a self-relative SD (owner/group + 3-ACE DACL, including a deny of the
Change-Password right to Everyone) with impacket and prints its bytes.

    python3 -m pip install --user impacket
    python3 scripts/gen_sd_vector.py
"""
import binascii
from impacket.ldap import ldaptypes as lt
from impacket.uuid import string_to_bin

H = lambda b: binascii.hexlify(b).decode()

def sid(s):
    x = lt.LDAP_SID(); x.fromCanonical(s); return x

def allowed_ace(mask, sidstr):
    a = lt.ACCESS_ALLOWED_ACE(); a['Mask'] = lt.ACCESS_MASK(); a['Mask']['Mask'] = mask; a['Sid'] = sid(sidstr)
    ace = lt.ACE(); ace['AceType'] = lt.ACCESS_ALLOWED_ACE.ACE_TYPE; ace['AceFlags'] = 0; ace['Ace'] = a
    return ace

def object_ace(acetype, cls, mask, guid, sidstr):
    a = cls(); a['Mask'] = lt.ACCESS_MASK(); a['Mask']['Mask'] = mask; a['Flags'] = 1
    a['ObjectType'] = string_to_bin(guid); a['InheritedObjectType'] = b''; a['Sid'] = sid(sidstr)
    ace = lt.ACE(); ace['AceType'] = acetype; ace['AceFlags'] = 0; ace['Ace'] = a
    return ace

CHANGE_PW = 'ab721a53-1e2f-11d0-9819-00aa0040529b'
dacl = lt.ACL(); dacl['AclRevision'] = 4; dacl['Sbz1'] = 0; dacl['Sbz2'] = 0
dacl.aces = [
    allowed_ace(0x10000000, 'S-1-5-21-1004336348-1177238915-682003330-512'),
    object_ace(lt.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE, lt.ACCESS_ALLOWED_OBJECT_ACE, 0x100, CHANGE_PW, 'S-1-5-10'),
    object_ace(lt.ACCESS_DENIED_OBJECT_ACE.ACE_TYPE, lt.ACCESS_DENIED_OBJECT_ACE, 0x100, CHANGE_PW, 'S-1-1-0'),
]
sd = lt.SR_SECURITY_DESCRIPTOR(); sd['Revision'] = b'\x01'; sd['Sbz1'] = b'\x00'; sd['Control'] = 0x8004
sd['OwnerSid'] = sid('S-1-5-21-1004336348-1177238915-682003330-512')
sd['GroupSid'] = sid('S-1-5-21-1004336348-1177238915-682003330-513')
sd['Sacl'] = b''; sd['Dacl'] = dacl
print("sdHex =", H(sd.getData()))


def esc1_template_sd():
    """ESC1 certificate-template SD used by internal/collect/adcs_test.go:
    Authenticated Users have Certificate-Enrollment; Domain Admins GenericAll."""
    ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
    dacl = lt.ACL(); dacl['AclRevision'] = 4; dacl['Sbz1'] = 0; dacl['Sbz2'] = 0
    dacl.aces = [
        object_ace(lt.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE, lt.ACCESS_ALLOWED_OBJECT_ACE, 0x100, ENROLL, 'S-1-5-11'),
        allowed_ace(0x10000000, 'S-1-5-21-1004336348-1177238915-682003330-512'),
    ]
    sd = lt.SR_SECURITY_DESCRIPTOR(); sd['Revision'] = b'\x01'; sd['Sbz1'] = b'\x00'; sd['Control'] = 0x8004
    sd['OwnerSid'] = sid('S-1-5-21-1004336348-1177238915-682003330-512')
    sd['GroupSid'] = sid('S-1-5-21-1004336348-1177238915-682003330-512')
    sd['Sacl'] = b''; sd['Dacl'] = dacl
    return H(sd.getData())


if __name__ == "__main__" and False:
    print("esc1SD =", esc1_template_sd())
