// Package sd parses Windows self-relative security descriptors ([MS-DTYP]
// 2.4.6) as returned in the nTSecurityDescriptor attribute: owner/group SIDs
// and the DACL/SACL with their ACEs. It exposes the structured result plus the
// specific ACL analyses the collectors need (starting with "cannot change
// password").
package sd

import (
	"encoding/binary"
	"fmt"
	"strings"

	"adit/internal/addecode"
)

// Control flags. [MS-DTYP] 2.4.6.
const (
	ControlDACLPresent  = 0x0004
	ControlSACLPresent  = 0x0010
	ControlSelfRelative = 0x8000
)

// ACE types. [MS-DTYP] 2.4.4.1.
const (
	AceTypeAccessAllowed               = 0x00
	AceTypeAccessDenied                = 0x01
	AceTypeSystemAudit                 = 0x02
	AceTypeAccessAllowedObject         = 0x05
	AceTypeAccessDeniedObject          = 0x06
	AceTypeSystemAuditObject           = 0x07
	AceTypeAccessAllowedCallback       = 0x09
	AceTypeAccessDeniedCallback        = 0x0A
	AceTypeAccessAllowedCallbackObject = 0x0B
	AceTypeAccessDeniedCallbackObject  = 0x0C
	AceTypeSystemMandatoryLabel        = 0x11
)

// Access-mask rights relevant to AD objects. [MS-ADTS] 5.1.3.2 / [MS-DTYP] 2.4.3.
const (
	RightGenericRead          = 0x80000000
	RightGenericWrite         = 0x40000000
	RightGenericExecute       = 0x20000000
	RightGenericAll           = 0x10000000
	RightMaximumAllowed       = 0x02000000
	RightAccessSystemSecurity = 0x01000000
	RightSynchronize          = 0x00100000
	RightWriteOwner           = 0x00080000
	RightWriteDACL            = 0x00040000
	RightReadControl          = 0x00020000
	RightDelete               = 0x00010000
	RightControlAccess        = 0x00000100 // extended right
	RightDSListObject         = 0x00000080
	RightDSDeleteTree         = 0x00000040
	RightDSWriteProp          = 0x00000020
	RightDSReadProp           = 0x00000010
	RightDSSelf               = 0x00000008 // validated write
	RightDSListChildren       = 0x00000004
	RightDSDeleteChild        = 0x00000002
	RightDSCreateChild        = 0x00000001
)

// Well-known control-access-right / property-set GUIDs. [MS-ADTS] Appendix.
const (
	GUIDChangePassword      = "ab721a53-1e2f-11d0-9819-00aa0040529b"
	GUIDResetPassword       = "00299570-246d-11d0-a768-00aa006e0529"
	GUIDDSReplGetChanges    = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
	GUIDDSReplGetChangesAll = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
	GUIDWriteMember         = "bf9679c0-0de6-11d0-a285-00aa003049e2"
)

// Well-known trustee SIDs used in ACL analysis.
const (
	SIDSelf     = "S-1-5-10"
	SIDEveryone = "S-1-1-0"
)

// SecurityDescriptor is a parsed self-relative security descriptor.
type SecurityDescriptor struct {
	Revision byte
	Control  uint16
	Owner    string // SID string, "" if absent
	Group    string
	SACL     *ACL
	DACL     *ACL
}

// ACL is an access-control list.
type ACL struct {
	Revision byte
	ACEs     []ACE
}

// ACE is one access-control entry. ObjectType / InheritedObjectType are GUID
// strings, empty when the ACE carries none.
type ACE struct {
	Type                byte
	Flags               byte
	Mask                uint32
	SID                 string
	ObjectType          string
	InheritedObjectType string
}

// Parse decodes a self-relative security descriptor.
func Parse(b []byte) (*SecurityDescriptor, error) {
	if len(b) < 20 {
		return nil, fmt.Errorf("sd: descriptor too short (%d bytes)", len(b))
	}
	sd := &SecurityDescriptor{
		Revision: b[0],
		Control:  binary.LittleEndian.Uint16(b[2:]),
	}
	offOwner := binary.LittleEndian.Uint32(b[4:])
	offGroup := binary.LittleEndian.Uint32(b[8:])
	offSacl := binary.LittleEndian.Uint32(b[12:])
	offDacl := binary.LittleEndian.Uint32(b[16:])

	if offOwner != 0 {
		if s, ok := sidAt(b, offOwner); ok {
			sd.Owner = s
		}
	}
	if offGroup != 0 {
		if s, ok := sidAt(b, offGroup); ok {
			sd.Group = s
		}
	}
	if offSacl != 0 && int(offSacl) <= len(b) {
		sd.SACL = parseACL(b[offSacl:])
	}
	if offDacl != 0 && int(offDacl) <= len(b) {
		sd.DACL = parseACL(b[offDacl:])
	}
	return sd, nil
}

// sidAt reads a SID at offset off and returns its canonical string.
func sidAt(b []byte, off uint32) (string, bool) {
	if int(off)+2 > len(b) {
		return "", false
	}
	subCount := int(b[off+1])
	n := 8 + subCount*4
	if int(off)+n > len(b) {
		return "", false
	}
	return addecode.SIDToString(b[off : int(off)+n]), true
}

// parseACL decodes an ACL whose header begins at b[0]. [MS-DTYP] 2.4.5.
func parseACL(b []byte) *ACL {
	if len(b) < 8 {
		return &ACL{}
	}
	acl := &ACL{Revision: b[0]}
	aceCount := int(binary.LittleEndian.Uint16(b[4:]))
	off := 8
	for i := 0; i < aceCount; i++ {
		if off+4 > len(b) {
			break
		}
		aceType := b[off]
		aceFlags := b[off+1]
		aceSize := int(binary.LittleEndian.Uint16(b[off+2:]))
		if aceSize < 4 || off+aceSize > len(b) {
			break
		}
		acl.ACEs = append(acl.ACEs, parseACE(aceType, aceFlags, b[off+4:off+aceSize]))
		off += aceSize
	}
	return acl
}

// isObjectACE reports whether the ACE type carries the object-type fields.
func isObjectACE(t byte) bool {
	switch t {
	case AceTypeAccessAllowedObject, AceTypeAccessDeniedObject, AceTypeSystemAuditObject,
		AceTypeAccessAllowedCallbackObject, AceTypeAccessDeniedCallbackObject:
		return true
	}
	return false
}

// parseACE decodes one ACE body (the bytes after the 4-byte ACE header).
func parseACE(t, flags byte, body []byte) ACE {
	ace := ACE{Type: t, Flags: flags}
	if len(body) < 4 {
		return ace
	}
	ace.Mask = binary.LittleEndian.Uint32(body)
	rest := body[4:]

	if isObjectACE(t) {
		if len(rest) < 4 {
			return ace
		}
		objFlags := binary.LittleEndian.Uint32(rest)
		rest = rest[4:]
		if objFlags&0x1 != 0 { // ACE_OBJECT_TYPE_PRESENT
			if len(rest) < 16 {
				return ace
			}
			ace.ObjectType = addecode.GUIDToString(rest[:16])
			rest = rest[16:]
		}
		if objFlags&0x2 != 0 { // ACE_INHERITED_OBJECT_TYPE_PRESENT
			if len(rest) < 16 {
				return ace
			}
			ace.InheritedObjectType = addecode.GUIDToString(rest[:16])
			rest = rest[16:]
		}
	}

	if s, ok := sidAt(rest, 0); ok {
		ace.SID = s
	}
	return ace
}

// CannotChangePassword reports whether the DACL denies the Change-Password
// extended right to SELF or Everyone — the ACL form of the "user cannot change
// password" setting. Mirrors PyADRecon-ADWS check_cannot_change_password.
func (sd *SecurityDescriptor) CannotChangePassword() bool {
	if sd.DACL == nil {
		return false
	}
	for _, ace := range sd.DACL.ACEs {
		if ace.Type != AceTypeAccessDeniedObject {
			continue
		}
		if !strings.EqualFold(ace.ObjectType, GUIDChangePassword) {
			continue
		}
		if ace.SID == SIDSelf || ace.SID == SIDEveryone {
			return true
		}
	}
	return false
}
