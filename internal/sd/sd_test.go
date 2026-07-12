package sd

import (
	"encoding/hex"
	"testing"
)

// Ground truth from impacket ldaptypes (scratchpad): a self-relative SD with
// SE_SELF_RELATIVE|SE_DACL_PRESENT, owner/group SIDs, and a 3-ACE DACL:
//
//	ACE0 ACCESS_ALLOWED       mask GENERIC_ALL  -> ...512
//	ACE1 ACCESS_ALLOWED_OBJECT mask 0x100 Change-Password -> SELF
//	ACE2 ACCESS_DENIED_OBJECT  mask 0x100 Change-Password -> Everyone
const sdHex = "0100048090000000ac000000000000001400000004007c00030000000000240000000010" +
	"010500000000000515000000dcf4dc3b833d2b46828ba62800020000" +
	"050028000001000001000000531a72ab2f1ed011981900aa0040529b01010000000000050a000000" +
	"060028000001000001000000531a72ab2f1ed011981900aa0040529b010100000000000100000000" +
	"010500000000000515000000dcf4dc3b833d2b46828ba62800020000" +
	"010500000000000515000000dcf4dc3b833d2b46828ba62801020000"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParse(t *testing.T) {
	descriptor, err := Parse(mustHex(t, sdHex))
	if err != nil {
		t.Fatal(err)
	}

	if descriptor.Revision != 1 {
		t.Errorf("revision = %d", descriptor.Revision)
	}
	if descriptor.Control != 0x8004 {
		t.Errorf("control = %#x", descriptor.Control)
	}
	const owner = "S-1-5-21-1004336348-1177238915-682003330-512"
	const group = "S-1-5-21-1004336348-1177238915-682003330-513"
	if descriptor.Owner != owner {
		t.Errorf("owner = %q", descriptor.Owner)
	}
	if descriptor.Group != group {
		t.Errorf("group = %q", descriptor.Group)
	}

	if descriptor.SACL != nil {
		t.Errorf("SACL should be absent")
	}
	if descriptor.DACL == nil || len(descriptor.DACL.ACEs) != 3 {
		t.Fatalf("DACL = %+v", descriptor.DACL)
	}

	aces := descriptor.DACL.ACEs
	if aces[0].Type != AceTypeAccessAllowed || aces[0].Mask != RightGenericAll || aces[0].SID != owner || aces[0].ObjectType != "" {
		t.Errorf("ACE0 = %+v", aces[0])
	}
	if aces[1].Type != AceTypeAccessAllowedObject || aces[1].Mask != RightControlAccess ||
		aces[1].ObjectType != GUIDChangePassword || aces[1].SID != SIDSelf {
		t.Errorf("ACE1 = %+v", aces[1])
	}
	if aces[2].Type != AceTypeAccessDeniedObject || aces[2].ObjectType != GUIDChangePassword || aces[2].SID != SIDEveryone {
		t.Errorf("ACE2 = %+v", aces[2])
	}
}

func TestCannotChangePassword(t *testing.T) {
	descriptor, err := Parse(mustHex(t, sdHex))
	if err != nil {
		t.Fatal(err)
	}
	if !descriptor.CannotChangePassword() {
		t.Error("expected CannotChangePassword to be true (deny Change-Password to Everyone)")
	}

	// A descriptor without the deny ACE must report false.
	allowOnly := &SecurityDescriptor{DACL: &ACL{ACEs: []ACE{
		{Type: AceTypeAccessAllowed, Mask: RightGenericAll, SID: "S-1-5-11"},
	}}}
	if allowOnly.CannotChangePassword() {
		t.Error("allow-only DACL should report false")
	}

	// Nil DACL must not panic.
	if (&SecurityDescriptor{}).CannotChangePassword() {
		t.Error("nil DACL should report false")
	}
}

func TestParseShort(t *testing.T) {
	if _, err := Parse([]byte{1, 0, 0}); err == nil {
		t.Error("expected error for short descriptor")
	}
}

func TestParseTruncatedDACLNoPanic(t *testing.T) {
	// Valid header claiming a DACL offset, but the ACL data is cut off.
	full := mustHex(t, sdHex)
	if _, err := Parse(full[:30]); err != nil {
		t.Fatalf("truncated parse should not error, got %v", err)
	}
}
