package addecode

import (
	"encoding/hex"
	"testing"
	"time"
)

func hexb(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSIDToString(t *testing.T) {
	// Ground truth from impacket LDAP_SID.formatCanonical().
	cases := []struct{ hexBytes, want string }{
		{"010500000000000515000000dcf4dc3b833d2b46828ba62800020000", "S-1-5-21-1004336348-1177238915-682003330-512"},
		{"010100000000000512000000", "S-1-5-18"},
	}
	for _, c := range cases {
		if got := SIDToString(hexb(t, c.hexBytes)); got != c.want {
			t.Errorf("SIDToString = %q, want %q", got, c.want)
		}
	}
	if SIDToString([]byte{1, 2, 3}) != "" {
		t.Error("short SID should be empty")
	}
}

func TestGUIDToString(t *testing.T) {
	got := GUIDToString(hexb(t, "6c7d8e6f4a5b28391716151413121110"))
	if want := "6f8e7d6c-5b4a-3928-1716-151413121110"; got != want {
		t.Errorf("GUIDToString = %q, want %q", got, want)
	}
}

func TestFileTimeToTime(t *testing.T) {
	// 116444736000000000 ticks == Unix epoch.
	tm, ok := FileTimeToTime(116444736000000000)
	if !ok || !tm.Equal(time.Unix(0, 0).UTC()) {
		t.Errorf("epoch: got %v ok=%v", tm, ok)
	}
	// A real pwdLastSet.
	tm, ok = FileTimeToTime(133200000000000000)
	if !ok || tm.Format(time.RFC3339) != "2023-02-04T16:00:00Z" {
		t.Errorf("pwdLastSet: got %v ok=%v", tm.Format(time.RFC3339), ok)
	}
	// Sentinels.
	if _, ok := FileTimeToTime(0); ok {
		t.Error("0 should be not-ok")
	}
	if _, ok := FileTimeToTime(0x7FFFFFFFFFFFFFFF); ok {
		t.Error("never sentinel should be not-ok")
	}
}

func TestGeneralizedTime(t *testing.T) {
	tm, ok := GeneralizedTimeToTime("20230204160000.0Z")
	if !ok || tm.Format(time.RFC3339) != "2023-02-04T16:00:00Z" {
		t.Errorf("got %v ok=%v", tm, ok)
	}
	if _, ok := GeneralizedTimeToTime(""); ok {
		t.Error("empty should be not-ok")
	}
}

func TestFormatDateTime(t *testing.T) {
	tm := time.Date(2023, 2, 4, 16, 7, 9, 0, time.UTC)
	if got := FormatDateTime(tm, true); got != "2/4/2023 4:07:09 PM" {
		t.Errorf("got %q", got)
	}
	if got := FormatDateTime(time.Time{}, false); got != "" {
		t.Errorf("not-ok should be empty, got %q", got)
	}
}

func TestParseUAC(t *testing.T) {
	// 0x200 (NORMAL_ACCOUNT) => enabled, nothing else.
	u := ParseUAC(0x200)
	if !u.Enabled || u.AccountLockedOut || u.PasswordNeverExpires {
		t.Errorf("normal account: %+v", u)
	}
	// Disabled + PasswordNeverExpires + DoesNotRequirePreAuth.
	u = ParseUAC(0x0002 | 0x10000 | 0x400000)
	if u.Enabled {
		t.Error("0x2 should be disabled")
	}
	if !u.PasswordNeverExpires || !u.DoesNotRequirePreAuth {
		t.Errorf("flags: %+v", u)
	}
	// Unconstrained delegation.
	if !ParseUAC(0x80000).TrustedForDelegation {
		t.Error("0x80000 should be TrustedForDelegation")
	}
}

func TestParseKerbEnc(t *testing.T) {
	if k := ParseKerbEnc(""); k.RC4 != "Default" || k.AES256 != "Default" {
		t.Errorf("unset: %+v", k)
	}
	if k := ParseKerbEnc("0"); k.AES128 != "Default" {
		t.Errorf("zero: %+v", k)
	}
	// 0x18 = AES128 | AES256, no RC4.
	k := ParseKerbEnc("24")
	if k.RC4 != "Not Supported" || k.AES128 != "Supported" || k.AES256 != "Supported" {
		t.Errorf("0x18: %+v", k)
	}
}

func TestGroupCategoryScope(t *testing.T) {
	// Global security group 0x80000002 (as signed -2147483646 or unsigned).
	cat, scope := GroupCategoryScope(-2147483646)
	if cat != "Security" || scope != "Global" {
		t.Errorf("global sec: %s/%s", cat, scope)
	}
	cat, scope = GroupCategoryScope(2147483650) // same value unsigned
	if cat != "Security" || scope != "Global" {
		t.Errorf("global sec unsigned: %s/%s", cat, scope)
	}
	// Domain-local distribution group 0x4.
	cat, scope = GroupCategoryScope(0x4)
	if cat != "Distribution" || scope != "DomainLocal" {
		t.Errorf("dl dist: %s/%s", cat, scope)
	}
}
