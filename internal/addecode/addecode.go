// Package addecode decodes the raw Active Directory attribute encodings that
// collectors need to turn into human-readable form: binary SIDs and GUIDs,
// Windows FILETIME and LDAP GeneralizedTime timestamps, and the bit-field
// attributes userAccountControl, msDS-SupportedEncryptionTypes and groupType.
//
// Semantics mirror PyADRecon-ADWS's helper functions so output matches the
// reference tool.
package addecode

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SIDToString formats a binary SID as S-R-IA-SA-SA-... [MS-DTYP] 2.4.2.
func SIDToString(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	revision := b[0]
	subCount := int(b[1])
	var authority uint64
	for _, c := range b[2:8] { // 6-byte big-endian identifier authority
		authority = authority<<8 | uint64(c)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S-%d-%d", revision, authority)
	for i := 0; i < subCount; i++ {
		off := 8 + i*4
		if off+4 > len(b) {
			break
		}
		fmt.Fprintf(&sb, "-%d", binary.LittleEndian.Uint32(b[off:]))
	}
	return sb.String()
}

// GUIDToString formats a 16-byte objectGUID (mixed-endian) canonically.
func GUIDToString(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// filetimeEpochDeltaSecs is the number of seconds between the FILETIME epoch
// (1601-01-01) and the Unix epoch (1970-01-01).
const filetimeEpochDeltaSecs = 11644473600

// neverFileTime is the "never" sentinel for accountExpires and similar.
const neverFileTime int64 = 0x7FFFFFFFFFFFFFFF

// FileTimeToTime converts a Windows FILETIME (100-ns ticks since 1601) to a UTC
// time. ok is false for the 0 and 0x7FFFFFFFFFFFFFFF sentinels.
func FileTimeToTime(ft int64) (t time.Time, ok bool) {
	if ft <= 0 || ft == neverFileTime {
		return time.Time{}, false
	}
	secs := ft/10_000_000 - filetimeEpochDeltaSecs
	nanos := (ft % 10_000_000) * 100
	return time.Unix(secs, nanos).UTC(), true
}

// ParseFileTime parses a decimal FILETIME string then converts it.
func ParseFileTime(s string) (time.Time, bool) {
	ft, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return FileTimeToTime(ft)
}

// GeneralizedTimeToTime parses LDAP GeneralizedTime (YYYYMMDDHHMMSS[.f][Z]).
func GeneralizedTimeToTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 14 {
		return time.Time{}, false
	}
	t, err := time.Parse("20060102150405", s[:14])
	if err != nil {
		return time.Time{}, false
	}
	// Timezone: either a trailing 'Z' (UTC) or a numeric +/-HHMM offset after
	// the optional fractional seconds. A non-Z offset must be applied, not
	// ignored, or the time would be wrong by that offset.
	rest := strings.TrimRight(s[14:], "Z")
	if i := strings.IndexAny(rest, "+-"); i >= 0 {
		if z, err := time.Parse("-0700", rest[i:]); err == nil {
			_, offset := z.Zone()
			t = t.Add(-time.Duration(offset) * time.Second)
		}
	}
	return t.UTC(), true
}

// FormatDateTime formats a time as M/D/YYYY h:MM:SS AM/PM (UTC), matching the
// reference; ok=false yields "".
func FormatDateTime(t time.Time, ok bool) string {
	if !ok {
		return ""
	}
	return t.Format("1/2/2006 3:04:05 PM")
}

// UAC is a decoded userAccountControl value. [MS-ADTS] 2.2.16.
type UAC struct {
	Raw                        uint32
	Enabled                    bool
	PasswordNotRequired        bool
	PasswordCantChange         bool
	ReversibleEncryption       bool
	PasswordNeverExpires       bool
	SmartcardRequired          bool
	TrustedForDelegation       bool
	NotDelegated               bool
	UseDESKeyOnly              bool
	DoesNotRequirePreAuth      bool
	PasswordExpired            bool
	TrustedToAuthForDelegation bool
	AccountLockedOut           bool
}

// ParseUAC decodes a userAccountControl bit field.
func ParseUAC(uac uint32) UAC {
	return UAC{
		Raw:                        uac,
		Enabled:                    uac&0x0002 == 0,
		AccountLockedOut:           uac&0x0010 != 0,
		PasswordNotRequired:        uac&0x0020 != 0,
		PasswordCantChange:         uac&0x0040 != 0,
		ReversibleEncryption:       uac&0x0080 != 0,
		PasswordNeverExpires:       uac&0x10000 != 0,
		SmartcardRequired:          uac&0x40000 != 0,
		TrustedForDelegation:       uac&0x80000 != 0,
		NotDelegated:               uac&0x100000 != 0,
		UseDESKeyOnly:              uac&0x200000 != 0,
		DoesNotRequirePreAuth:      uac&0x400000 != 0,
		PasswordExpired:            uac&0x800000 != 0,
		TrustedToAuthForDelegation: uac&0x1000000 != 0,
	}
}

// KerbEnc is the decoded msDS-SupportedEncryptionTypes. Each field is
// "Default" (attribute unset), "Supported" or "Not Supported".
type KerbEnc struct {
	RC4    string
	AES128 string
	AES256 string
}

// ParseKerbEnc decodes msDS-SupportedEncryptionTypes from its raw string. An
// empty or zero value means the attribute is unset and the DC uses defaults.
func ParseKerbEnc(raw string) KerbEnc {
	n, _ := strconv.Atoi(strings.TrimSpace(raw))
	if raw == "" || n == 0 {
		return KerbEnc{RC4: "Default", AES128: "Default", AES256: "Default"}
	}
	sup := func(bit int) string {
		if n&bit != 0 {
			return "Supported"
		}
		return "Not Supported"
	}
	return KerbEnc{RC4: sup(0x04), AES128: sup(0x08), AES256: sup(0x10)}
}

// GroupCategoryScope decodes groupType into (category, scope). [MS-ADTS] 2.2.12.
func GroupCategoryScope(gt int64) (category, scope string) {
	if gt&0x80000000 != 0 {
		category = "Security"
	} else {
		category = "Distribution"
	}
	switch {
	case gt&0x02 != 0:
		scope = "Global"
	case gt&0x04 != 0:
		scope = "DomainLocal"
	case gt&0x08 != 0:
		scope = "Universal"
	default:
		scope = "Unknown"
	}
	return category, scope
}
