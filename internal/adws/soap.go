package adws

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// knownBinaryAttributes are returned base64-encoded by ADWS but not always
// tagged with an xsi:type; they are always decoded to raw bytes. Mirrors
// PyADRecon-ADWS KNOWN_BINARY_ADWS_ATTRIBUTES.
var knownBinaryAttributes = map[string]bool{
	"objectsid": true, "objectguid": true, "ntsecuritydescriptor": true,
	"sidhistory": true, "cacertificate": true, "pkiexpirationperiod": true,
	"pkioverlapperiod": true, "msds-allowedtoactonbehalfofotheridentity": true,
	"msds-groupmsamembership": true, "schemaidguid": true, "dnsrecord": true,
}

// errReferralCode is the AD Win32 error for a directory referral, returned when
// a child domain is asked for forest-level objects. [MS-ERREF] ERROR_DS_REFERRAL.
const errReferralCode = 8235

// Value is one value of a directory attribute. Binary is populated (and IsBinary
// set) when the value is base64Binary; Text always holds the string form.
type Value struct {
	Text     string
	Binary   []byte
	IsBinary bool
}

// Object is a parsed directory object: attribute local name -> values.
type Object struct {
	Attributes map[string][]Value
}

// DN returns the object's distinguishedName, or "".
func (o *Object) DN() string { return o.First("distinguishedName") }

// First returns the first text value of an attribute, or "".
func (o *Object) First(attr string) string {
	if vs := o.Attributes[attr]; len(vs) > 0 {
		return vs[0].Text
	}
	return ""
}

// soapFault is a parsed SOAP fault.
type soapFault struct {
	reason     string
	win32Error int
}

func (f *soapFault) Error() string {
	if f.win32Error != 0 {
		return fmt.Sprintf("soap fault: %s (Win32ErrorCode %d)", f.reason, f.win32Error)
	}
	return "soap fault: " + f.reason
}

// isReferral reports whether the fault is a (non-fatal) directory referral.
func (f *soapFault) isReferral() bool { return f.win32Error == errReferralCode }

// checkFault returns a *soapFault if the envelope carries one.
func checkFault(env *node) *soapFault {
	fault := env.first("Fault")
	if fault == nil {
		return nil
	}
	f := &soapFault{reason: "unknown"}
	if reason := fault.first("Text"); reason != nil {
		f.reason = reason.trimText()
	}
	if code := fault.first("Win32ErrorCode"); code != nil {
		f.win32Error, _ = strconv.Atoi(code.trimText())
	}
	return f
}

// enumerationContext extracts the WS-Enumeration context token.
func enumerationContext(env *node) (string, bool) {
	if c := env.first("EnumerationContext"); c != nil {
		return c.trimText(), true
	}
	return "", false
}

// pullItems returns the object elements from a PullResponse and whether the
// enumeration is exhausted (EndOfSequence present).
func pullItems(env *node) (items []*node, done bool) {
	if items := env.first("Items"); items != nil {
		return items.Children, env.first("EndOfSequence") != nil
	}
	return nil, env.first("EndOfSequence") != nil
}

// parseItem turns one object element into an Object.
func parseItem(item *node) *Object {
	obj := &Object{Attributes: make(map[string][]Value)}
	for _, attrEl := range item.Children {
		name := attrEl.Local
		binary := knownBinaryAttributes[strings.ToLower(name)]
		var values []Value
		for _, v := range attrEl.Children {
			if v.Local != "value" {
				continue
			}
			values = append(values, parseValue(v, binary))
		}
		if len(values) > 0 {
			obj.Attributes[name] = values
		}
	}
	return obj
}

func parseValue(v *node, forceBinary bool) Value {
	text := v.trimText()
	isBinary := forceBinary
	if t, ok := v.attr("type"); ok && strings.HasSuffix(t, "base64Binary") {
		isBinary = true
	}
	val := Value{Text: text}
	if isBinary && text != "" {
		if raw, err := base64.StdEncoding.DecodeString(text); err == nil {
			val.Binary = raw
			val.IsBinary = true
		}
	}
	return val
}
