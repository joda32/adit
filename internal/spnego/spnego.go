// Package spnego implements the minimal SPNEGO ([RFC 4178]) token handling
// needed to carry NTLM through the MS-NNS handshake: wrap the initial NTLM
// NEGOTIATE in a GSS-API-framed NegTokenInit, wrap the NTLM AUTHENTICATE in a
// NegTokenResp, and extract the server's NTLM CHALLENGE from its NegTokenResp.
//
// Only NTLM is advertised, so the token shapes are fixed and built with a small
// hand-rolled DER writer rather than a general ASN.1 encoder. Output matches
// impacket's spnego module byte-for-byte (see spnego_test.go).
package spnego

import (
	"errors"
	"fmt"
)

// DER identifier octets used here.
const (
	tagOID           = 0x06
	tagOctetString   = 0x04
	tagSequence      = 0x30
	tagApplication0  = 0x60 // [APPLICATION 0] constructed — GSS InitialContextToken
	tagContext0      = 0xA0 // [0] mechTypes / negTokenInit
	tagContext1      = 0xA1 // [1] negTokenResp
	tagContext2      = 0xA2 // [2] mechToken / responseToken
	tagContext3      = 0xA3 // [3] mechListMIC
	classContextMask = 0xC0
)

// oidSPNEGO is 1.3.6.1.5.5.2, DER-encoded (tag+len+value).
var oidSPNEGO = []byte{tagOID, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}

// oidNTLM is 1.3.6.1.4.1.311.2.2.10 (NTLMSSP), DER-encoded.
var oidNTLM = []byte{tagOID, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

// encodeLen encodes a DER definite length.
func encodeLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp []byte
	for n > 0 {
		tmp = append([]byte{byte(n & 0xff)}, tmp...)
		n >>= 8
	}
	return append([]byte{byte(0x80 | len(tmp))}, tmp...)
}

// tlv builds a DER TLV from a tag and content.
func tlv(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, encodeLen(len(content))...)
	return append(out, content...)
}

// NegTokenInit wraps an NTLM negotiate token in a GSS-API-framed SPNEGO
// NegTokenInit advertising only the NTLM mechanism.
func NegTokenInit(mechToken []byte) []byte {
	mechTypes := tlv(tagContext0, tlv(tagSequence, oidNTLM))
	token := tlv(tagContext2, tlv(tagOctetString, mechToken))
	negTokenInit := tlv(tagContext0, tlv(tagSequence, concat(mechTypes, token)))
	return tlv(tagApplication0, concat(oidSPNEGO, negTokenInit))
}

// NegTokenResp wraps a response token (the NTLM authenticate) in a SPNEGO
// NegTokenResp.
func NegTokenResp(responseToken []byte) []byte {
	respTok := tlv(tagContext2, tlv(tagOctetString, responseToken))
	return tlv(tagContext1, tlv(tagSequence, respTok))
}

// ExtractResponseToken pulls the responseToken (context tag [2] → OCTET STRING)
// out of a server SPNEGO token — for NTLM this is the CHALLENGE message. It
// tolerates both the GSS-wrapped and bare forms by walking the DER tree.
func ExtractResponseToken(data []byte) ([]byte, error) {
	tok, err := findContextOctetString(data, tagContext2)
	if err != nil {
		return nil, err
	}
	if tok == nil {
		return nil, errors.New("spnego: no responseToken in server token")
	}
	return tok, nil
}

// findContextOctetString walks the DER structure looking for a constructed
// context tag whose immediate child is an OCTET STRING, and returns that
// string's bytes.
func findContextOctetString(data []byte, wantTag byte) ([]byte, error) {
	for len(data) > 0 {
		tag, content, rest, err := readTLV(data)
		if err != nil {
			return nil, err
		}
		if tag == wantTag {
			// Expect an OCTET STRING as the first child.
			if ct, cc, _, err := readTLV(content); err == nil && ct == tagOctetString {
				return cc, nil
			}
		}
		// Recurse into constructed encodings (context tags and SEQUENCE).
		if isConstructed(tag) {
			if found, err := findContextOctetString(content, wantTag); err != nil {
				return nil, err
			} else if found != nil {
				return found, nil
			}
		}
		data = rest
	}
	return nil, nil
}

func isConstructed(tag byte) bool {
	// Constructed bit (0x20) set: SEQUENCE, context/application constructed tags.
	return tag&0x20 != 0
}

// readTLV parses one DER TLV, returning its tag, content, and the remaining
// bytes after it.
func readTLV(data []byte) (tag byte, content, rest []byte, err error) {
	if len(data) < 2 {
		return 0, nil, nil, fmt.Errorf("spnego: truncated TLV")
	}
	tag = data[0]
	i := 1
	l := int(data[i])
	i++
	if l&0x80 != 0 {
		nBytes := l & 0x7f
		if nBytes == 0 || nBytes > 4 || i+nBytes > len(data) {
			return 0, nil, nil, fmt.Errorf("spnego: bad DER length")
		}
		l = 0
		for j := 0; j < nBytes; j++ {
			l = l<<8 | int(data[i+j])
		}
		i += nBytes
	}
	if i+l > len(data) {
		return 0, nil, nil, fmt.Errorf("spnego: TLV length %d exceeds buffer", l)
	}
	return tag, data[i : i+l], data[i+l:], nil
}

func concat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	return append(out, b...)
}
