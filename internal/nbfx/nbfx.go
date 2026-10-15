// Package nbfx implements the .NET Binary XML encoding used by ADWS: [MC-NBFX]
// records with the [MC-NBFS] standard string dictionary, wrapped by the
// [MC-NBFSE] in-band dictionary extension that WCF's net.tcp binding negotiates.
//
// It provides a bidirectional codec satisfying nmf.Encoder:
//
//   - Encode turns an outgoing SOAP envelope (string) into NBFX bytes. This is
//     a faithful port of PyADRecon-ADWS's encoder and is validated
//     byte-for-byte against it (see nbfx_test.go).
//   - Decode turns an NBFX response back into XML text for the SOAP layer.
//
// The client never sends an in-band dictionary, so Encode emits an empty one
// (a single 0x00) for NBFSE. Decode reads and applies any in-band dictionary the
// server sends: static strings live at even indices, session strings at odd.
package nbfx

import (
	"encoding/binary"
	"fmt"
)

// Encoding selects the wire format. ADWS negotiates NBFSE.
type Encoding int

const (
	NBFS  Encoding = 0x07 // [MC-NBFS]
	NBFSE Encoding = 0x08 // [MC-NBFSE]
)

// Encoder is a stateless NBFX codec.
type Encoder struct{ encoding Encoding }

// New returns an Encoder for the given encoding.
func New(encoding Encoding) *Encoder { return &Encoder{encoding: encoding} }

// Encode serializes a SOAP envelope string to NBFX bytes.
func (e *Encoder) Encode(xml string) ([]byte, error) {
	nodes, err := parseXML(xml)
	if err != nil {
		return nil, fmt.Errorf("nbfx: parse xml: %w", err)
	}
	body := dumpRecords(nodes)

	switch e.encoding {
	case NBFS:
		return body, nil
	case NBFSE:
		// Empty in-band dictionary: a single MBI(0).
		return append([]byte{0x00}, body...), nil
	default:
		return nil, fmt.Errorf("nbfx: unknown encoding 0x%x", e.encoding)
	}
}

// Decode deserializes NBFX bytes back to an XML string.
func (e *Encoder) Decode(data []byte) (string, error) {
	if e.encoding == NBFSE {
		size, n := readMBI(data)
		if n == 0 || size > len(data)-n { // overflow-safe bounds check
			return "", fmt.Errorf("nbfx: invalid in-band dictionary size")
		}
		inband := parseInbandDictionary(data[n : n+size])
		return decodeRecords(data[n+size:], inband)
	}
	return decodeRecords(data, nil)
}

// --- MultiByteInt31 (MC-NBFX 2.1.2) ---

// encodeMBI encodes a non-negative integer as a 7-bit multi-byte integer.
func encodeMBI(v uint32) []byte {
	if v <= 0x7f {
		return []byte{byte(v)}
	}
	out := make([]byte, 0, 5)
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if v == 0 {
			return out
		}
	}
}

// readMBI decodes a multi-byte integer, returning the value and bytes consumed.
func readMBI(data []byte) (value, n int) {
	var shift uint
	for i := 0; i < 5 && i < len(data); i++ {
		b := data[i]
		value |= int(b&0x7f) << shift
		n++
		if b&0x80 == 0 {
			// MultiByteInt31 encodes at most 31 bits; reject anything larger
			// (also guards against int overflow to a negative value, which
			// would bypass length checks on a 32-bit build).
			if value < 0 || value > 0x7fffffff {
				return 0, 0
			}
			return value, n
		}
		shift += 7
	}
	// Ran out of bytes mid-varint, or a 5th byte still had the continuation
	// bit set: a malformed / over-long varint. Signal failure with n == 0.
	return 0, 0
}

// utf8String encodes a string as MBI(len) followed by its UTF-8 bytes.
func utf8String(s string) []byte {
	b := []byte(s)
	return append(encodeMBI(uint32(len(b))), b...)
}

// parseInbandDictionary reads the MC-NBFSE string table: a sequence of
// length-prefixed UTF-8 strings assigned successive odd indices (1, 3, 5, ...).
func parseInbandDictionary(data []byte) map[uint32]string {
	table := make(map[uint32]string)
	idx := uint32(1)
	for len(data) > 0 {
		size, n := readMBI(data)
		if n == 0 || size > len(data)-n { // overflow-safe bounds check
			break
		}
		table[idx] = string(data[n : n+size])
		data = data[n+size:]
		idx += 2
	}
	return table
}

// little-endian fixed-width helpers used by value records.
func le16(v uint16) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); return b }
func le32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
func le64(v uint64) []byte { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, v); return b }
