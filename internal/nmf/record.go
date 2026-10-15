package nmf

import (
	"errors"
	"fmt"
	"io"
)

// RecordType identifies an MC-NMF record. [MC-NMF] 2.2.1.
type RecordType byte

const (
	recVersion         RecordType = 0x00
	recMode            RecordType = 0x01
	recVia             RecordType = 0x02
	recKnownEncoding   RecordType = 0x03
	recExtensibleEnc   RecordType = 0x04
	recUnsizedEnvelope RecordType = 0x05
	recSizedEnvelope   RecordType = 0x06
	recEnd             RecordType = 0x07
	recFault           RecordType = 0x08
	recUpgradeRequest  RecordType = 0x09
	recUpgradeResponse RecordType = 0x0A
	recPreambleAck     RecordType = 0x0B
	recPreambleEnd     RecordType = 0x0C
)

func (t RecordType) String() string {
	switch t {
	case recVersion:
		return "Version"
	case recMode:
		return "Mode"
	case recVia:
		return "Via"
	case recKnownEncoding:
		return "KnownEncoding"
	case recExtensibleEnc:
		return "ExtensibleEncoding"
	case recUnsizedEnvelope:
		return "UnsizedEnvelope"
	case recSizedEnvelope:
		return "SizedEnvelope"
	case recEnd:
		return "End"
	case recFault:
		return "Fault"
	case recUpgradeRequest:
		return "UpgradeRequest"
	case recUpgradeResponse:
		return "UpgradeResponse"
	case recPreambleAck:
		return "PreambleAck"
	case recPreambleEnd:
		return "PreambleEnd"
	default:
		return fmt.Sprintf("Unknown(0x%02x)", byte(t))
	}
}

// Mode is the MC-NMF communication mode. [MC-NMF] 2.2.3.2.
type Mode byte

const (
	ModeSingletonUnsized Mode = 0x1
	ModeDuplex           Mode = 0x2
	ModeSimplex          Mode = 0x3
	ModeSingletonSized   Mode = 0x4
)

// Encoding is the MC-NMF known encoding for the SOAP payload. [MC-NMF] 2.2.3.4.1.
type Encoding byte

const (
	EncodingSoap12Binary       Encoding = 0x07 // [MC-NBFS]
	EncodingSoap12BinaryInband Encoding = 0x08 // [MC-NBFSE]
)

// maxSizeFieldLen bounds the multi-byte integer used for record sizes. A size
// field is at most 5 bytes (a 32-bit value, 7 bits per byte). [MC-NMF] 2.2.2.
const maxSizeFieldLen = 5

// maxRecordSize bounds a sized record's payload so a malicious or corrupt size
// field cannot drive a huge allocation. 64 MiB matches WCF's default
// maxReceivedMessageSize, comfortably above any real directory response.
const maxRecordSize = 64 << 20

// encodeSize encodes a payload length using the MC-NMF multi-byte integer
// scheme: 7 value bits per byte, high bit set on every byte except the last.
func encodeSize(size int) []byte {
	if size < 0 {
		panic("nmf: negative size")
	}
	if size <= 0x7f {
		return []byte{byte(size)}
	}
	out := make([]byte, 0, maxSizeFieldLen)
	for {
		b := byte(size & 0x7f)
		size >>= 7
		if size != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if size == 0 {
			return out
		}
	}
}

// readByte reads a single byte from r.
func readByte(r io.Reader) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

// readSize reads an MC-NMF multi-byte integer from the stream.
func readSize(r io.Reader) (int, error) {
	var (
		size  int
		shift uint
	)
	for i := 0; i < maxSizeFieldLen; i++ {
		b, err := readByte(r)
		if err != nil {
			return 0, err
		}
		size |= int(b&0x7f) << shift
		if b&0x80 == 0 {
			return size, nil
		}
		shift += 7
	}
	return 0, errors.New("nmf: size field exceeds 5 bytes")
}

// --- record builders (client -> server) ---

func versionRecord(major, minor byte) []byte {
	return []byte{byte(recVersion), major, minor}
}

func modeRecord(m Mode) []byte {
	return []byte{byte(recMode), byte(m)}
}

func knownEncodingRecord(e Encoding) []byte {
	return []byte{byte(recKnownEncoding), byte(e)}
}

// sizedRecord builds a record consisting of a type byte, an encoded size and a
// payload — the shape shared by Via, UpgradeRequest and SizedEnvelope.
func sizedRecord(t RecordType, payload []byte) []byte {
	size := encodeSize(len(payload))
	out := make([]byte, 0, 1+len(size)+len(payload))
	out = append(out, byte(t))
	out = append(out, size...)
	out = append(out, payload...)
	return out
}

func viaRecord(via string) []byte {
	return sizedRecord(recVia, []byte(via))
}

func upgradeRequestRecord(proto string) []byte {
	return sizedRecord(recUpgradeRequest, []byte(proto))
}

func sizedEnvelopeRecord(payload []byte) []byte {
	return sizedRecord(recSizedEnvelope, payload)
}

// preamble concatenates the four records the client sends to open a connection:
// Version, Mode, Via, KnownEncoding. [MC-NMF] 2.2.3.1.
func preamble(major, minor byte, mode Mode, via string, enc Encoding) []byte {
	out := versionRecord(major, minor)
	out = append(out, modeRecord(mode)...)
	out = append(out, viaRecord(via)...)
	out = append(out, knownEncodingRecord(enc)...)
	return out
}

// readRecord reads one record from the stream and returns its type plus any
// payload (nil for records that carry none).
func readRecord(r io.Reader) (RecordType, []byte, error) {
	b, err := readByte(r)
	if err != nil {
		return 0, nil, err
	}
	typ := RecordType(b)

	switch typ {
	case recVersion:
		buf := make([]byte, 2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return typ, nil, err
		}
		return typ, buf, nil

	case recMode, recKnownEncoding:
		v, err := readByte(r)
		if err != nil {
			return typ, nil, err
		}
		return typ, []byte{v}, nil

	case recVia, recFault, recUpgradeRequest, recSizedEnvelope:
		n, err := readSize(r)
		if err != nil {
			return typ, nil, err
		}
		if n < 0 || n > maxRecordSize {
			return typ, nil, fmt.Errorf("nmf: record size out of range (%d bytes)", n)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return typ, nil, err
		}
		return typ, buf, nil

	case recEnd, recPreambleAck, recPreambleEnd, recUpgradeResponse:
		return typ, nil, nil

	default:
		return typ, nil, fmt.Errorf("nmf: unexpected record type %s", typ)
	}
}
