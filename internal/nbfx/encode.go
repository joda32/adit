package nbfx

import (
	"encoding/base64"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// inverted maps a dictionary string to its index, built from the static
// dictionary. There are no duplicate values, so the mapping is unambiguous.
var inverted = func() map[string]uint32 {
	m := make(map[string]uint32, len(dictionary))
	for k, v := range dictionary {
		m[v] = k
	}
	return m
}()

// --- encode record tree ---

type eNode interface{ isENode() }

// eElem is an element record: head holds its type+name/index bytes, attrs the
// pre-encoded attribute records, kids the child nodes.
type eElem struct {
	head  []byte
	attrs [][]byte
	kids  []eNode
}

// eText is a value record split into its base type byte and payload; dump adds
// 1 to the type for the "WithEndElement" form when it is an element's last child.
type eText struct {
	baseType byte
	payload  []byte
}

type eComment struct{ text string }

func (*eElem) isENode()    {}
func (*eText) isENode()    {}
func (*eComment) isENode() {}

// dumpRecords serializes a node list. The last text child of an element is
// emitted as its WithEndElement variant (base type + 1), which stands in for the
// element's EndElement record; every other element emits an explicit EndElement
// (0x01). Faithful to PyADRecon-ADWS dump_records.
func dumpRecords(nodes []eNode) []byte {
	var out []byte
	for i, n := range nodes {
		last := i == len(nodes)-1
		switch v := n.(type) {
		case *eText:
			bt := v.baseType
			if last {
				bt++ // WithEndElement
			}
			out = append(out, bt)
			out = append(out, v.payload...)
		case *eComment:
			out = append(out, 0x02)
			out = append(out, utf8String(v.text)...)
		case *eElem:
			out = append(out, v.head...)
			for _, a := range v.attrs {
				out = append(out, a...)
			}
			out = append(out, dumpRecords(v.kids)...)
			if len(v.kids) == 0 || !isText(v.kids[len(v.kids)-1]) {
				out = append(out, 0x01) // EndElement
			}
		}
	}
	return out
}

func isText(n eNode) bool {
	_, ok := n.(*eText)
	return ok
}

// --- element / attribute construction ([MC-NBFX] 2.2) ---

// makeElementHead returns the record head (type byte + name/index) for a tag,
// mirroring PyADRecon-ADWS _parse_tag.
func makeElementHead(tag string) []byte {
	if prefix, name, ok := strings.Cut(tag, ":"); ok {
		if len(prefix) == 1 {
			c := prefix[0] - 'a'
			if idx, isDict := inverted[name]; isDict {
				// PrefixDictionaryElement[a-z]: 0x44..0x5D
				return append([]byte{0x44 + c}, encodeMBI(idx)...)
			}
			// PrefixElement[a-z]: 0x5E..0x77
			return append([]byte{0x5E + c}, utf8String(name)...)
		}
		if idx, isDict := inverted[name]; isDict {
			// DictionaryElement 0x43: prefix + index
			return append(append([]byte{0x43}, utf8String(prefix)...), encodeMBI(idx)...)
		}
		// Element 0x41: prefix + name
		return append(append([]byte{0x41}, utf8String(prefix)...), utf8String(name)...)
	}
	if idx, isDict := inverted[tag]; isDict {
		// ShortDictionaryElement 0x42: index
		return append([]byte{0x42}, encodeMBI(idx)...)
	}
	// ShortElement 0x40: name
	return append([]byte{0x40}, utf8String(tag)...)
}

// makeAttribute returns an attribute record, mirroring _parse_attr.
func makeAttribute(name, value string) []byte {
	if prefix, local, ok := strings.Cut(name, ":"); ok {
		switch {
		case prefix == "xmlns":
			if idx, isDict := inverted[value]; isDict {
				// DictionaryXmlnsAttribute 0x0B: prefix + index
				return append(append([]byte{0x0B}, utf8String(local)...), encodeMBI(idx)...)
			}
			// XmlnsAttribute 0x09: name + value
			return append(append([]byte{0x09}, utf8String(local)...), utf8String(value)...)
		case len(prefix) == 1:
			c := prefix[0] - 'a'
			val := encodeValue(value)
			if idx, isDict := inverted[local]; isDict {
				// PrefixDictionaryAttribute[a-z]: 0x0C..0x25
				return append(append([]byte{0x0C + c}, encodeMBI(idx)...), val...)
			}
			// PrefixAttribute[a-z]: 0x26..0x3F
			return append(append([]byte{0x26 + c}, utf8String(local)...), val...)
		default:
			val := encodeValue(value)
			if idx, isDict := inverted[local]; isDict {
				// DictionaryAttribute 0x07: prefix + index + value
				return append(append(append([]byte{0x07}, utf8String(prefix)...), encodeMBI(idx)...), val...)
			}
			// Attribute 0x05: prefix + name + value
			return append(append(append([]byte{0x05}, utf8String(prefix)...), utf8String(local)...), val...)
		}
	}
	if name == "xmlns" {
		if idx, isDict := inverted[value]; isDict {
			// ShortDictionaryXmlnsAttribute 0x0A: index
			return append([]byte{0x0A}, encodeMBI(idx)...)
		}
		// ShortXmlnsAttribute 0x08: value
		return append([]byte{0x08}, utf8String(value)...)
	}
	val := encodeValue(value)
	if idx, isDict := inverted[name]; isDict {
		// ShortDictionaryAttribute 0x06: index + value
		return append(append([]byte{0x06}, encodeMBI(idx)...), val...)
	}
	// ShortAttribute 0x04: name + value
	return append(append([]byte{0x04}, utf8String(name)...), val...)
}

// --- value typing ([MC-NBFX] text records), mirroring _parse_data ---

var (
	reInt      = regexp.MustCompile(`^-?\d+$`)
	reUUID     = regexp.MustCompile(`^([a-fA-F0-9]{8})-([a-fA-F0-9]{4})-([a-fA-F0-9]{4})-([a-fA-F0-9]{4})-([a-fA-F0-9]{12})$`)
	reUniqueID = regexp.MustCompile(`^urn:uuid:([a-fA-F0-9]{8})-([a-fA-F0-9]{4})-([a-fA-F0-9]{4})-([a-fA-F0-9]{4})-([a-fA-F0-9]{12})$`)
	reBase64   = regexp.MustCompile(`^[a-zA-Z0-9/+]*={0,2}$`)
	reFloat    = regexp.MustCompile(`^-?(INF)|(NaN)|(\d+(\.\d+)?)$`)
)

// encodeValue returns the full to_bytes of the value record for a text value.
func encodeValue(value string) []byte {
	baseType, payload := typeValue(value)
	return append([]byte{baseType}, payload...)
}

// matchAtStart emulates Python's re.match: the regex must match starting at
// position 0. Go's MatchString searches anywhere, which differs for patterns
// like reFloat whose alternatives are not all anchored at the start.
func matchAtStart(re *regexp.Regexp, s string) bool {
	loc := re.FindStringIndex(s)
	return loc != nil && loc[0] == 0
}

// typeValue classifies a (stripped) string into a text record base type and
// payload, following PyADRecon-ADWS _parse_data ordering exactly.
func typeValue(raw string) (baseType byte, payload []byte) {
	data := strings.TrimSpace(raw)

	b64ok := false
	if matchAtStart(reBase64, data) {
		if _, err := base64.StdEncoding.DecodeString(data); err == nil {
			b64ok = true
		}
	}

	switch {
	case data == "0":
		return 0x80, nil // ZeroText
	case data == "1":
		return 0x82, nil // OneText
	case strings.EqualFold(data, "false"):
		return 0x84, nil // FalseText
	case strings.EqualFold(data, "true"):
		return 0x86, nil // TrueText
	case len(data) > 3 && data[1] == ':' && isDictWord(data[2:]):
		// QNameDictionaryText 0xBC: prefix char + index
		return 0xBC, append([]byte{data[0] - 'a'}, encodeMBI(inverted[data[2:]])...)
	case matchAtStart(reUniqueID, data):
		return 0xAC, guidBytes(data[len("urn:uuid:"):]) // UniqueIdText
	case matchAtStart(reUUID, data):
		return 0xB0, guidBytes(data) // UuidText
	case matchAtStart(reInt, data):
		return intRecord(data)
	case data == "":
		return 0xA8, nil // EmptyText
	case b64ok:
		return bytesRecord(data)
	case matchAtStart(reFloat, data):
		// DoubleText 0x92
		f, _ := strconv.ParseFloat(data, 64)
		return 0x92, le64(math.Float64bits(f))
	case isDictWord(data):
		return 0xAA, encodeMBI(inverted[data]) // DictionaryText
	default:
		return charsRecord(data)
	}
}

func isDictWord(s string) bool {
	_, ok := inverted[s]
	return ok
}

// intRecord picks the narrowest signed integer record, or falls back to chars
// when the value overflows int64 (matching the reference).
func intRecord(data string) (byte, []byte) {
	v, err := strconv.ParseInt(data, 10, 64)
	if err != nil {
		return charsRecord(data) // out of int64 range
	}
	switch {
	case v >= -128 && v <= 127:
		return 0x88, []byte{byte(int8(v))} // Int8
	case v >= -32768 && v <= 32767:
		return 0x8A, le16(uint16(int16(v))) // Int16
	case v >= -2147483648 && v <= 2147483647:
		return 0x8C, le32(uint32(int32(v))) // Int32
	default:
		return 0x8E, le64(uint64(v)) // Int64
	}
}

// charsRecord picks Chars8/16/32 by UTF-8 byte length.
func charsRecord(data string) (byte, []byte) {
	b := []byte(data)
	switch n := len(b); {
	case n < 1<<8:
		return 0x98, append([]byte{byte(n)}, b...) // Chars8
	case n < 1<<16:
		return 0x9A, append(le16(uint16(n)), b...) // Chars16
	default:
		return 0x9C, append(le32(uint32(n)), b...) // Chars32
	}
}

// bytesRecord picks Bytes8/16/32 by decoded length.
func bytesRecord(data string) (byte, []byte) {
	raw, _ := base64.StdEncoding.DecodeString(data)
	switch n := len(raw); {
	case n < 1<<8:
		return 0x9E, append([]byte{byte(n)}, raw...) // Bytes8
	case n < 1<<16:
		return 0xA0, append(le16(uint16(n)), raw...) // Bytes16
	default:
		return 0xA2, append(le32(uint32(n)), raw...) // Bytes32
	}
}

// guidBytes packs a canonical GUID string into the 16-byte mixed-endian layout
// (uint32 LE, uint16 LE, uint16 LE, then 8 bytes big-endian). [MS-DTYP] GUID.
func guidBytes(g string) []byte {
	m := reUUID.FindStringSubmatch(g)
	if m == nil {
		return make([]byte, 16)
	}
	out := make([]byte, 0, 16)
	d1, _ := strconv.ParseUint(m[1], 16, 32)
	d2, _ := strconv.ParseUint(m[2], 16, 16)
	d3, _ := strconv.ParseUint(m[3], 16, 16)
	out = append(out, le32(uint32(d1))...)
	out = append(out, le16(uint16(d2))...)
	out = append(out, le16(uint16(d3))...)
	for i := 0; i < len(m[4]); i += 2 {
		v, _ := strconv.ParseUint(m[4][i:i+2], 16, 8)
		out = append(out, byte(v))
	}
	for i := 0; i < len(m[5]); i += 2 {
		v, _ := strconv.ParseUint(m[5][i:i+2], 16, 8)
		out = append(out, byte(v))
	}
	return out
}
