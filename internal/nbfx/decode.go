package nbfx

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

// --- decode record tree ---

type dNode interface{ isDNode() }

type dElem struct {
	prefix    string
	name      string
	dictSpace bool // ShortDictionaryElement formats an extra space after the name
	attrs     []string
	kids      []dNode
}

type dLeaf struct{ s string } // already-formatted text or comment

func (*dElem) isDNode() {}
func (*dLeaf) isDNode() {}

// reader is a cursor over the record bytes that records the first short read.
type reader struct {
	data []byte
	pos  int
	err  error
}

func (r *reader) u8() byte {
	if r.err != nil || r.pos >= len(r.data) {
		r.fail()
		return 0
	}
	b := r.data[r.pos]
	r.pos++
	return b
}

func (r *reader) take(n int) []byte {
	if r.err != nil || n < 0 || r.pos+n > len(r.data) {
		r.fail()
		return nil
	}
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b
}

func (r *reader) mbi() uint32 {
	v, n := readMBI(r.data[r.pos:])
	if n == 0 {
		r.fail()
		return 0
	}
	r.pos += n
	return uint32(v)
}

func (r *reader) utf8() string { return string(r.take(int(r.mbi()))) }

func (r *reader) fail() {
	if r.err == nil {
		r.err = fmt.Errorf("nbfx: unexpected end of records at offset %d", r.pos)
	}
}

// decodeRecords parses the record stream into a tree and serializes it back to
// XML text. inband is the MC-NBFSE session dictionary (odd indices), or nil.
func decodeRecords(data []byte, inband map[uint32]string) (string, error) {
	r := &reader{data: data}
	var root []dNode
	var stack []*dElem

	appendChild := func(n dNode) {
		if len(stack) == 0 {
			root = append(root, n)
		} else {
			top := stack[len(stack)-1]
			top.kids = append(top.kids, n)
		}
	}
	pop := func() {
		if len(stack) > 0 {
			stack = stack[:len(stack)-1]
		}
	}

	for r.pos < len(r.data) && r.err == nil {
		t := r.u8()
		switch {
		case t == 0x01: // EndElement
			pop()
		case t == 0x02: // Comment
			appendChild(&dLeaf{s: "<!-- " + r.utf8() + " -->"})
		case t == 0x03: // Array
			appendChild(&dLeaf{s: r.array(inband)})
		case t >= 0x04 && t <= 0x3F: // Attribute
			a := r.attribute(t, inband)
			if len(stack) > 0 {
				top := stack[len(stack)-1]
				top.attrs = append(top.attrs, a)
			}
		case t >= 0x40 && t <= 0x77: // Element
			el := r.element(t, inband)
			appendChild(el)
			stack = append(stack, el)
		case t >= 0x80: // Value record
			base := t
			withEnd := t%2 == 1
			if withEnd {
				base = t - 1
			}
			appendChild(&dLeaf{s: r.text(base, inband)})
			if withEnd {
				pop()
			}
		default:
			r.err = fmt.Errorf("nbfx: unknown record type 0x%02x at offset %d", t, r.pos-1)
		}
	}
	if r.err != nil {
		return "", r.err
	}
	return serialize(root), nil
}

// lookupDict resolves a dictionary index: even indices are static [MC-NBFS]
// strings, odd indices come from the [MC-NBFSE] session dictionary.
func lookupDict(idx uint32, inband map[uint32]string) string {
	if idx%2 == 0 {
		if s, ok := dictionary[idx]; ok {
			return s
		}
	} else if inband != nil {
		if s, ok := inband[idx]; ok {
			return s
		}
	}
	return fmt.Sprintf("[[VALUE_0x%02x]]", idx)
}

func (r *reader) element(t byte, inband map[uint32]string) *dElem {
	switch {
	case t == 0x40: // ShortElement
		return &dElem{name: r.utf8()}
	case t == 0x41: // Element
		prefix := r.utf8()
		return &dElem{prefix: prefix, name: r.utf8()}
	case t == 0x42: // ShortDictionaryElement
		return &dElem{name: lookupDict(r.mbi(), inband), dictSpace: true}
	case t == 0x43: // DictionaryElement
		prefix := r.utf8()
		return &dElem{prefix: prefix, name: lookupDict(r.mbi(), inband)}
	case t >= 0x44 && t <= 0x5D: // PrefixDictionaryElement[a-z]
		return &dElem{prefix: string(rune('a' + (t - 0x44))), name: lookupDict(r.mbi(), inband)}
	default: // 0x5E..0x77 PrefixElement[a-z]
		return &dElem{prefix: string(rune('a' + (t - 0x5E))), name: r.utf8()}
	}
}

func (r *reader) attribute(t byte, inband map[uint32]string) string {
	// quote wraps an already-escaped value in literal double quotes, matching
	// the reference '%s="%s"' formatting (not Go's %q escaping).
	quote := func(s string) string { return `"` + s + `"` }
	val := func() string { return r.text(r.textBase(), inband) }
	switch {
	case t == 0x04: // ShortAttribute
		name := r.utf8()
		return name + "=" + quote(val())
	case t == 0x05: // Attribute
		prefix := r.utf8()
		name := r.utf8()
		return prefix + ":" + name + "=" + quote(val())
	case t == 0x06: // ShortDictionaryAttribute
		name := lookupDict(r.mbi(), inband)
		return name + "=" + quote(val())
	case t == 0x07: // DictionaryAttribute
		prefix := r.utf8()
		name := lookupDict(r.mbi(), inband)
		return prefix + ":" + name + "=" + quote(val())
	case t == 0x08: // ShortXmlnsAttribute
		return "xmlns=" + quote(r.utf8())
	case t == 0x09: // XmlnsAttribute
		name := r.utf8()
		return "xmlns:" + name + "=" + quote(r.utf8())
	case t == 0x0A: // ShortDictionaryXmlnsAttribute
		return "xmlns=" + quote(lookupDict(r.mbi(), inband))
	case t == 0x0B: // DictionaryXmlnsAttribute
		prefix := r.utf8()
		return "xmlns:" + prefix + "=" + quote(lookupDict(r.mbi(), inband))
	case t >= 0x0C && t <= 0x25: // PrefixDictionaryAttribute[a-z]
		prefix := string(rune('a' + (t - 0x0C)))
		name := lookupDict(r.mbi(), inband)
		return prefix + ":" + name + "=" + quote(val())
	default: // 0x26..0x3F PrefixAttribute[a-z]
		prefix := string(rune('a' + (t - 0x26)))
		name := r.utf8()
		return prefix + ":" + name + "=" + quote(val())
	}
}

// textBase reads a value record's type byte and returns its base type, handling
// the WithEndElement form (used for attribute values, which never end an element
// but reuse the value encoding).
func (r *reader) textBase() byte {
	t := r.u8()
	if t%2 == 1 {
		return t - 1
	}
	return t
}

func (r *reader) text(base byte, inband map[uint32]string) string {
	switch base {
	case 0x80:
		return "0"
	case 0x82:
		return "1"
	case 0x84:
		return "false"
	case 0x86:
		return "true"
	case 0x88:
		return strconv.FormatInt(int64(int8(r.u8())), 10)
	case 0x8A:
		return strconv.FormatInt(int64(int16(binary.LittleEndian.Uint16(r.take(2)))), 10)
	case 0x8C:
		return strconv.FormatInt(int64(int32(binary.LittleEndian.Uint32(r.take(4)))), 10)
	case 0x8E:
		return strconv.FormatInt(int64(binary.LittleEndian.Uint64(r.take(8))), 10)
	case 0xB2:
		return strconv.FormatUint(binary.LittleEndian.Uint64(r.take(8)), 10)
	case 0xB4:
		if r.u8() == 1 {
			return "True"
		}
		return "False"
	case 0xB6:
		return sanitizeXML(decodeUTF16(r.take(int(r.u8()))))
	case 0xB8:
		return sanitizeXML(decodeUTF16(r.take(int(binary.LittleEndian.Uint16(r.take(2))))))
	case 0xBA:
		return sanitizeXML(decodeUTF16(r.take(int(binary.LittleEndian.Uint32(r.take(4))))))
	case 0xBC:
		prefix := string(rune('a' + r.u8()))
		return prefix + ":" + lookupDict(r.mbi(), inband)
	case 0x90:
		return formatFloat(float64(math.Float32frombits(binary.LittleEndian.Uint32(r.take(4)))))
	case 0x92:
		return formatFloat(math.Float64frombits(binary.LittleEndian.Uint64(r.take(8))))
	case 0x96:
		return formatDateTime(binary.LittleEndian.Uint64(r.take(8)))
	case 0x98:
		return sanitizeXML(string(r.take(int(r.u8()))))
	case 0x9A:
		return sanitizeXML(string(r.take(int(binary.LittleEndian.Uint16(r.take(2))))))
	case 0x9C:
		return sanitizeXML(string(r.take(int(binary.LittleEndian.Uint32(r.take(4))))))
	case 0x9E:
		return base64.StdEncoding.EncodeToString(r.take(int(r.u8())))
	case 0xA0:
		return base64.StdEncoding.EncodeToString(r.take(int(binary.LittleEndian.Uint16(r.take(2)))))
	case 0xA2:
		return base64.StdEncoding.EncodeToString(r.take(int(binary.LittleEndian.Uint32(r.take(4)))))
	case 0xA8:
		return ""
	case 0xAA:
		return lookupDict(r.mbi(), inband)
	case 0xAC:
		return "urn:uuid:" + formatGUID(r.take(16))
	case 0xB0:
		return formatGUID(r.take(16))
	case 0xA4, 0xA6: // StartList / EndList (structural)
		return ""
	default:
		r.err = fmt.Errorf("nbfx: unsupported value record 0x%02x", base)
		return ""
	}
}

// array decodes an ArrayRecord (0x03): an element template repeated over a
// homogeneous list of values. [MC-NBFX] 2.2.3.1 / record.py ArrayRecord.
func (r *reader) array(inband map[uint32]string) string {
	et := r.u8()
	el := r.element(et, inband)
	for r.u8() != 0x01 { // consume until the template's EndElement
		if r.err != nil {
			return ""
		}
	}
	recordType := r.u8()
	count := int(r.mbi())
	var b strings.Builder
	for i := 0; i < count && r.err == nil; i++ {
		b.WriteString(openTag(el))
		b.WriteString(r.text(recordType-1, inband))
		b.WriteString(closeTag(el))
	}
	return b.String()
}

// --- serialization (print_records + record __str__) ---

func serialize(nodes []dNode) string {
	var b strings.Builder
	for _, n := range nodes {
		switch v := n.(type) {
		case *dLeaf:
			b.WriteString(v.s)
		case *dElem:
			b.WriteString(openTag(v))
			b.WriteString(serialize(v.kids))
			b.WriteString(closeTag(v))
		}
	}
	return b.String()
}

func openTag(e *dElem) string {
	attrs := ""
	if len(e.attrs) > 0 {
		attrs = " " + strings.Join(e.attrs, " ")
	}
	switch {
	case e.prefix != "":
		return "<" + e.prefix + ":" + e.name + attrs + ">"
	case e.dictSpace:
		// ShortDictionaryElement renders a space after the name even with no attrs.
		return "<" + e.name + " " + attrs + ">"
	default:
		return "<" + e.name + attrs + ">"
	}
}

func closeTag(e *dElem) string {
	if e.prefix != "" {
		return "</" + e.prefix + ":" + e.name + ">"
	}
	return "</" + e.name + ">"
}

// --- text helpers ---

var reInvalidXML = regexp.MustCompile("[\x00-\x08\x0b\x0c\x0e-\x1f]")

// sanitizeXML mirrors the reference _sanitize_xml_text: drop invalid XML 1.0
// control characters, then escape the five XML special characters.
func sanitizeXML(s string) string {
	s = reInvalidXML.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

func decodeUTF16(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// formatGUID renders the 16-byte mixed-endian GUID layout as a canonical string.
func formatGUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	d1 := binary.LittleEndian.Uint32(b[0:4])
	d2 := binary.LittleEndian.Uint16(b[4:6])
	d3 := binary.LittleEndian.Uint16(b[6:8])
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		d1, d2, d3, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// formatFloat matches the reference's number formatting: integral values print
// without a fractional part.
func formatFloat(f float64) string {
	if f == math.Trunc(f) && !math.IsInf(f, 0) {
		return strconv.FormatFloat(f, 'f', 0, 64)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// formatDateTime renders a .NET binary datetime (ticks since 0001-01-01 in the
// high 62 bits) as an ISO-8601 string, matching the reference formula.
func formatDateTime(raw uint64) string {
	const ticksPerSecond = 10_000_000
	ticks := raw >> 2
	secs := ticks / ticksPerSecond
	frac := ticks % ticksPerSecond
	// Days/seconds since year 1; use a simple civil-time conversion.
	days := secs / 86400
	rem := secs % 86400
	y, mo, d := civilFromDays(int64(days))
	h := rem / 3600
	mi := (rem % 3600) / 60
	s := rem % 60
	out := fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d", y, mo, d, h, mi, s)
	if frac != 0 {
		out += "." + strings.TrimRight(fmt.Sprintf("%07d", frac), "0")
	}
	return out
}

// civilFromDays converts days since 0001-01-01 (day 0) to a proleptic Gregorian
// date.
func civilFromDays(z int64) (year int64, month, day int) {
	z += 306
	era := z / 146097
	doe := z - era*146097
	yoe := (doe - doe/1460 + doe/36524 - doe/146096) / 365
	y := yoe + era*400
	doy := doe - (365*yoe + yoe/4 - yoe/100)
	mp := (5*doy + 2) / 153
	day = int(doy - (153*mp+2)/5 + 1)
	if mp < 10 {
		month = int(mp + 3)
	} else {
		month = int(mp - 9)
	}
	if month <= 2 {
		y++
	}
	return y, month, day
}
