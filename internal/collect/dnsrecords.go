package collect

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// DNSRecords parses the binary dnsRecord blobs under each DNS zone.
func (c *Collector) DNSRecords() (*Table, error) {
	t := &Table{Name: "DNSRecords", Headers: []string{
		"ZoneName", "Name", "RecordType", "Data", "TTL", "Age", "TimeStamp",
		"UpdatedAtSerial", "whenCreated", "whenChanged", "showInAdvancedViewOnly", "DistinguishedName",
	}}

	for _, z := range c.dnsZoneRefs() {
		nodes, err := c.q.Query(z.dn, "(objectCategory=dnsNode)",
			[]string{"name", "dnsRecord", "dNSTombstoned", "whenCreated", "whenChanged",
				"showInAdvancedViewOnly", "distinguishedName"})
		if err != nil {
			continue // a zone we can't read is not fatal
		}
		for _, node := range nodes {
			name := text(node, "name")
			whenCreated := whenStr(node, "whenCreated")
			whenChanged := whenStr(node, "whenChanged")
			showAdvanced := "TRUE"
			if v := text(node, "showInAdvancedViewOnly"); v != "" {
				showAdvanced = strings.ToUpper(v)
			}
			dn := text(node, "distinguishedName")

			records := node.Attributes["dnsRecord"]
			if len(records) == 0 {
				t.Rows = append(t.Rows, []string{
					z.name, name, "", "", "", "", "", "", whenCreated, whenChanged, showAdvanced, dn,
				})
				continue
			}
			for _, rec := range records {
				if !rec.IsBinary {
					continue
				}
				p := parseDNSRecord(rec.Binary)
				if p == nil {
					continue
				}
				t.Rows = append(t.Rows, []string{
					z.name, name, p.recordType, p.data, itoa64(p.ttl), itoa64(p.age),
					p.timestamp, itoa64(p.serial), whenCreated, whenChanged, showAdvanced, dn,
				})
			}
		}
	}
	return t, nil
}

// zoneRef is a DNS zone's name and DN.
type zoneRef struct{ name, dn string }

// dnsZoneRefs lists DNS zones across the domain, DomainDnsZones and
// ForestDnsZones partitions.
func (c *Collector) dnsZoneRefs() []zoneRef {
	bases := []string{c.baseDN, "DC=DomainDnsZones," + c.baseDN}
	if c.cfg.RootDomainDN != "" {
		bases = append(bases, "DC=ForestDnsZones,"+c.cfg.RootDomainDN)
	}
	var zones []zoneRef
	for _, base := range bases {
		objs, err := c.q.Query(base, "(objectCategory=dnsZone)", []string{"name", "distinguishedName"})
		if err != nil {
			continue
		}
		for _, o := range objs {
			zones = append(zones, zoneRef{name: text(o, "name"), dn: text(o, "distinguishedName")})
		}
	}
	return zones
}

// dnsRecord is a parsed DNS_RPC_RECORD ([MS-DNSP] 2.3.2.2).
type dnsRecord struct {
	recordType string
	data       string
	ttl        int64
	age        int64
	timestamp  string
	serial     int64
}

// parseDNSRecord decodes one dnsRecord blob, faithful to PyADRecon-ADWS.
//
// Note: TTL is read little-endian to match the reference. [MS-DNSP] specifies
// dwTtlSeconds as big-endian, so this reproduces a byte-swap present in the
// reference; kept for output parity.
func parseDNSRecord(b []byte) *dnsRecord {
	if len(b) < 24 {
		return nil
	}
	recordType := binary.LittleEndian.Uint16(b[2:4])
	serial := binary.LittleEndian.Uint32(b[8:12])
	ttl := binary.LittleEndian.Uint32(b[12:16])
	timestamp := binary.LittleEndian.Uint32(b[20:24])

	tsStr := "[static]"
	if timestamp != 0 {
		// Hours since 1601-01-01, via Unix seconds to avoid Duration overflow.
		const secs1601ToUnix = -11644473600
		unix := int64(secs1601ToUnix) + int64(timestamp)*3600
		tm := time.Unix(unix, 0).UTC()
		if tm.Year() <= 9999 {
			tsStr = tm.Format("01/02/2006 03:04:05 PM")
		}
	}

	rdata := b[24:]
	typeName, data := parseDNSData(recordType, rdata)

	return &dnsRecord{
		recordType: typeName,
		data:       data,
		ttl:        int64(ttl),
		age:        int64(timestamp),
		timestamp:  tsStr,
		serial:     int64(serial),
	}
}

// parseDNSData decodes the type-specific RDATA.
func parseDNSData(recordType uint16, d []byte) (typeName, data string) {
	switch recordType {
	case 1: // A
		if len(d) >= 4 {
			return "A", fmt.Sprintf("%d.%d.%d.%d", d[0], d[1], d[2], d[3])
		}
		return "A", ""
	case 2: // NS
		s, _ := parseDNSName(d, 2)
		return "NS", s
	case 5: // CNAME
		s, _ := parseDNSName(d, 2)
		return "CNAME", s
	case 6: // SOA
		if len(d) >= 20 {
			serial := binary.BigEndian.Uint32(d[0:4])
			refresh := binary.BigEndian.Uint32(d[4:8])
			retry := binary.BigEndian.Uint32(d[8:12])
			expire := binary.BigEndian.Uint32(d[12:16])
			minimum := binary.BigEndian.Uint32(d[16:20])
			primaryNS, off := parseDNSName(d, 22)
			adminEmail, _ := parseDNSName(d, off+2)
			return "SOA", fmt.Sprintf("[%d][%s][%s][%d][%d][%d][%d]",
				serial, primaryNS, adminEmail, refresh, retry, expire, minimum)
		}
		return "SOA", ""
	case 12: // PTR
		s, _ := parseDNSName(d, 2)
		return "PTR", s
	case 15: // MX
		if len(d) >= 2 {
			pref := binary.BigEndian.Uint16(d[0:2])
			// 2-byte preference, then a DNS_COUNT_NAME (2-byte header + labels);
			// the name's first label-length byte is at offset 4, not 2.
			exchange, _ := parseDNSName(d, 4)
			return "MX", fmt.Sprintf("[%d][%s]", pref, exchange)
		}
		return "MX", ""
	case 16: // TXT
		if len(d) > 0 {
			n := int(d[0])
			if len(d) >= n+1 {
				return "TXT", string(d[1 : n+1])
			}
		}
		return "TXT", ""
	case 28: // AAAA
		if len(d) >= 16 {
			parts := make([]string, 8)
			for i := 0; i < 8; i++ {
				parts[i] = fmt.Sprintf("%04x", binary.BigEndian.Uint16(d[2*i:2*i+2]))
			}
			return "AAAA", strings.Join(parts, ":")
		}
		return "AAAA", ""
	case 33: // SRV
		if len(d) >= 8 {
			priority := binary.BigEndian.Uint16(d[0:2])
			weight := binary.BigEndian.Uint16(d[2:4])
			port := binary.BigEndian.Uint16(d[4:6])
			target, _ := parseDNSName(d, 8)
			return "SRV", fmt.Sprintf("[%d][%d][%d][%s]", priority, weight, port, target)
		}
		return "SRV", ""
	default:
		return fmt.Sprintf("TYPE%d", recordType), hexString(d)
	}
}

// parseDNSName parses a length-prefixed DNS name (with compression pointers)
// starting at offset, returning the dotted name (trailing '.') and next offset.
// Faithful port of the reference's parser.
func parseDNSName(data []byte, offset int) (string, int) {
	return parseDNSNameDepth(data, offset, 0)
}

// parseDNSNameDepth is parseDNSName with a recursion guard: a malformed blob
// whose compression pointers form a cycle (or point to themselves) would
// otherwise recurse until the stack overflows.
func parseDNSNameDepth(data []byte, offset, depth int) (string, int) {
	if len(data) == 0 || offset >= len(data) || depth > 16 {
		return "", offset
	}
	var parts []string
	jumped := false
	savedOffset := 0

	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		if length >= 0xC0 {
			if !jumped {
				savedOffset = offset + 2
			}
			if offset+1 < len(data) {
				pointer := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
				pointed, _ := parseDNSNameDepth(data, pointer, depth+1)
				if pointed != "" && pointed != "." {
					parts = append(parts, strings.TrimRight(pointed, "."))
				}
				jumped = true
				offset = savedOffset
			}
			break
		}
		offset++
		if offset+length > len(data) {
			break
		}
		if label := cleanLabel(data[offset : offset+length]); label != "" {
			parts = append(parts, label)
		}
		offset += length
	}
	if jumped && savedOffset > 0 {
		offset = savedOffset
	}
	result := strings.Join(parts, ".")
	if result != "" && !strings.HasSuffix(result, ".") {
		result += "."
	}
	return result, offset
}

// cleanLabel keeps printable ASCII bytes of a DNS label.
func cleanLabel(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 32 && c < 127 {
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

func hexString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[2*i] = hexdigits[c>>4]
		out[2*i+1] = hexdigits[c&0x0f]
	}
	return string(out)
}

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }
