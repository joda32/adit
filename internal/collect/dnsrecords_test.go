package collect_test

import (
	"encoding/binary"
	"net"
	"testing"

	"adit/internal/adws"
	"adit/internal/collect"
)

// dnsBlob builds a DNS_RPC_RECORD blob (header + rdata).
func dnsBlob(recordType uint16, serial, ttl, timestamp uint32, rdata []byte) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint16(b[0:2], uint16(len(rdata)))
	binary.LittleEndian.PutUint16(b[2:4], recordType)
	b[4] = 5    // version
	b[5] = 0xf0 // rank
	binary.LittleEndian.PutUint32(b[8:12], serial)
	binary.LittleEndian.PutUint32(b[12:16], ttl)
	binary.LittleEndian.PutUint32(b[20:24], timestamp)
	return append(b, rdata...)
}

func binVal(b []byte) []adws.Value { return []adws.Value{{Binary: b, IsBinary: true}} }

func TestDNSRecords(t *testing.T) {
	aStatic := dnsBlob(1, 100, 3600, 0, net.ParseIP("192.168.1.10").To4())
	aTimed := dnsBlob(1, 101, 1200, 3700000, net.ParseIP("10.0.0.5").To4())
	aaaa := dnsBlob(28, 102, 900, 0, net.ParseIP("2001:db8::1").To16())

	node := func(name string, records ...[]byte) *adws.Object {
		vals := make([]adws.Value, len(records))
		for i, r := range records {
			vals[i] = adws.Value{Binary: r, IsBinary: true}
		}
		return &adws.Object{Attributes: map[string][]adws.Value{
			"name":              tv(name),
			"dnsRecord":         vals,
			"distinguishedName": tv("DC=" + name + ",DC=corp,DC=local,CN=MicrosoftDNS"),
		}}
	}

	q := &mockQuerier{fn: func(base, filter string, _ []string) ([]*adws.Object, error) {
		switch {
		case filter == "(objectCategory=dnsZone)" && base == "DC=corp,DC=local":
			return []*adws.Object{{Attributes: map[string][]adws.Value{
				"name":              tv("corp.local"),
				"distinguishedName": tv("DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local"),
			}}}, nil
		case filter == "(objectCategory=dnsNode)":
			return []*adws.Object{
				node("www", aStatic),
				node("mail", aTimed, aaaa), // two records on one node -> two rows
				node("empty"),              // no dnsRecord -> one empty row
			}, nil
		}
		return nil, nil
	}}

	tbl, err := collect.New(q, "DC=corp,DC=local", collect.Config{}).DNSRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(tbl.Rows) != 4 {
		t.Fatalf("got %d rows, want 4", len(tbl.Rows))
	}

	// www A (static)
	rowEq(t, tbl, 0, map[string]string{
		"ZoneName": "corp.local", "Name": "www", "RecordType": "A",
		"Data": "192.168.1.10", "TTL": "3600", "TimeStamp": "[static]", "UpdatedAtSerial": "100",
	})
	// mail A (timestamped): 3,700,000 hours since 1601 -> 2023-02-04 16:00 UTC
	rowEq(t, tbl, 1, map[string]string{
		"Name": "mail", "RecordType": "A", "Data": "10.0.0.5",
		"Age": "3700000", "TimeStamp": "02/04/2023 04:00:00 PM",
	})
	// mail AAAA
	rowEq(t, tbl, 2, map[string]string{
		"Name": "mail", "RecordType": "AAAA", "Data": "2001:0db8:0000:0000:0000:0000:0000:0001",
	})
	// empty node
	rowEq(t, tbl, 3, map[string]string{
		"Name": "empty", "RecordType": "", "Data": "",
	})
}

func TestParseDNSNameViaSRV(t *testing.T) {
	// SRV rdata: priority, weight, port (big-endian), then a length-prefixed
	// name "_ldap.corp.local" starting at offset 8 (2-byte count header + labels).
	// rdata: priority, weight, port (big-endian), a 2-byte DNS_COUNT_NAME header
	// (bytes 6-7, skipped by the parser's offset 8), then length-prefixed labels.
	rdata := make([]byte, 8)
	binary.BigEndian.PutUint16(rdata[0:2], 0)   // priority
	binary.BigEndian.PutUint16(rdata[2:4], 100) // weight
	binary.BigEndian.PutUint16(rdata[4:6], 389) // port
	var name []byte
	for _, label := range []string{"dc01", "corp", "local"} {
		name = append(name, byte(len(label)))
		name = append(name, []byte(label)...)
	}
	name = append(name, 0)
	rdata = append(rdata, name...)

	blob := dnsBlob(33, 1, 600, 0, rdata)
	node := &adws.Object{Attributes: map[string][]adws.Value{
		"name":      tv("_ldap"),
		"dnsRecord": binVal(blob),
	}}
	q := &mockQuerier{fn: func(_, filter string, _ []string) ([]*adws.Object, error) {
		switch filter {
		case "(objectCategory=dnsZone)":
			return []*adws.Object{{Attributes: map[string][]adws.Value{
				"name": tv("z"), "distinguishedName": tv("DC=z"),
			}}}, nil
		case "(objectCategory=dnsNode)":
			return []*adws.Object{node}, nil
		}
		return nil, nil
	}}
	tbl, err := collect.New(q, "DC=corp,DC=local", collect.Config{}).DNSRecords()
	if err != nil {
		t.Fatal(err)
	}
	if got := cell(t, tbl, 0, "Data"); got != "[0][100][389][dc01.corp.local.]" {
		t.Errorf("SRV Data = %q", got)
	}
}
