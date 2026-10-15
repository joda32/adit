package nbfx

import (
	"encoding/hex"
	"testing"
)

// Golden vectors from the PyADRecon-ADWS reference encoder (NBFSE, 0x08). See
// scripts/gen_nbfx_vectors.py. Each case pairs an input XML string with the
// exact bytes the reference emits and the exact XML its decoder reconstructs.
type vector struct {
	name string
	xml  string // encoder input
	enc  string // expected encoded bytes (hex)
	dec  string // expected decoder output
}

var vectors = []vector{
	{
		name: "simple",
		xml:  "<a>hello</a>",
		enc:  "0042b601990568656c6c6f",
		dec:  "<a >hello</a>",
	},
	{
		name: "nested",
		xml:  "<Envelope><Header></Header><Body>x</Body></Envelope>",
		enc:  "004202420801420e99017801",
		dec:  "<Envelope ><Header ></Header><Body >x</Body></Envelope>",
	},
	{
		name: "attrs",
		xml:  `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body></s:Body></s:Envelope>`,
		enc:  "0056020b017304560e0101",
		dec:  `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body></s:Body></s:Envelope>`,
	},
	{
		name: "base64val",
		xml:  `<ad:controlValue>MIQAAAADAgEH</ad:controlValue>`,
		enc:  "00410261640c636f6e74726f6c56616c75659f09308400000003020107",
		dec:  `<ad:controlValue>MIQAAAADAgEH</ad:controlValue>`,
	},
	{
		name: "intval",
		xml:  "<n>1234</n>",
		enc:  "0040016e8bd204",
		dec:  "<n>1234</n>",
	},
	{
		name: "rootdse",
		xml: `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
    xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<s:Header>
    <a:Action s:mustUnderstand="1" xmlns="http://www.w3.org/2005/08/addressing">http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action>
    <ad:instance>ldap:389</ad:instance>
    <ad:objectReferenceProperty>11111111-1111-1111-1111-111111111111</ad:objectReferenceProperty>
    <a:MessageID>urn:uuid:11111111-2222-3333-4444-555555555555</a:MessageID>
    <a:ReplyTo>
        <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
    <a:To s:mustUnderstand="1">net.tcp://dc01.domain.local:9389/ActiveDirectoryWebServices/Windows/Resource</a:To>
</s:Header>
    <s:Body></s:Body>
</s:Envelope>`,
		enc: "0056020b0173040b016106090661646461746138687474703a2f2f736368656d61732e6d6963726f736f66742e636f6d2f323030382f312f4163746976654469726563746f72792f446174610902616433687474703a2f2f736368656d61732e6d6963726f736f66742e636f6d2f323030382f312f4163746976654469726563746f72790b03787364f4060b03787369f2065608440a1e00820a069932687474703a2f2f736368656d61732e786d6c736f61702e6f72672f77732f323030342f30392f7472616e736665722f4765744102616408696e7374616e636599086c6461703a33383941026164176f626a6563745265666572656e636550726f7065727479b111111111111111111111111111111111441aad11111111222233334444555555555555442c442aab1401440c1e0082994c6e65742e7463703a2f2f646330312e646f6d61696e2e6c6f63616c3a393338392f4163746976654469726563746f727957656253657276696365732f57696e646f77732f5265736f7572636501560e0101",
		dec: `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><s:Header><a:Action s:mustUnderstand="1" xmlns="http://www.w3.org/2005/08/addressing">http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action><ad:instance>ldap:389</ad:instance><ad:objectReferenceProperty>11111111-1111-1111-1111-111111111111</ad:objectReferenceProperty><a:MessageID>urn:uuid:11111111-2222-3333-4444-555555555555</a:MessageID><a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo><a:To s:mustUnderstand="1">net.tcp://dc01.domain.local:9389/ActiveDirectoryWebServices/Windows/Resource</a:To></s:Header><s:Body></s:Body></s:Envelope>`,
	},
	{
		name: "query",
		xml: `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
    xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</a:Action>
        <ad:instance>ldap:389</ad:instance>
        <a:MessageID>urn:uuid:11111111-2222-3333-4444-555555555555</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">net.tcp://dc01.domain.local:9389/ActiveDirectoryWebServices/Windows/Enumeration</a:To>
    </s:Header>
    <s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
        xmlns:adlq="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery">
        <wsen:Enumerate>
            <wsen:Filter Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery">
                <adlq:LdapQuery>
                    <adlq:Filter>(objectClass=user)</adlq:Filter>
                    <adlq:BaseObject>DC=domain,DC=local</adlq:BaseObject>
                    <adlq:Scope>Subtree</adlq:Scope>
                </adlq:LdapQuery>
            </wsen:Filter>
            <ad:Selection Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1">
                <ad:SelectionProperty>addata:distinguishedName</ad:SelectionProperty>
<ad:SelectionProperty>addata:objectClass</ad:SelectionProperty>
<ad:SelectionProperty>addata:sAMAccountName</ad:SelectionProperty>

            </ad:Selection>
        </wsen:Enumerate>
    </s:Body>
</s:Envelope>`,
		enc: "0056020b0173040b016106090661646461746138687474703a2f2f736368656d61732e6d6963726f736f66742e636f6d2f323030382f312f4163746976654469726563746f72792f446174610902616433687474703a2f2f736368656d61732e6d6963726f736f66742e636f6d2f323030382f312f4163746976654469726563746f72790b03787364f4060b03787369f2065608440a1e0082993b687474703a2f2f736368656d61732e786d6c736f61702e6f72672f77732f323030342f30392f656e756d65726174696f6e2f456e756d65726174654102616408696e7374616e636599086c6461703a333839441aad11111111222233334444555555555555442c442aab1401440c1e0082994f6e65742e7463703a2f2f646330312e646f6d61696e2e6c6f63616c3a393338392f4163746976654469726563746f727957656253657276696365732f57696e646f77732f456e756d65726174696f6e01560e09047773656e31687474703a2f2f736368656d61732e786d6c736f61702e6f72672f77732f323030342f30392f656e756d65726174696f6e090461646c7145687474703a2f2f736368656d61732e6d6963726f736f66742e636f6d2f323030382f312f4163746976654469726563746f72792f4469616c6563742f4c646170517565727941047773656e09456e756d657261746541047773656e0646696c74657204074469616c6563749845687474703a2f2f736368656d61732e6d6963726f736f66742e636f6d2f323030382f312f4163746976654469726563746f72792f4469616c6563742f4c6461705175657279410461646c71094c6461705175657279410461646c710646696c7465729912286f626a656374436c6173733d7573657229410461646c710a426173654f626a656374991244433d646f6d61696e2c44433d6c6f63616c410461646c710553636f70659907537562747265650101410261640953656c656374696f6e04074469616c6563749849687474703a2f2f736368656d61732e6d6963726f736f66742e636f6d2f323030382f312f4163746976654469726563746f72792f4469616c6563742f58506174682d4c6576656c2d31410261641153656c656374696f6e50726f706572747999186164646174613a64697374696e677569736865644e616d65410261641153656c656374696f6e50726f706572747999126164646174613a6f626a656374436c617373410261641153656c656374696f6e50726f706572747999156164646174613a73414d4163636f756e744e616d6501010101",
		dec: `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><s:Header><a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</a:Action><ad:instance>ldap:389</ad:instance><a:MessageID>urn:uuid:11111111-2222-3333-4444-555555555555</a:MessageID><a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo><a:To s:mustUnderstand="1">net.tcp://dc01.domain.local:9389/ActiveDirectoryWebServices/Windows/Enumeration</a:To></s:Header><s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:adlq="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery"><wsen:Enumerate><wsen:Filter Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery"><adlq:LdapQuery><adlq:Filter>(objectClass=user)</adlq:Filter><adlq:BaseObject>DC=domain,DC=local</adlq:BaseObject><adlq:Scope>Subtree</adlq:Scope></adlq:LdapQuery></wsen:Filter><ad:Selection Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1"><ad:SelectionProperty>addata:distinguishedName</ad:SelectionProperty><ad:SelectionProperty>addata:objectClass</ad:SelectionProperty><ad:SelectionProperty>addata:sAMAccountName</ad:SelectionProperty></ad:Selection></wsen:Enumerate></s:Body></s:Envelope>`,
	},
	{
		name: "pull",
		xml: `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
    xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull</a:Action>
        <ad:instance>ldap:389</ad:instance>
        <a:MessageID>urn:uuid:11111111-2222-3333-4444-555555555555</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">net.tcp://dc01.domain.local:9389/ActiveDirectoryWebServices/Windows/Enumeration</a:To>
    </s:Header>
    <s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
        <wsen:Pull>
            <wsen:EnumerationContext>00000000-0000-0000-0000-000000000000</wsen:EnumerationContext>
            <wsen:MaxElements>256</wsen:MaxElements>
                <ad:controls>
                    <ad:control criticality="true" type="1.2.840.113556.1.4.801">
                       <ad:controlValue xsi:type="xsd:base64Binary">MIQAAAADAgEH</ad:controlValue>
                </ad:control>
        </wsen:Pull>
    </s:Body>
</s:Envelope>`,
		enc: "0056020b0173040b016106090661646461746138687474703a2f2f736368656d61732e6d6963726f736f66742e636f6d2f323030382f312f4163746976654469726563746f72792f446174610902616433687474703a2f2f736368656d61732e6d6963726f736f66742e636f6d2f323030382f312f4163746976654469726563746f72790b03787364f4060b03787369f2065608440a1e00829936687474703a2f2f736368656d61732e786d6c736f61702e6f72672f77732f323030342f30392f656e756d65726174696f6e2f50756c6c4102616408696e7374616e636599086c6461703a333839441aad11111111222233334444555555555555442c442aab1401440c1e0082994f6e65742e7463703a2f2f646330312e646f6d61696e2e6c6f63616c3a393338392f4163746976654469726563746f727957656253657276696365732f57696e646f77732f456e756d65726174696f6e01560e09047773656e31687474703a2f2f736368656d61732e786d6c736f61702e6f72672f77732f323030342f30392f656e756d65726174696f6e41047773656e0450756c6c41047773656e12456e756d65726174696f6e436f6e74657874b10000000000000000000000000000000041047773656e0b4d6178456c656d656e74738b00014102616408636f6e74726f6c734102616407636f6e74726f6c040b637269746963616c6974798606f8069816312e322e3834302e3131333535362e312e342e383031410261640c636f6e74726f6c56616c75650703787369f80698107873643a62617365363442696e6172799f093084000000030201070101010101",
		dec: `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><s:Header><a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull</a:Action><ad:instance>ldap:389</ad:instance><a:MessageID>urn:uuid:11111111-2222-3333-4444-555555555555</a:MessageID><a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo><a:To s:mustUnderstand="1">net.tcp://dc01.domain.local:9389/ActiveDirectoryWebServices/Windows/Enumeration</a:To></s:Header><s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration"><wsen:Pull><wsen:EnumerationContext>00000000-0000-0000-0000-000000000000</wsen:EnumerationContext><wsen:MaxElements>256</wsen:MaxElements><ad:controls><ad:control criticality="true" type="1.2.840.113556.1.4.801"><ad:controlValue xsi:type="xsd:base64Binary">MIQAAAADAgEH</ad:controlValue></ad:control></ad:controls></wsen:Pull></s:Body></s:Envelope>`,
	},
}

func TestEncode(t *testing.T) {
	enc := New(NBFSE)
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			got, err := enc.Encode(v.xml)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if hex.EncodeToString(got) != v.enc {
				t.Errorf("Encode mismatch\n got=%s\nwant=%s", hex.EncodeToString(got), v.enc)
			}
		})
	}
}

func TestDecode(t *testing.T) {
	enc := New(NBFSE)
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			raw, err := hex.DecodeString(v.enc)
			if err != nil {
				t.Fatal(err)
			}
			got, err := enc.Decode(raw)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if got != v.dec {
				t.Errorf("Decode mismatch\n got=%q\nwant=%q", got, v.dec)
			}
		})
	}
}

// TestRoundTrip decodes the golden bytes and re-encodes the result, which must
// reproduce the original bytes — proving Decode yields a re-encodable equivalent.
func TestRoundTrip(t *testing.T) {
	enc := New(NBFSE)
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			raw, _ := hex.DecodeString(v.enc)
			xml, err := enc.Decode(raw)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			reencoded, err := enc.Encode(xml)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if hex.EncodeToString(reencoded) != v.enc {
				t.Errorf("round trip changed bytes\n got=%s\nwant=%s", hex.EncodeToString(reencoded), v.enc)
			}
		})
	}
}

// TestDecodeMalformedNoPanic feeds truncated and hostile NBFSE inputs and
// requires Decode to return (not panic or hang). Regressions guarded:
//   - fixed-width value records (Int16/32/64, Float, DateTime, Chars/Bytes16/32)
//     used to index past a short buffer in binary.LittleEndian;
//   - an Array record used to loop on an attacker-controlled element count.
func TestDecodeMalformedNoPanic(t *testing.T) {
	enc := New(NBFSE)
	inputs := map[string][]byte{
		"int16-no-payload":   {0x00, 0x8A},
		"int32-truncated":    {0x00, 0x8C, 0x01},
		"int64-no-payload":   {0x00, 0x8E},
		"datetime-truncated": {0x00, 0x96, 0x01, 0x02},
		"chars16-bad-len":    {0x00, 0x9A, 0xff},
		"bytes32-bad-len":    {0x00, 0xA2, 0xff, 0xff, 0xff, 0x7f},
		// Array of ZeroText (0-byte elements) with a large count: pre-fix this
		// looped ~2^28 times building a string; now bounded by the buffer.
		"array-huge-count": {0x00, 0x03, 0x40, 0x01, 0x61, 0x01, 0x81, 0xff, 0xff, 0xff, 0x7f},
	}
	for name, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: panicked: %v", name, r)
				}
			}()
			_, _ = enc.Decode(in) // an error is fine; a panic/hang is not
		}()
	}
}

func TestMBIRoundTrip(t *testing.T) {
	for _, n := range []uint32{0, 1, 0x7f, 0x80, 0x376, 0x3fff, 0x4000, 0xfffff} {
		enc := encodeMBI(n)
		got, consumed := readMBI(enc)
		if uint32(got) != n || consumed != len(enc) {
			t.Errorf("MBI %d -> %x -> %d (consumed %d)", n, enc, got, consumed)
		}
	}
}
