package adws

import (
	"bytes"
	"io"
	"testing"
)

// mockTransport replays canned responses, one per Send/Recv round-trip.
type mockTransport struct {
	responses []string
	i         int
	sent      []string
}

func (m *mockTransport) Send(s string) error { m.sent = append(m.sent, s); return nil }
func (m *mockTransport) Recv() (string, error) {
	if m.i >= len(m.responses) {
		return "", io.EOF
	}
	r := m.responses[m.i]
	m.i++
	return r, nil
}

const nsDecls = `xmlns:s="http://www.w3.org/2003/05/soap-envelope" ` +
	`xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration" ` +
	`xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" ` +
	`xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" ` +
	`xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"`

const rootDSEResponse = `<s:Envelope ` + nsDecls + `><s:Body>
  <addata:defaultNamingContext><ad:value>DC=corp,DC=local</ad:value></addata:defaultNamingContext>
  <addata:configurationNamingContext><ad:value>CN=Configuration,DC=corp,DC=local</ad:value></addata:configurationNamingContext>
  <addata:namingContexts><ad:value>DC=corp,DC=local</ad:value><ad:value>CN=Configuration,DC=corp,DC=local</ad:value></addata:namingContexts>
</s:Body></s:Envelope>`

const enumerateResponse = `<s:Envelope ` + nsDecls + `><s:Body>
  <wsen:EnumerateResponse><wsen:EnumerationContext>ctx-abc</wsen:EnumerationContext></wsen:EnumerateResponse>
</s:Body></s:Envelope>`

// page 1: two users, no EndOfSequence.
const pullPage1 = `<s:Envelope ` + nsDecls + `><s:Body><wsen:PullResponse>
  <wsen:EnumerationContext>ctx-abc</wsen:EnumerationContext>
  <wsen:Items>
    <addata:user>
      <addata:distinguishedName><ad:value>CN=Alice,DC=corp,DC=local</ad:value></addata:distinguishedName>
      <addata:sAMAccountName><ad:value>alice</ad:value></addata:sAMAccountName>
      <addata:objectClass><ad:value>top</ad:value><ad:value>person</ad:value><ad:value>user</ad:value></addata:objectClass>
      <addata:objectSid><ad:value xsi:type="ad:base64Binary">AQIDBA==</ad:value></addata:objectSid>
    </addata:user>
    <addata:user>
      <addata:distinguishedName><ad:value>CN=Bob,DC=corp,DC=local</ad:value></addata:distinguishedName>
      <addata:sAMAccountName><ad:value>bob</ad:value></addata:sAMAccountName>
    </addata:user>
  </wsen:Items>
</wsen:PullResponse></s:Body></s:Envelope>`

// page 2: one user, EndOfSequence present.
const pullPage2 = `<s:Envelope ` + nsDecls + `><s:Body><wsen:PullResponse>
  <wsen:Items>
    <addata:user>
      <addata:distinguishedName><ad:value>CN=Carol,DC=corp,DC=local</ad:value></addata:distinguishedName>
      <addata:sAMAccountName><ad:value>carol</ad:value></addata:sAMAccountName>
    </addata:user>
  </wsen:Items>
  <wsen:EndOfSequence></wsen:EndOfSequence>
</wsen:PullResponse></s:Body></s:Envelope>`

const faultResponse = `<s:Envelope ` + nsDecls + `><s:Body>
  <s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code>
    <s:Reason><s:Text xml:lang="en">Invalid filter</s:Text></s:Reason></s:Fault>
</s:Body></s:Envelope>`

const referralResponse = `<s:Envelope ` + nsDecls + `><s:Body>
  <s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code>
    <s:Reason><s:Text xml:lang="en">A referral was returned</s:Text></s:Reason>
    <s:Detail><ad:DirectoryError><ad:Win32ErrorCode>8235</ad:Win32ErrorCode></ad:DirectoryError></s:Detail>
  </s:Fault>
</s:Body></s:Envelope>`

func TestRootDSE(t *testing.T) {
	c := NewClient(&mockTransport{responses: []string{rootDSEResponse}}, "dc.corp.local", 256)
	rd, err := c.RootDSE()
	if err != nil {
		t.Fatal(err)
	}
	if rd.DefaultNamingContext != "DC=corp,DC=local" {
		t.Errorf("defaultNamingContext = %q", rd.DefaultNamingContext)
	}
	if rd.ConfigurationNamingContext != "CN=Configuration,DC=corp,DC=local" {
		t.Errorf("configurationNamingContext = %q", rd.ConfigurationNamingContext)
	}
	if len(rd.NamingContexts) != 2 {
		t.Errorf("namingContexts = %v", rd.NamingContexts)
	}
}

func TestQueryPaging(t *testing.T) {
	tr := &mockTransport{responses: []string{enumerateResponse, pullPage1, pullPage2}}
	c := NewClient(tr, "dc.corp.local", 256)

	objects, err := c.Query("DC=corp,DC=local", "(objectClass=user)",
		[]string{"distinguishedName", "sAMAccountName", "objectClass", "objectSid"})
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 3 {
		t.Fatalf("got %d objects, want 3", len(objects))
	}

	names := []string{objects[0].First("sAMAccountName"), objects[1].First("sAMAccountName"), objects[2].First("sAMAccountName")}
	want := []string{"alice", "bob", "carol"}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("object %d sAMAccountName = %q, want %q", i, names[i], want[i])
		}
	}

	if dn := objects[0].DN(); dn != "CN=Alice,DC=corp,DC=local" {
		t.Errorf("alice DN = %q", dn)
	}

	// Multi-valued objectClass.
	oc := objects[0].Attributes["objectClass"]
	if len(oc) != 3 || oc[2].Text != "user" {
		t.Errorf("objectClass = %+v", oc)
	}

	// Binary objectSid decoded from base64 "AQIDBA==" -> 01 02 03 04.
	sid := objects[0].Attributes["objectSid"]
	if len(sid) != 1 || !sid[0].IsBinary || !bytes.Equal(sid[0].Binary, []byte{1, 2, 3, 4}) {
		t.Errorf("objectSid = %+v", sid)
	}

	// The three requests were Enumerate then two Pulls.
	if len(tr.sent) != 3 {
		t.Errorf("sent %d requests, want 3", len(tr.sent))
	}
}

func TestQueryFault(t *testing.T) {
	c := NewClient(&mockTransport{responses: []string{faultResponse}}, "dc.corp.local", 256)
	_, err := c.Query("DC=corp,DC=local", "(bad", nil)
	if err == nil {
		t.Fatal("expected fault error")
	}
	f, ok := err.(*soapFault)
	if !ok || f.reason != "Invalid filter" {
		t.Errorf("err = %v", err)
	}
}

func TestQueryReferralIsTerminal(t *testing.T) {
	// Enumerate succeeds, first Pull returns a referral: treated as empty + done.
	tr := &mockTransport{responses: []string{enumerateResponse, referralResponse}}
	c := NewClient(tr, "dc.corp.local", 256)
	objects, err := c.Query("DC=child,DC=corp,DC=local", "(objectClass=*)", nil)
	if err != nil {
		t.Fatalf("referral should not error: %v", err)
	}
	if len(objects) != 0 {
		t.Errorf("got %d objects, want 0", len(objects))
	}
}

func TestEnumerateRequestContents(t *testing.T) {
	tr := &mockTransport{responses: []string{enumerateResponse, pullPage2}}
	c := NewClient(tr, "dc.corp.local", 256)
	if _, err := c.Query("DC=corp,DC=local", "(objectClass=user)", []string{"sAMAccountName", "objectSid"}); err != nil {
		t.Fatal(err)
	}
	req := tr.sent[0]
	for _, want := range []string{
		"<adlq:Filter>(objectClass=user)</adlq:Filter>",
		"<adlq:BaseObject>DC=corp,DC=local</adlq:BaseObject>",
		"<ad:SelectionProperty>addata:sAMAccountName</ad:SelectionProperty>",
		"<ad:SelectionProperty>addata:objectSid</ad:SelectionProperty>",
	} {
		if !bytes.Contains([]byte(req), []byte(want)) {
			t.Errorf("Enumerate request missing %q", want)
		}
	}
}
