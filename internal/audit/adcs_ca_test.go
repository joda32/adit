package audit

import (
	"encoding/binary"
	"testing"

	"adit/internal/adws"
	"adit/internal/sd"
)

// --- minimal self-relative security-descriptor builder for tests ---

func allowACE(mask uint32, sid []byte) []byte {
	size := 8 + len(sid)
	a := []byte{sd.AceTypeAccessAllowed, 0x00, byte(size), byte(size >> 8)}
	m := make([]byte, 4)
	binary.LittleEndian.PutUint32(m, mask)
	a = append(a, m...)
	return append(a, sid...)
}

func buildDACL(aces ...[]byte) []byte {
	var body []byte
	for _, a := range aces {
		body = append(body, a...)
	}
	size := 8 + len(body)
	hdr := []byte{2, 0, byte(size), byte(size >> 8), byte(len(aces)), byte(len(aces) >> 8), 0, 0}
	return append(hdr, body...)
}

func buildSD(owner, dacl []byte) []byte {
	header := make([]byte, 20)
	header[0] = 1 // revision
	binary.LittleEndian.PutUint16(header[2:], sd.ControlSelfRelative|sd.ControlDACLPresent)
	binary.LittleEndian.PutUint32(header[4:], 20)                     // owner offset
	binary.LittleEndian.PutUint32(header[16:], uint32(20+len(owner))) // dacl offset
	out := append(header, owner...)
	return append(out, dacl...)
}

func pkiObj(t *testing.T, dn string, sdBytes []byte) *adws.Object {
	o := obj("distinguishedName", dn, "cn", "NTAuthCertificates")
	o.Attributes["nTSecurityDescriptor"] = []adws.Value{{Binary: sdBytes, IsBinary: true}}
	return o
}

func TestADCSESC5NTAuthWritable(t *testing.T) {
	s := testSnapshot()
	domainAdmins := encodeSID(21, 1, 2, 3, 512) // owner, expected
	authUsers := encodeSID(11)                  // S-1-5-11, non-Tier-0
	sdBytes := buildSD(domainAdmins, buildDACL(allowACE(sd.RightGenericAll, authUsers)))
	s.PKIObjects = []*adws.Object{
		pkiObj(t, "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local", sdBytes),
	}
	got := runRule(s, (*Snapshot).ruleADCSObjectControl)
	if len(got) != 1 {
		t.Fatalf("expected 1 ESC5 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.RuleID != "AD-CS-005" || f.Severity != Critical {
		t.Fatalf("want AD-CS-005/Critical, got %s/%s", f.RuleID, f.Severity)
	}
	if f.Evidence["object"] != "NTAuthCertificates" || f.Evidence["right"] != "GenericAll" {
		t.Errorf("evidence = %+v", f.Evidence)
	}
}

func TestADCSESC5IgnoresAdminRIDsCrossDomain(t *testing.T) {
	s := testSnapshot()
	// Enterprise Admins from a *different* domain SID (root domain in a forest).
	entAdmins := encodeSID(21, 9, 9, 9, 519)
	sdBytes := buildSD(entAdmins, buildDACL(allowACE(sd.RightGenericAll, entAdmins)))
	s.PKIObjects = []*adws.Object{
		pkiObj(t, "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local", sdBytes),
	}
	if got := runRule(s, (*Snapshot).ruleADCSObjectControl); len(got) != 0 {
		t.Fatalf("Enterprise Admins (RID 519) should be an expected controller, got %+v", got)
	}
}

func TestADCSHostCheckInformational(t *testing.T) {
	s := testSnapshot()
	s.CAs = []*adws.Object{obj(
		"cn", "corp-CA",
		"dNSHostName", "ca01.corp.local",
		"distinguishedName", "CN=corp-CA,CN=Enrollment Services,...",
	)}
	got := runRule(s, (*Snapshot).ruleADCSHostChecks)
	if len(got) != 1 || got[0].RuleID != "AD-CS-006" {
		t.Fatalf("expected 1 AD-CS-006 finding, got %+v", got)
	}
	s.build()
	res := Run(s)
	var info bool
	for _, f := range res.Findings {
		if f.RuleID == "AD-CS-006" {
			info = true
			if f.Severity != Info {
				t.Errorf("AD-CS-006 severity = %s, want Informational", f.Severity)
			}
		}
	}
	if !info {
		t.Fatal("AD-CS-006 did not flow through Run")
	}
}

func TestADCSHostCheckSkippedWithoutCAs(t *testing.T) {
	s := testSnapshot()
	if got := runRule(s, (*Snapshot).ruleADCSHostChecks); got != nil {
		t.Fatalf("no CAs should yield no finding, got %+v", got)
	}
}
