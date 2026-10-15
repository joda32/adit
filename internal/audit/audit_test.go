package audit

import (
	"encoding/binary"
	"testing"
	"time"

	"adit/internal/adws"
	"adit/internal/sd"
)

// --- helpers to build synthetic directory objects ---

func obj(pairs ...string) *adws.Object {
	o := &adws.Object{Attributes: map[string][]adws.Value{}}
	for i := 0; i+1 < len(pairs); i += 2 {
		o.Attributes[pairs[i]] = append(o.Attributes[pairs[i]], adws.Value{Text: pairs[i+1]})
	}
	return o
}

func withBin(o *adws.Object, attr string, b []byte) *adws.Object {
	o.Attributes[attr] = append(o.Attributes[attr], adws.Value{Binary: b, IsBinary: true})
	return o
}

// encodeSID builds a binary SID for S-1-5-<subauths...>.
func encodeSID(subAuths ...uint32) []byte {
	b := []byte{1, byte(len(subAuths)), 0, 0, 0, 0, 0, 5}
	for _, sa := range subAuths {
		var tmp [4]byte
		binary.LittleEndian.PutUint32(tmp[:], sa)
		b = append(b, tmp[:]...)
	}
	return b
}

// fileTime returns an AD FILETIME string for the given time.
func fileTime(t time.Time) string {
	const ticksPerSecond = 10_000_000
	const epochDiff = 11644473600 // seconds between 1601 and 1970
	ticks := (t.Unix() + epochDiff) * ticksPerSecond
	return itoa(ticks)
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// testSnapshot builds a snapshot with a fixed clock and privileged set.
func testSnapshot() *Snapshot {
	s := &Snapshot{
		Cfg:       Config{Now: time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC), KrbtgtMaxAgeDays: 180, PrivPwdMaxAgeDays: 365, StaleDays: 90},
		DomainSID: "S-1-5-21-1-2-3",
	}
	return s
}

func runRule(s *Snapshot, fn func(*Snapshot) []Finding) []Finding {
	s.build()
	return fn(s)
}

// --- attribute rule tests ---

func TestASREPRoast(t *testing.T) {
	s := testSnapshot()
	s.Users = []*adws.Object{
		obj("sAMAccountName", "svc1", "userAccountControl", "4260352"), // 0x410200: normal + no-preauth
		obj("sAMAccountName", "svc2", "userAccountControl", "512"),     // normal only
	}
	got := runRule(s, (*Snapshot).ruleASREPRoast)
	if len(got) != 1 || got[0].Affected[0].SAMAccountName != "svc1" {
		t.Fatalf("expected svc1 flagged, got %+v", got)
	}
}

func TestKerberoastableSeverity(t *testing.T) {
	s := testSnapshot()
	priv := obj("sAMAccountName", "svc-priv", "userAccountControl", "512", "adminCount", "1", "servicePrincipalName", "HTTP/x")
	norm := obj("sAMAccountName", "svc-norm", "userAccountControl", "512", "servicePrincipalName", "HTTP/y")
	krbtgt := obj("sAMAccountName", "krbtgt", "userAccountControl", "514", "servicePrincipalName", "kadmin/changepw")
	s.Users = []*adws.Object{priv, norm, krbtgt}
	got := runRule(s, (*Snapshot).ruleKerberoastable)
	if len(got) != 2 {
		t.Fatalf("expected 2 kerberoastable (krbtgt excluded), got %d: %+v", len(got), got)
	}
	sev := map[string]Severity{}
	for _, f := range got {
		sev[f.Affected[0].SAMAccountName] = f.Severity
	}
	if sev["svc-priv"] != High || sev["svc-norm"] != Medium {
		t.Fatalf("wrong severities: %+v", sev)
	}
}

func TestMachineAccountQuota(t *testing.T) {
	s := testSnapshot()
	s.Domain = obj("distinguishedName", "DC=lab,DC=local", "ms-DS-MachineAccountQuota", "10")
	if got := runRule(s, (*Snapshot).ruleMachineAccountQuota); len(got) != 1 {
		t.Fatalf("MAQ=10 should flag, got %+v", got)
	}
	s.Domain = obj("distinguishedName", "DC=lab,DC=local", "ms-DS-MachineAccountQuota", "0")
	if got := runRule(s, (*Snapshot).ruleMachineAccountQuota); len(got) != 0 {
		t.Fatalf("MAQ=0 should not flag, got %+v", got)
	}
}

func TestReversibleDomain(t *testing.T) {
	s := testSnapshot()
	s.Domain = obj("distinguishedName", "DC=lab,DC=local", "pwdProperties", "16") // 0x10
	if got := runRule(s, (*Snapshot).ruleReversibleDomain); len(got) != 1 {
		t.Fatalf("reversible enc should flag, got %+v", got)
	}
	s.Domain = obj("distinguishedName", "DC=lab,DC=local", "pwdProperties", "1")
	if got := runRule(s, (*Snapshot).ruleReversibleDomain); len(got) != 0 {
		t.Fatalf("no reversible enc should not flag, got %+v", got)
	}
}

func TestKrbtgtAge(t *testing.T) {
	s := testSnapshot()
	old := s.Cfg.Now.AddDate(0, 0, -400)
	fresh := s.Cfg.Now.AddDate(0, 0, -30)
	s.Users = []*adws.Object{obj("sAMAccountName", "krbtgt", "pwdLastSet", fileTime(old))}
	if got := runRule(s, (*Snapshot).ruleKrbtgtAge); len(got) != 1 {
		t.Fatalf("stale krbtgt should flag, got %+v", got)
	}
	s.Users = []*adws.Object{obj("sAMAccountName", "krbtgt", "pwdLastSet", fileTime(fresh))}
	if got := runRule(s, (*Snapshot).ruleKrbtgtAge); len(got) != 0 {
		t.Fatalf("fresh krbtgt should not flag, got %+v", got)
	}
}

func TestUnconstrainedDelegation(t *testing.T) {
	s := testSnapshot()
	// 0x80000 TRUSTED_FOR_DELEGATION + 0x1000 WORKSTATION_TRUST enabled workstation.
	ws := obj("sAMAccountName", "WS1$", "userAccountControl", "528384") // 0x81000
	// 0x2000 SERVER_TRUST_ACCOUNT (DC) + delegation -> excluded.
	dc := obj("sAMAccountName", "DC1$", "userAccountControl", "532480") // 0x82000
	s.Computers = []*adws.Object{ws, dc}
	got := runRule(s, (*Snapshot).ruleUnconstrainedDelegation)
	if len(got) != 1 || got[0].Affected[0].SAMAccountName != "WS1$" {
		t.Fatalf("only WS1$ should flag (DC excluded), got %+v", got)
	}
}

func TestStaleComputer(t *testing.T) {
	s := testSnapshot()
	old := s.Cfg.Now.AddDate(0, 0, -200)
	s.Computers = []*adws.Object{
		obj("sAMAccountName", "OLD$", "userAccountControl", "4096", "lastLogonTimestamp", fileTime(old)),
		obj("sAMAccountName", "NEW$", "userAccountControl", "4096", "lastLogonTimestamp", fileTime(s.Cfg.Now.AddDate(0, 0, -5))),
	}
	got := runRule(s, (*Snapshot).ruleStaleComputer)
	if len(got) != 1 || got[0].Affected[0].SAMAccountName != "OLD$" {
		t.Fatalf("only OLD$ should flag, got %+v", got)
	}
}

func TestLegacyOS(t *testing.T) {
	s := testSnapshot()
	s.Computers = []*adws.Object{
		obj("sAMAccountName", "SRV03$", "userAccountControl", "4096", "operatingSystem", "Windows Server 2003"),
		obj("sAMAccountName", "SRV22$", "userAccountControl", "4096", "operatingSystem", "Windows Server 2022 Datacenter"),
	}
	got := runRule(s, (*Snapshot).ruleLegacyOS)
	if len(got) != 1 || got[0].Affected[0].SAMAccountName != "SRV03$" {
		t.Fatalf("only SRV03$ should flag, got %+v", got)
	}
}

func TestSIDHistoryPrivileged(t *testing.T) {
	s := testSnapshot()
	// Domain Admins SID for this domain: S-1-5-21-1-2-3-512.
	u := withBin(obj("sAMAccountName", "migrated"), "sIDHistory", encodeSID(21, 1, 2, 3, 512))
	s.Users = []*adws.Object{u}
	got := runRule(s, (*Snapshot).ruleSIDHistoryPrivileged)
	if len(got) != 1 {
		t.Fatalf("privileged SID history should flag, got %+v", got)
	}
}

// TestSIDHistoryCrossDomain guards cross-/root-domain privileged SID history:
// Enterprise Admins (519) of a *different* domain (prefix S-1-5-21-9-9-9) must
// still be flagged via the domain-independent RID match, not only this domain's.
func TestSIDHistoryCrossDomain(t *testing.T) {
	s := testSnapshot() // DomainSID = S-1-5-21-1-2-3
	u := withBin(obj("sAMAccountName", "migrated"), "sIDHistory", encodeSID(21, 9, 9, 9, 519))
	s.Users = []*adws.Object{u}
	got := runRule(s, (*Snapshot).ruleSIDHistoryPrivileged)
	if len(got) != 1 {
		t.Fatalf("cross-domain Enterprise Admins SID history should flag, got %+v", got)
	}
}

// TestUnconstrainedDelegationUser guards that user/service accounts with
// TRUSTED_FOR_DELEGATION (not just computers) are evaluated.
func TestUnconstrainedDelegationUser(t *testing.T) {
	s := testSnapshot()
	// 0x80200 = TRUSTED_FOR_DELEGATION (0x80000) + NORMAL_ACCOUNT (0x200), enabled.
	s.Users = []*adws.Object{
		obj("sAMAccountName", "svc-deleg", "userAccountControl", "524800"),
		obj("sAMAccountName", "svc-normal", "userAccountControl", "512"),
	}
	got := runRule(s, (*Snapshot).ruleUnconstrainedDelegation)
	if len(got) != 1 || got[0].Affected[0].SAMAccountName != "svc-deleg" {
		t.Fatalf("only svc-deleg should flag, got %+v", got)
	}
}

// --- ACL classification tests ---

func TestClassifyDangerous(t *testing.T) {
	cases := []struct {
		name string
		ace  sd.ACE
		want string
	}{
		{"generic-all", sd.ACE{Type: sd.AceTypeAccessAllowed, Mask: sd.RightGenericAll}, "GenericAll"},
		{"writedacl", sd.ACE{Type: sd.AceTypeAccessAllowed, Mask: sd.RightWriteDACL}, "WriteDACL"},
		{"writeowner", sd.ACE{Type: sd.AceTypeAccessAllowed, Mask: sd.RightWriteOwner}, "WriteOwner"},
		{"reset-pw", sd.ACE{Type: sd.AceTypeAccessAllowedObject, Mask: sd.RightControlAccess, ObjectType: sd.GUIDResetPassword}, "ForceChangePassword"},
		{"write-member", sd.ACE{Type: sd.AceTypeAccessAllowedObject, Mask: sd.RightDSWriteProp, ObjectType: sd.GUIDWriteMember}, "WriteMember"},
		{"write-spn", sd.ACE{Type: sd.AceTypeAccessAllowedObject, Mask: sd.RightDSWriteProp, ObjectType: guidSPN}, "WriteSPN"},
		{"read-only", sd.ACE{Type: sd.AceTypeAccessAllowed, Mask: 0x20000}, ""},
	}
	for _, c := range cases {
		got, ok := classifyDangerous(c.ace)
		if c.want == "" {
			if ok {
				t.Errorf("%s: expected no match, got %s", c.name, got.kind)
			}
			continue
		}
		if !ok || got.kind != c.want {
			t.Errorf("%s: want %s, got %q (ok=%v)", c.name, c.want, got.kind, ok)
		}
	}
}

func TestIsExpectedController(t *testing.T) {
	s := testSnapshot()
	s.build()
	if !s.isExpectedController("S-1-5-18", "") {
		t.Error("Local System should be expected")
	}
	if !s.isExpectedController("S-1-5-21-1-2-3-512", "") {
		t.Error("Domain Admins should be expected")
	}
	if !s.isExpectedController("S-1-5-21-1-2-3-9999", "S-1-5-21-1-2-3-9999") {
		t.Error("object controlling itself should be expected")
	}
	if s.isExpectedController("S-1-5-21-1-2-3-1105", "") {
		t.Error("ordinary user should not be expected")
	}
	// Built-in Administrator (RID 500) is Tier-0 and expected.
	if !s.isExpectedController("S-1-5-21-1-2-3-500", "") {
		t.Error("built-in Administrator (RID 500) should be expected")
	}
}

// TestExpectedControllerPrivilegedUser guards that an adminCount=1 *user* (not
// just groups) is treated as an expected controller, avoiding false-positive
// takeover findings against named Tier-0 admins.
func TestExpectedControllerPrivilegedUser(t *testing.T) {
	s := testSnapshot()
	s.Users = []*adws.Object{
		withBin(obj("sAMAccountName", "tier0-admin", "adminCount", "1"), "objectSid", encodeSID(21, 1, 2, 3, 1107)),
	}
	s.build()
	if !s.isExpectedController("S-1-5-21-1-2-3-1107", "") {
		t.Error("adminCount=1 user should be an expected controller")
	}
}

func TestRunSetsMetadata(t *testing.T) {
	s := testSnapshot()
	s.Domain = obj("distinguishedName", "DC=lab,DC=local", "ms-DS-MachineAccountQuota", "10")
	s.build()
	res := Run(s)
	var found bool
	for _, f := range res.Findings {
		if f.RuleID == "AD-DOM-005" {
			found = true
			if f.Category == "" || f.Remediation == "" || f.RiskScore == 0 || !f.SafeCheck {
				t.Errorf("metadata not filled: %+v", f)
			}
		}
	}
	if !found {
		t.Fatal("AD-DOM-005 not produced by Run")
	}
	if res.Rules == 0 {
		t.Error("Rules count should be > 0")
	}
}
