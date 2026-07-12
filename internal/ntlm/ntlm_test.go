package ntlm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// Ground-truth vectors generated from impacket (see scratchpad/gen_vectors.py)
// with fixed inputs: user "User", domain "Domain", password "Password",
// serverChallenge 0123456789abcdef, clientChallenge aaaa...aa, exported session
// key 1011..1f, zero timestamp, target info for "Domain"/"Server". The NTOWFv2
// value also matches [MS-NLMP] 4.2.4.1.1; the responses are impacket's output
// for these exact inputs (what a real DC must accept).
const (
	vServerChallenge   = "0123456789abcdef"
	vClientChallenge   = "aaaaaaaaaaaaaaaa"
	vExportedKey       = "101112131415161718191a1b1c1d1e1f"
	vTargetInfo        = "02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000"
	vNTOWFv2           = "0c868a403bfd7a93a3001ef22ef02e3f"
	vNTProof           = "b232050b98e5f4e336bd187921a27bb2" // == vNTResponse[:32 hex]
	vNTResponse        = "b232050b98e5f4e336bd187921a27bb201010000000000000000000000000000aaaaaaaaaaaaaaaa0000000002000c0044006f006d00610069006e0001000c0053006500720076006500720000000000"
	vLMResponse        = "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa"
	vSessionBaseKey    = "e0029235f11808e612eaa1ace613785f"
	vEncryptedKey      = "5d28e8a8276055df94c002546b1e3a06"
	vClientSignKey     = "a14c3d1e1b365279873f7dcf51aed29d"
	vServerSignKey     = "dbfeaa5883b889757ff1d849f31d6d53"
	vClientSealKey     = "af22a2127a4b090cccdfa26c427969c7"
	vServerSealKey     = "b9e4af6ccd5f5edeb067d13815036db5"
	vSealPlaintext     = "68656c6c6f2061647773"
	vSealCiphertext    = "7347795f5a35f99755f2"
	vSealSignature     = "010000007b0a49345a80e66300000000"
	vType1             = "4e544c4d5353500001000000358288e000000000000000000000000000000000"
	vSrvSealPlaintext  = "7365727665722073617973206869"
	vSrvSealCiphertext = "7ddfc2b555acf23c46cfa3ded174"
	vSrvSealSignature  = "01000000f89b680ae81aef0700000000"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func eq(t *testing.T, name string, got []byte, wantHex string) {
	t.Helper()
	if want := mustHex(t, wantHex); !bytes.Equal(got, want) {
		t.Errorf("%s = %x, want %s", name, got, wantHex)
	}
}

func TestNTOWFv2(t *testing.T) {
	eq(t, "NTOWFv2", ntowf("User", "Password", "Domain"), vNTOWFv2)
}

func TestComputeV2Response(t *testing.T) {
	nt, lm, sbk := ComputeV2Response(
		mustHex(t, vNTOWFv2),
		mustHex(t, vServerChallenge),
		mustHex(t, vClientChallenge),
		make([]byte, 8), // zero timestamp
		mustHex(t, vTargetInfo),
	)
	eq(t, "NTChallengeResponse", nt, vNTResponse)
	eq(t, "NTProofStr", nt[:16], vNTProof)
	eq(t, "LMChallengeResponse", lm, vLMResponse)
	eq(t, "SessionBaseKey", sbk, vSessionBaseKey)
}

func TestEncryptRandomSessionKey(t *testing.T) {
	got, err := EncryptRandomSessionKey(mustHex(t, vSessionBaseKey), mustHex(t, vExportedKey))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "EncryptedRandomSessionKey", got, vEncryptedKey)
}

func TestKeyDerivation(t *testing.T) {
	esk := mustHex(t, vExportedKey)
	eq(t, "ClientSignKey", SignKey(esk, true), vClientSignKey)
	eq(t, "ServerSignKey", SignKey(esk, false), vServerSignKey)
	eq(t, "ClientSealKey", SealKey(esk, true), vClientSealKey)
	eq(t, "ServerSealKey", SealKey(esk, false), vServerSealKey)
}

func TestSessionSeal(t *testing.T) {
	sess, err := NewSession(mustHex(t, vExportedKey))
	if err != nil {
		t.Fatal(err)
	}
	out := sess.Seal(mustHex(t, vSealPlaintext))
	eq(t, "Seal signature", out[:16], vSealSignature)
	eq(t, "Seal ciphertext", out[16:], vSealCiphertext)
	if sess.sendSeq != 1 {
		t.Errorf("sendSeq = %d, want 1", sess.sendSeq)
	}
}

func TestSessionUnseal(t *testing.T) {
	sess, err := NewSession(mustHex(t, vExportedKey))
	if err != nil {
		t.Fatal(err)
	}
	sealed := append(mustHex(t, vSrvSealSignature), mustHex(t, vSrvSealCiphertext)...)
	plain, err := sess.Unseal(sealed) // verifies the server signature
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	eq(t, "Unseal plaintext", plain, vSrvSealPlaintext)
}

func TestUnsealDetectsTampering(t *testing.T) {
	sess, err := NewSession(mustHex(t, vExportedKey))
	if err != nil {
		t.Fatal(err)
	}
	sealed := append(mustHex(t, vSrvSealSignature), mustHex(t, vSrvSealCiphertext)...)
	sealed[20] ^= 0xff // flip a ciphertext byte
	if _, err := sess.Unseal(sealed); err == nil {
		t.Fatal("expected signature verification failure")
	}
}

func TestNegotiateMessage(t *testing.T) {
	c := NewClient("Domain", "User", "Password", "")
	eq(t, "type1", c.Negotiate(), vType1)
}

// syntheticChallenge builds a minimal type 2 message with the given flags,
// server challenge and target info (placed right after the 48-byte header).
func syntheticChallenge(flags uint32, serverChallenge, targetInfo []byte) []byte {
	buf := make([]byte, 48)
	copy(buf[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(buf[8:], msgTypeChallenge)
	binary.LittleEndian.PutUint32(buf[20:], flags)
	copy(buf[24:32], serverChallenge)
	binary.LittleEndian.PutUint16(buf[40:], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(buf[42:], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(buf[44:], 48)
	return append(buf, targetInfo...)
}

func field(t *testing.T, msg []byte, descPos int) []byte {
	t.Helper()
	n := int(binary.LittleEndian.Uint16(msg[descPos:]))
	off := int(binary.LittleEndian.Uint32(msg[descPos+4:]))
	return msg[off : off+n]
}

func TestAuthenticateMessage(t *testing.T) {
	serverFlags := NegotiateUnicode | NegotiateNTLM | NegotiateExtendedSessionSecurity |
		NegotiateTargetInfo | Negotiate128 | Negotiate56 | NegotiateKeyExch |
		NegotiateSeal | NegotiateSign | NegotiateAlwaysSign | NegotiateTargetTypeDomain
	type2 := syntheticChallenge(serverFlags, mustHex(t, vServerChallenge), mustHex(t, vTargetInfo))

	c := NewClient("Domain", "User", "Password", "")
	c.clientChallenge = mustHex(t, vClientChallenge)
	c.exportedSessionKey = mustHex(t, vExportedKey)

	type3, sess, err := c.Authenticate(type2)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	// ntlm descriptor at 20, lanman at 12, session_key at 52.
	eq(t, "type3 NT response", field(t, type3, 20), vNTResponse)
	eq(t, "type3 LM response", field(t, type3, 12), vLMResponse)
	eq(t, "type3 session key", field(t, type3, 52), vEncryptedKey)

	// The session derived from the injected exported key must seal identically.
	out := sess.Seal(mustHex(t, vSealPlaintext))
	eq(t, "post-auth seal", out, vSealSignature+vSealCiphertext)
}
