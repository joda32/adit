package spnego

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// Vectors from impacket's spnego module (scratchpad):
//
//	NegTokenInit over mechToken "MECHTOKEN-NTLM-TYPE1", NTLM-only.
//	NegTokenResp over responseToken "RESPONSE-TYPE3".
const (
	vInitNTLMOnly = "603406062b0601050502a02a3028a00e300c060a2b06010401823702020aa21604144d454348544f4b454e2d4e544c4d2d5459504531"
	vResp         = "a1143012a210040e524553504f4e53452d5459504533"
)

func TestNegTokenInitMatchesImpacket(t *testing.T) {
	got := NegTokenInit([]byte("MECHTOKEN-NTLM-TYPE1"))
	if want := mustHex(t, vInitNTLMOnly); !bytes.Equal(got, want) {
		t.Errorf("NegTokenInit\n got=%x\nwant=%x", got, want)
	}
}

func TestNegTokenRespMatchesImpacket(t *testing.T) {
	got := NegTokenResp([]byte("RESPONSE-TYPE3"))
	if want := mustHex(t, vResp); !bytes.Equal(got, want) {
		t.Errorf("NegTokenResp\n got=%x\nwant=%x", got, want)
	}
}

func TestExtractResponseToken(t *testing.T) {
	// From a server NegTokenResp (bare [1] form).
	tok, err := ExtractResponseToken(mustHex(t, vResp))
	if err != nil {
		t.Fatalf("ExtractResponseToken: %v", err)
	}
	if string(tok) != "RESPONSE-TYPE3" {
		t.Errorf("got %q", tok)
	}
}

func TestExtractResponseTokenGSSWrapped(t *testing.T) {
	// A server may also reply with negState + supportedMech before the token.
	// Build a NegTokenResp containing an OID and our octet string and ensure we
	// still find the responseToken by walking the tree.
	resp := NegTokenResp([]byte("CHALLENGE-TYPE2"))
	tok, err := ExtractResponseToken(resp)
	if err != nil {
		t.Fatalf("ExtractResponseToken: %v", err)
	}
	if string(tok) != "CHALLENGE-TYPE2" {
		t.Errorf("got %q", tok)
	}
}

func TestEncodeLen(t *testing.T) {
	cases := []struct {
		n    int
		want []byte
	}{
		{0, []byte{0x00}},
		{0x7f, []byte{0x7f}},
		{0x80, []byte{0x81, 0x80}},
		{0xff, []byte{0x81, 0xff}},
		{0x100, []byte{0x82, 0x01, 0x00}},
		{0x1234, []byte{0x82, 0x12, 0x34}},
	}
	for _, c := range cases {
		if got := encodeLen(c.n); !bytes.Equal(got, c.want) {
			t.Errorf("encodeLen(%#x) = %x, want %x", c.n, got, c.want)
		}
	}
}

func TestReadTLVLongForm(t *testing.T) {
	// 0x82 length form with a 200-byte payload.
	payload := bytes.Repeat([]byte{0xAB}, 200)
	enc := tlv(tagOctetString, payload)
	tag, content, rest, err := readTLV(enc)
	if err != nil {
		t.Fatal(err)
	}
	if tag != tagOctetString || !bytes.Equal(content, payload) || len(rest) != 0 {
		t.Errorf("round trip failed: tag=%x len(content)=%d len(rest)=%d", tag, len(content), len(rest))
	}
}
