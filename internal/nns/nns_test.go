package nns

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"adit/internal/ntlm"
	"adit/internal/spnego"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// Same vectors as the ntlm package (impacket ground truth).
const (
	vExportedKey       = "101112131415161718191a1b1c1d1e1f"
	vSealSignature     = "010000007b0a49345a80e66300000000"
	vSealCiphertext    = "7347795f5a35f99755f2"
	vSrvSealSignature  = "01000000f89b680ae81aef0700000000"
	vSrvSealCiphertext = "7ddfc2b555acf23c46cfa3ded174"
)

func TestHandshakeFramingRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("spnego-token")
	if err := writeHandshake(&buf, msgInProgress, payload); err != nil {
		t.Fatal(err)
	}
	// Header: id, major, minor, len-hi, len-lo.
	raw := buf.Bytes()
	want := []byte{msgInProgress, 1, 0, 0, byte(len(payload))}
	if !bytes.Equal(raw[:5], want) {
		t.Errorf("header = % x, want % x", raw[:5], want)
	}
	id, got, err := readHandshake(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if id != msgInProgress || !bytes.Equal(got, payload) {
		t.Errorf("readHandshake = %#x %q", id, got)
	}
}

func TestSealedConnWrite(t *testing.T) {
	sess, err := ntlm.NewSession(mustHex(t, vExportedKey))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	c := &sealedConn{rw: &out, sealer: ntlmSealer{sess}}
	if _, err := c.Write([]byte("hello adws")); err != nil {
		t.Fatal(err)
	}
	// Expect: len(26) LE + client seal signature + ciphertext.
	sealed := mustHex(t, vSealSignature+vSealCiphertext)
	want := append(make([]byte, 4), sealed...)
	binary.LittleEndian.PutUint32(want, uint32(len(sealed)))
	if !bytes.Equal(out.Bytes(), want) {
		t.Errorf("frame\n got=%x\nwant=%x", out.Bytes(), want)
	}
}

func TestSealedConnRead(t *testing.T) {
	sess, err := ntlm.NewSession(mustHex(t, vExportedKey))
	if err != nil {
		t.Fatal(err)
	}
	// Build an incoming server data message: len LE + server seal sig+ct.
	sealed := mustHex(t, vSrvSealSignature+vSrvSealCiphertext)
	frame := append(make([]byte, 4), sealed...)
	binary.LittleEndian.PutUint32(frame, uint32(len(sealed)))

	c := &sealedConn{rw: readWriter{r: bytes.NewReader(frame)}}
	c.sealer = ntlmSealer{sess}

	got, err := io.ReadAll(io.LimitReader(c, int64(len("server says hi"))))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "server says hi" {
		t.Errorf("got %q", got)
	}
}

// readWriter adapts a reader into an io.ReadWriter (writes discarded).
type readWriter struct{ r io.Reader }

func (rw readWriter) Read(p []byte) (int, error) { return rw.r.Read(p) }
func (readWriter) Write(p []byte) (int, error)   { return len(p), nil }

// TestAuthenticateHandshakeFlow drives the full Authenticate exchange against a
// fake server that speaks the NNS handshake and issues a synthetic NTLM
// challenge, verifying message flow and that a sealed transport is returned.
func TestAuthenticateHandshakeFlow(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	serverErr := make(chan error, 1)
	go func() { serverErr <- fakeNNSServer(server) }()

	auth := NewNTLM("Domain", "User", "Password", "")
	transport, err := auth.Authenticate(client)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if transport == nil {
		t.Fatal("nil transport")
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

// fakeNNSServer implements just enough server side to exercise the client
// handshake: read negotiate, send a synthetic challenge, read authenticate,
// send done.
func fakeNNSServer(conn net.Conn) error {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// 1. Negotiate.
	id, payload, err := readHandshake(conn)
	if err != nil {
		return err
	}
	if id != msgInProgress {
		return fmt.Errorf("expected in-progress negotiate, got %#x", id)
	}
	if len(payload) == 0 || payload[0] != 0x60 { // GSS InitialContextToken
		return fmt.Errorf("negotiate not a GSS token")
	}

	// 2. Challenge: wrap a synthetic type 2 in a NegTokenResp.
	type2 := syntheticChallenge()
	if err := writeHandshake(conn, msgInProgress, spnego.NegTokenResp(type2)); err != nil {
		return err
	}

	// 3. Authenticate.
	id, payload, err = readHandshake(conn)
	if err != nil {
		return err
	}
	if id != msgInProgress {
		return fmt.Errorf("expected in-progress authenticate, got %#x", id)
	}
	if _, err := spnego.ExtractResponseToken(payload); err != nil {
		return fmt.Errorf("authenticate has no response token: %v", err)
	}

	// 4. Done.
	return writeHandshake(conn, msgDone, nil)
}

// syntheticChallenge builds a minimal NTLM CHALLENGE with flags a DC would
// negotiate and target info placed after a 48-byte header.
func syntheticChallenge() []byte {
	flags := ntlm.NegotiateUnicode | ntlm.NegotiateNTLM | ntlm.NegotiateExtendedSessionSecurity |
		ntlm.NegotiateTargetInfo | ntlm.Negotiate128 | ntlm.Negotiate56 | ntlm.NegotiateKeyExch |
		ntlm.NegotiateSeal | ntlm.NegotiateSign | ntlm.NegotiateAlwaysSign
	targetInfo, _ := hex.DecodeString("02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000")

	buf := make([]byte, 48)
	copy(buf[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(buf[8:], 2) // CHALLENGE
	binary.LittleEndian.PutUint32(buf[20:], flags)
	copy(buf[24:32], mustDecode("0123456789abcdef"))
	binary.LittleEndian.PutUint16(buf[40:], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(buf[42:], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(buf[44:], 48)
	return append(buf, targetInfo...)
}

func mustDecode(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}
