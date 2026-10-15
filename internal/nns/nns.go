// Package nns implements the client side of the .NET NegotiateStream Protocol,
// [MS-NNS] — the security upgrade MC-NMF negotiates before application data
// flows. It runs an NTLM (SPNEGO) handshake and then returns an io.ReadWriter
// that transparently signs+seals writes and verifies+unseals reads, satisfying
// nmf.Authenticator.
//
// Two framings are involved:
//
//   - Handshake messages (2.2.2): msgID(1) major(1) minor(1) len(2, big-endian)
//     payload — used to carry the SPNEGO/NTLM tokens.
//   - Data messages (2.2.3): len(4, little-endian) payload — used after auth,
//     where payload is signature(16)||ciphertext.
//
// A large NMF record may span several data messages; because the returned
// transport is a byte stream and callers read with io.ReadFull, reassembly is
// transparent.
package nns

import (
	"encoding/binary"
	"fmt"
	"io"

	"adit/internal/ntlm"
	"adit/internal/spnego"
)

// Handshake message ids. [MS-NNS] 2.2.2.
const (
	msgInProgress = 0x16
	msgError      = 0x15
	msgDone       = 0x14

	handshakeMajor = 1
	handshakeMinor = 0
)

// Authenticator runs an NTLM-over-SPNEGO NNS handshake.
type Authenticator struct {
	client *ntlm.Client
}

// NewNTLM builds an NTLM authenticator. workstation may be empty (which
// bypasses userWorkstations restrictions).
func NewNTLM(domain, user, password, workstation string) *Authenticator {
	return &Authenticator{client: ntlm.NewClient(domain, user, password, workstation)}
}

// Authenticate performs the handshake over rw and returns the sealed transport.
// [MS-NNS] 3.2.5 (Negotiate → Challenge → Authenticate → Done).
func (a *Authenticator) Authenticate(rw io.ReadWriter) (io.ReadWriter, error) {
	// 1. Client -> Server: NTLM NEGOTIATE inside a SPNEGO NegTokenInit.
	negTokenInit := spnego.NegTokenInit(a.client.Negotiate())
	if err := writeHandshake(rw, msgInProgress, negTokenInit); err != nil {
		return nil, fmt.Errorf("send negotiate: %w", err)
	}

	// 2. Server -> Client: SPNEGO NegTokenResp carrying the NTLM CHALLENGE.
	id, payload, err := readHandshake(rw)
	if err != nil {
		return nil, fmt.Errorf("read challenge: %w", err)
	}
	if id == msgError {
		return nil, fmt.Errorf("server rejected negotiate: %s", errPayload(payload))
	}
	challenge, err := spnego.ExtractResponseToken(payload)
	if err != nil {
		return nil, fmt.Errorf("parse challenge: %w", err)
	}

	// 3. Client -> Server: NTLM AUTHENTICATE inside a SPNEGO NegTokenResp.
	type3, session, err := a.client.Authenticate(challenge)
	if err != nil {
		return nil, fmt.Errorf("compute authenticate: %w", err)
	}
	if err := writeHandshake(rw, msgInProgress, spnego.NegTokenResp(type3)); err != nil {
		return nil, fmt.Errorf("send authenticate: %w", err)
	}

	// 4. Server -> Client: completion. Anything but an error means success; the
	//    payload (accept-completed token) is not needed for NTLM.
	id, payload, err = readHandshake(rw)
	if err != nil {
		return nil, fmt.Errorf("read completion: %w", err)
	}
	if id == msgError {
		return nil, fmt.Errorf("authentication failed: %s", errPayload(payload))
	}

	return &sealedConn{rw: rw, sealer: ntlmSealer{session}}, nil
}

// writeHandshake frames and sends an NNS handshake message.
func writeHandshake(w io.Writer, msgID byte, payload []byte) error {
	if len(payload) > 0xffff {
		return fmt.Errorf("nns: handshake payload too large (%d)", len(payload))
	}
	hdr := [5]byte{msgID, handshakeMajor, handshakeMinor, byte(len(payload) >> 8), byte(len(payload))}
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// readHandshake reads one NNS handshake message.
func readHandshake(r io.Reader) (msgID byte, payload []byte, err error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	payload = make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[0], payload, nil
}

func errPayload(p []byte) string {
	if len(p) == 4 {
		return fmt.Sprintf("HRESULT 0x%08x", binary.BigEndian.Uint32(p))
	}
	return fmt.Sprintf("% x", p)
}

// sealer seals and unseals the payload of an NNS data message. Implemented by
// NTLM (sign+seal) and Kerberos (GSS Wrap) sessions.
type sealer interface {
	Seal(plaintext []byte) ([]byte, error)
	Unseal(payload []byte) ([]byte, error)
}

// ntlmSealer adapts *ntlm.Session (whose Seal cannot fail) to the sealer interface.
type ntlmSealer struct{ s *ntlm.Session }

func (a ntlmSealer) Seal(p []byte) ([]byte, error)   { return a.s.Seal(p), nil }
func (a ntlmSealer) Unseal(p []byte) ([]byte, error) { return a.s.Unseal(p) }

// sealedConn wraps the raw transport after authentication, framing every write
// as a sealed NNS data message and unsealing reads. It is a byte stream: Read
// serves decrypted bytes from an internal buffer, refilling one data message at
// a time.
type sealedConn struct {
	rw     io.ReadWriter
	sealer sealer
	rbuf   []byte
}

// maxDataChunk bounds a single NNS data message. The upgraded transport is a
// .NET NegotiateStream, whose receive side rejects any frame larger than its
// 64 KiB MaxReadFrameSize, so a larger record must be split across several
// sealed data messages. 63 KiB leaves room for the per-message signature.
const maxDataChunk = 63 * 1024

// maxDataFrame bounds a single inbound sealed data message, so a malicious or
// corrupt 4-byte length prefix cannot drive a multi-gigabyte allocation.
const maxDataFrame = 64 << 20 // 64 MiB (WCF's default maxReceivedMessageSize)

// Write seals p across one or more NNS data messages, each capped to
// maxDataChunk so none exceeds the NegotiateStream frame limit. Each chunk is
// sealed independently (advancing the per-direction sequence number), which the
// receiver reassembles transparently.
func (c *sealedConn) Write(p []byte) (int, error) {
	written := 0
	for {
		end := written + maxDataChunk
		if end > len(p) {
			end = len(p)
		}
		sealed, err := c.sealer.Seal(p[written:end])
		if err != nil {
			return written, err
		}
		var lenPrefix [4]byte
		binary.LittleEndian.PutUint32(lenPrefix[:], uint32(len(sealed)))
		if _, err := c.rw.Write(lenPrefix[:]); err != nil {
			return written, err
		}
		if _, err := c.rw.Write(sealed); err != nil {
			return written, err
		}
		written = end
		if written >= len(p) {
			return written, nil
		}
	}
}

// Read serves plaintext bytes, unsealing another data message when the buffer
// is empty.
func (c *sealedConn) Read(p []byte) (int, error) {
	if len(c.rbuf) == 0 {
		if err := c.fill(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *sealedConn) fill() error {
	var lenPrefix [4]byte
	if _, err := io.ReadFull(c.rw, lenPrefix[:]); err != nil {
		return err
	}
	size := binary.LittleEndian.Uint32(lenPrefix[:])
	if size > maxDataFrame {
		return fmt.Errorf("nns: data message too large (%d bytes)", size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(c.rw, payload); err != nil {
		return err
	}
	plain, err := c.sealer.Unseal(payload)
	if err != nil {
		return err
	}
	c.rbuf = plain
	return nil
}
