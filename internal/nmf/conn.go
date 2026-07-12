package nmf

import (
	"fmt"
	"io"
	"net"
	"time"
)

// Authenticator performs the MS-NNS upgrade handshake. After the server
// acknowledges the NMF UpgradeRequest, Conn hands the raw post-preamble
// transport to Authenticate, which runs the negotiate/authenticate exchange and
// returns the transport to use for all subsequent (signed and sealed) traffic.
//
// Implemented by internal/nns. A nil Authenticator skips the upgrade entirely,
// which is only valid for unauthenticated endpoints (e.g. WS-MetadataExchange).
type Authenticator interface {
	Authenticate(rw io.ReadWriter) (io.ReadWriter, error)
}

// Encoder serializes a SOAP envelope to the negotiated payload encoding and
// back. For ADWS this is .NET Binary XML, [MC-NBFS]/[MC-NBFSE], implemented by
// internal/nbfx.
type Encoder interface {
	Encode(xml string) ([]byte, error)
	Decode(data []byte) (string, error)
}

// upgradeProtocol is the content negotiated during the NMF upgrade. WCF's
// net.tcp binding advertises SSPI negotiation under this token.
const upgradeProtocol = "application/negotiate"

// Fault is returned when the server sends an NMF Fault record.
type Fault struct{ Reason string }

func (f *Fault) Error() string { return "nmf: server fault: " + f.Reason }

// Conn is a framed MC-NMF connection to an ADWS endpoint.
type Conn struct {
	raw       net.Conn      // underlying socket, retained for Close/deadlines
	transport io.ReadWriter // current transport: raw before upgrade, sealed after
	auth      Authenticator
	enc       Encoder

	fqdn     string
	mode     Mode
	encoding Encoding
}

// NewConn wraps an established socket. auth may be nil (no upgrade); enc may be
// nil if only the handshake is exercised (Send/Recv then error).
func NewConn(sock net.Conn, fqdn string, auth Authenticator, enc Encoder) *Conn {
	return &Conn{
		raw:       sock,
		transport: sock,
		auth:      auth,
		enc:       enc,
		fqdn:      fqdn,
		mode:      ModeDuplex,
		encoding:  EncodingSoap12BinaryInband,
	}
}

// DialFunc establishes the raw TCP connection to addr. A nil DialFunc means a
// direct net.DialTimeout; a non-nil one (e.g. from internal/proxy) tunnels the
// connection through a jump host. Its signature matches proxy.Dialer.Dial.
type DialFunc func(network, addr string) (net.Conn, error)

// Dial opens a connection to host:port — directly, or via dial when non-nil —
// and wraps it in a Conn.
func Dial(host string, port int, fqdn string, auth Authenticator, enc Encoder, timeout time.Duration, dial DialFunc) (*Conn, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	if dial == nil {
		dial = func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, timeout)
		}
	}
	sock, err := dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("nmf: dial %s: %w", addr, err)
	}
	return NewConn(sock, fqdn, auth, enc), nil
}

// Close closes the underlying socket.
func (c *Conn) Close() error { return c.raw.Close() }

// SetDeadline sets read/write deadlines on the underlying socket.
func (c *Conn) SetDeadline(t time.Time) error { return c.raw.SetDeadline(t) }

// Connect performs the full open sequence for the given resource (e.g.
// "Windows/Enumeration"):
//
//	send preamble  ->  [upgrade + NNS auth]  ->  send PreambleEnd  ->  expect PreambleAck
//
// The via URI embeds the resource. [MC-NMF] 2.2.3.1 / 3.1.5.
func (c *Conn) Connect(resource string) error {
	via := fmt.Sprintf("net.tcp://%s:9389/ActiveDirectoryWebServices/%s", c.fqdn, resource)

	// The preamble advertises framing version 1.0.
	if _, err := c.transport.Write(preamble(1, 0, c.mode, via, c.encoding)); err != nil {
		return fmt.Errorf("nmf: send preamble: %w", err)
	}

	if err := c.upgrade(); err != nil {
		return err
	}

	if _, err := c.transport.Write([]byte{byte(recPreambleEnd)}); err != nil {
		return fmt.Errorf("nmf: send preamble end: %w", err)
	}

	typ, payload, err := readRecord(c.transport)
	if err != nil {
		return fmt.Errorf("nmf: read preamble ack: %w", err)
	}
	if err := expect(recPreambleAck, typ, payload); err != nil {
		return err
	}
	return nil
}

// upgrade requests the transport upgrade and runs the NNS handshake. It is a
// no-op when no Authenticator is configured.
func (c *Conn) upgrade() error {
	if c.auth == nil {
		return nil
	}

	if _, err := c.transport.Write(upgradeRequestRecord(upgradeProtocol)); err != nil {
		return fmt.Errorf("nmf: send upgrade request: %w", err)
	}

	typ, payload, err := readRecord(c.transport)
	if err != nil {
		return fmt.Errorf("nmf: read upgrade response: %w", err)
	}
	if err := expect(recUpgradeResponse, typ, payload); err != nil {
		return err
	}

	sealed, err := c.auth.Authenticate(c.transport)
	if err != nil {
		return fmt.Errorf("nmf: nns handshake: %w", err)
	}
	c.transport = sealed
	return nil
}

// Send encodes and transmits a SOAP envelope as a sized-envelope record.
func (c *Conn) Send(xml string) error {
	if c.enc == nil {
		return fmt.Errorf("nmf: no encoder configured")
	}
	payload, err := c.enc.Encode(xml)
	if err != nil {
		return fmt.Errorf("nmf: encode: %w", err)
	}
	if _, err := c.transport.Write(sizedEnvelopeRecord(payload)); err != nil {
		return fmt.Errorf("nmf: send envelope: %w", err)
	}
	return nil
}

// Recv reads the next sized-envelope record and decodes it to a SOAP string.
func (c *Conn) Recv() (string, error) {
	if c.enc == nil {
		return "", fmt.Errorf("nmf: no encoder configured")
	}
	typ, payload, err := readRecord(c.transport)
	if err != nil {
		return "", fmt.Errorf("nmf: read envelope: %w", err)
	}
	if err := expect(recSizedEnvelope, typ, payload); err != nil {
		return "", err
	}
	return c.enc.Decode(payload)
}

// expect validates that got matches want, turning a Fault record into a *Fault
// error and any other mismatch into a descriptive error.
func expect(want, got RecordType, payload []byte) error {
	if got == want {
		return nil
	}
	if got == recFault {
		return &Fault{Reason: string(payload)}
	}
	return fmt.Errorf("nmf: expected %s record, got %s", want, got)
}
