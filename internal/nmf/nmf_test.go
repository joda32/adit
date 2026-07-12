package nmf

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestEncodeSizeKnownVectors(t *testing.T) {
	// Vectors from the MC-NMF multi-byte integer scheme (same as .NET 7-bit).
	cases := []struct {
		in   int
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{0x7f, []byte{0x7f}},
		{0x80, []byte{0x80, 0x01}},
		{0x81, []byte{0x81, 0x01}},
		{0xFF, []byte{0xff, 0x01}},
		{0x3FFF, []byte{0xff, 0x7f}},
		{0x4000, []byte{0x80, 0x80, 0x01}},
		{0xFC30, []byte{0xb0, 0xf8, 0x03}},
	}
	for _, c := range cases {
		if got := encodeSize(c.in); !bytes.Equal(got, c.want) {
			t.Errorf("encodeSize(%#x) = % x, want % x", c.in, got, c.want)
		}
	}
}

func TestSizeRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 127, 128, 300, 0xFC30, 0xFFFF, 1 << 20, 0x7FFFFFFF} {
		enc := encodeSize(n)
		got, err := readSize(bytes.NewReader(enc))
		if err != nil {
			t.Fatalf("readSize(% x): %v", enc, err)
		}
		if got != n {
			t.Errorf("round trip %d -> % x -> %d", n, enc, got)
		}
	}
}

func TestReadSizeTooLong(t *testing.T) {
	// Six continuation bytes must be rejected.
	_, err := readSize(bytes.NewReader([]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x01}))
	if err == nil {
		t.Fatal("expected error for oversized size field")
	}
}

func TestPreambleBytes(t *testing.T) {
	got := preamble(1, 0, ModeDuplex, "a", EncodingSoap12BinaryInband)
	want := []byte{
		0x00, 0x01, 0x00, // Version 1.0
		0x01, 0x02, // Mode Duplex
		0x02, 0x01, 'a', // Via len=1 "a"
		0x03, 0x08, // KnownEncoding NBFSE
	}
	if !bytes.Equal(got, want) {
		t.Errorf("preamble = % x, want % x", got, want)
	}
}

func TestReadRecordTypes(t *testing.T) {
	tests := []struct {
		name        string
		in          []byte
		wantType    RecordType
		wantPayload []byte
	}{
		{"preamble-ack", []byte{0x0b}, recPreambleAck, nil},
		{"upgrade-response", []byte{0x0a}, recUpgradeResponse, nil},
		{"end", []byte{0x07}, recEnd, nil},
		{"mode", []byte{0x01, 0x02}, recMode, []byte{0x02}},
		{"version", []byte{0x00, 0x01, 0x00}, recVersion, []byte{0x01, 0x00}},
		{"fault", append([]byte{0x08, 0x03}, []byte("bad")...), recFault, []byte("bad")},
		{"envelope", append([]byte{0x06, 0x04}, []byte("data")...), recSizedEnvelope, []byte("data")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			typ, payload, err := readRecord(bytes.NewReader(tc.in))
			if err != nil {
				t.Fatalf("readRecord: %v", err)
			}
			if typ != tc.wantType {
				t.Errorf("type = %s, want %s", typ, tc.wantType)
			}
			if !bytes.Equal(payload, tc.wantPayload) {
				t.Errorf("payload = % x, want % x", payload, tc.wantPayload)
			}
		})
	}
}

func TestReadRecordUnknownType(t *testing.T) {
	_, _, err := readRecord(bytes.NewReader([]byte{0x7e}))
	if err == nil {
		t.Fatal("expected error for unknown record type")
	}
}

// identityEncoder is a stand-in for the NBFS encoder: it passes bytes through
// unchanged so the framing layer can be tested without the binary XML codec.
type identityEncoder struct{}

func (identityEncoder) Encode(xml string) ([]byte, error)  { return []byte(xml), nil }
func (identityEncoder) Decode(data []byte) (string, error) { return string(data), nil }

// TestConnectHandshakeNoAuth drives Connect against an in-memory server that
// validates the preamble and PreambleEnd, then acks. Exercises the framing
// without the NNS upgrade.
func TestConnectHandshakeNoAuth(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- fakeServer(server)
	}()

	c := NewConn(client, "dc.example.local", nil, identityEncoder{})
	if err := c.Connect("Windows/Enumeration"); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

// fakeServer reads the client's preamble records, expects a PreambleEnd, and
// replies with a PreambleAck.
func fakeServer(conn net.Conn) error {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Version, Mode, Via, KnownEncoding, then PreambleEnd.
	for _, want := range []RecordType{recVersion, recMode, recVia, recKnownEncoding, recPreambleEnd} {
		got, _, err := readRecord(conn)
		if err != nil {
			return err
		}
		if got != want {
			return &Fault{Reason: "unexpected " + got.String()}
		}
	}
	_, err := conn.Write([]byte{byte(recPreambleAck)})
	return err
}

// TestConnectFault ensures a Fault record during the handshake surfaces as *Fault.
func TestConnectFault(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		// Drain the preamble + PreambleEnd, then fault.
		for i := 0; i < 5; i++ {
			if _, _, err := readRecord(server); err != nil {
				return
			}
		}
		server.Write(sizedRecord(recFault, []byte("http://schemas.xmlsoap.org/ws/2004/09/enumeration/fault")))
	}()

	c := NewConn(client, "dc.example.local", nil, identityEncoder{})
	err := c.Connect("Windows/Enumeration")
	var f *Fault
	if !asFault(err, &f) {
		t.Fatalf("expected *Fault, got %v", err)
	}
}

func asFault(err error, target **Fault) bool {
	f, ok := err.(*Fault)
	if ok {
		*target = f
	}
	return ok
}

var _ io.ReadWriter = (net.Conn)(nil)
