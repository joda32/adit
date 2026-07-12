package proxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// echoTarget starts a TCP server that echoes a fixed banner then mirrors input.
func echoTarget(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.Write([]byte("HELLO"))
				io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// splice connects to target and pipes both directions.
func splice(client net.Conn, target string) {
	up, err := net.Dial("tcp", target)
	if err != nil {
		client.Close()
		return
	}
	go func() { io.Copy(up, client); up.Close() }()
	io.Copy(client, up)
	client.Close()
}

// roundtrip drives the echo protocol through a dialed conn.
func roundtrip(t *testing.T, c net.Conn) {
	t.Helper()
	defer c.Close()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if string(buf) != "HELLO" {
		t.Fatalf("banner = %q", buf)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("echo = %q", got)
	}
}

// --- SOCKS5 mock server ---

func socks5Server(t *testing.T, target string, user, pass string, capture *byte, captureHost *string) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// greeting
		h := make([]byte, 2)
		io.ReadFull(c, h)
		methods := make([]byte, h[1])
		io.ReadFull(c, methods)
		if user != "" {
			c.Write([]byte{0x05, 0x02})
			ah := make([]byte, 2)
			io.ReadFull(c, ah) // ver, ulen
			u := make([]byte, ah[1])
			io.ReadFull(c, u)
			pl := make([]byte, 1)
			io.ReadFull(c, pl)
			p := make([]byte, pl[0])
			io.ReadFull(c, p)
			if string(u) != user || string(p) != pass {
				c.Write([]byte{0x01, 0x01})
				c.Close()
				return
			}
			c.Write([]byte{0x01, 0x00})
		} else {
			c.Write([]byte{0x05, 0x00})
		}
		// request
		head := make([]byte, 4)
		io.ReadFull(c, head)
		if capture != nil {
			*capture = head[3]
		}
		var host string
		switch head[3] {
		case 0x01:
			b := make([]byte, 4)
			io.ReadFull(c, b)
			host = net.IP(b).String()
		case 0x03:
			n := make([]byte, 1)
			io.ReadFull(c, n)
			b := make([]byte, n[0])
			io.ReadFull(c, b)
			host = string(b)
		}
		if captureHost != nil {
			*captureHost = host
		}
		port := make([]byte, 2)
		io.ReadFull(c, port)
		c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		splice(c, target)
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestSOCKS5NoAuth(t *testing.T) {
	tgt, stopT := echoTarget(t)
	defer stopT()
	var atyp byte
	px, stopP := socks5Server(t, tgt, "", "", &atyp, nil)
	defer stopP()

	d, err := New("socks5://"+px, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.Dial("tcp", tgt)
	if err != nil {
		t.Fatal(err)
	}
	roundtrip(t, c)
	if atyp != 0x01 {
		t.Errorf("expected IPv4 ATYP for %s, got 0x%02x", tgt, atyp)
	}
}

func TestSOCKS5Auth(t *testing.T) {
	tgt, stopT := echoTarget(t)
	defer stopT()
	px, stopP := socks5Server(t, tgt, "bob", "s3cret", nil, nil)
	defer stopP()

	d, _ := New("socks5://bob:s3cret@"+px, 2*time.Second)
	c, err := d.Dial("tcp", tgt)
	if err != nil {
		t.Fatal(err)
	}
	roundtrip(t, c)
}

func TestSOCKS5AuthWrongPassword(t *testing.T) {
	tgt, stopT := echoTarget(t)
	defer stopT()
	px, stopP := socks5Server(t, tgt, "bob", "s3cret", nil, nil)
	defer stopP()

	d, _ := New("socks5://bob:wrong@"+px, 2*time.Second)
	if _, err := d.Dial("tcp", tgt); err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestSOCKS5RemoteDNS(t *testing.T) {
	tgt, stopT := echoTarget(t)
	defer stopT()
	// Address the target by hostname so the client must send ATYP=domain.
	_, port, _ := net.SplitHostPort(tgt)
	var atyp byte
	var host string
	px, stopP := socks5Server(t, tgt, "", "", &atyp, &host)
	defer stopP()

	d, _ := New("socks5h://"+px, 2*time.Second)
	c, err := d.Dial("tcp", net.JoinHostPort("localhost", port))
	if err != nil {
		t.Fatal(err)
	}
	roundtrip(t, c)
	if atyp != 0x03 || host != "localhost" {
		t.Errorf("expected remote-DNS domain 'localhost', got ATYP 0x%02x host %q", atyp, host)
	}
}

// --- SOCKS4a mock server ---

func socks4Server(t *testing.T, target string, wantHost *string) (addr string, stop func()) {
	t.Helper()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		head := make([]byte, 8) // VN CD DSTPORT(2) DSTIP(4)
		io.ReadFull(c, head)
		readNul := func() string {
			var b []byte
			one := make([]byte, 1)
			for {
				if _, err := io.ReadFull(c, one); err != nil {
					return string(b)
				}
				if one[0] == 0 {
					return string(b)
				}
				b = append(b, one[0])
			}
		}
		readNul() // userid
		// SOCKS4a: IP 0.0.0.x signals a trailing hostname.
		if head[4] == 0 && head[5] == 0 && head[6] == 0 && head[7] != 0 {
			h := readNul()
			if wantHost != nil {
				*wantHost = h
			}
		}
		c.Write([]byte{0x00, 0x5a, 0, 0, 0, 0, 0, 0})
		splice(c, target)
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestSOCKS4aRemoteDNS(t *testing.T) {
	tgt, stopT := echoTarget(t)
	defer stopT()
	_, port, _ := net.SplitHostPort(tgt)
	var host string
	px, stopP := socks4Server(t, tgt, &host)
	defer stopP()

	d, _ := New("socks4a://"+px, 2*time.Second)
	c, err := d.Dial("tcp", net.JoinHostPort("localhost", port))
	if err != nil {
		t.Fatal(err)
	}
	roundtrip(t, c)
	if host != "localhost" {
		t.Errorf("socks4a host = %q, want localhost", host)
	}
}

// --- HTTP CONNECT mock server ---

func httpConnectServer(t *testing.T, target, wantAuth string, code int) (addr string, stop func()) {
	t.Helper()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		br := bufio.NewReader(c)
		var gotAuth string
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				c.Close()
				return
			}
			if strings.HasPrefix(strings.ToLower(line), "proxy-authorization:") {
				gotAuth = strings.TrimSpace(line[len("proxy-authorization:"):])
			}
			if line == "\r\n" {
				break
			}
		}
		if code != 200 {
			fmt.Fprintf(c, "HTTP/1.1 %d Denied\r\n\r\n", code)
			c.Close()
			return
		}
		if wantAuth != "" && gotAuth != wantAuth {
			c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
			c.Close()
			return
		}
		c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		splice(c, target)
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestHTTPConnect(t *testing.T) {
	tgt, stopT := echoTarget(t)
	defer stopT()
	px, stopP := httpConnectServer(t, tgt, "", 200)
	defer stopP()

	d, _ := New("http://"+px, 2*time.Second)
	c, err := d.Dial("tcp", tgt)
	if err != nil {
		t.Fatal(err)
	}
	roundtrip(t, c)
}

func TestHTTPConnectAuth(t *testing.T) {
	tgt, stopT := echoTarget(t)
	defer stopT()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p"))
	px, stopP := httpConnectServer(t, tgt, want, 200)
	defer stopP()

	d, _ := New("http://u:p@"+px, 2*time.Second)
	c, err := d.Dial("tcp", tgt)
	if err != nil {
		t.Fatal(err)
	}
	roundtrip(t, c)
}

func TestHTTPConnectRejected(t *testing.T) {
	tgt, stopT := echoTarget(t)
	defer stopT()
	px, stopP := httpConnectServer(t, tgt, "", 403)
	defer stopP()

	d, _ := New("http://"+px, 2*time.Second)
	if _, err := d.Dial("tcp", tgt); err == nil {
		t.Fatal("expected CONNECT rejection error")
	}
}

func TestNew(t *testing.T) {
	if d, err := New("", time.Second); err != nil || d.Describe() != "direct (no proxy)" {
		t.Fatalf("empty should be direct: %v %v", d, err)
	}
	for _, ok := range []string{"socks5://h:1", "socks4://h:1", "socks4a://h:1", "http://h:1", "https://h:1"} {
		if _, err := New(ok, time.Second); err != nil {
			t.Errorf("New(%q) unexpected error: %v", ok, err)
		}
	}
	for _, bad := range []string{"ftp://h:1", "://nope", "socks5://"} {
		if _, err := New(bad, time.Second); err == nil {
			t.Errorf("New(%q) expected error", bad)
		}
	}
}
