package proxy

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// httpConnect tunnels TCP through an HTTP proxy using the CONNECT method.
type httpConnect struct {
	proxy   string
	tls     bool   // TLS to the proxy itself (https:// scheme)
	auth    string // "Basic <base64>" or ""
	timeout time.Duration
}

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func (h *httpConnect) Describe() string {
	scheme := "http"
	if h.tls {
		scheme = "https"
	}
	return fmt.Sprintf("%s proxy %s (CONNECT)", scheme, h.proxy)
}

func (h *httpConnect) Dial(network, addr string) (net.Conn, error) {
	c, err := dialProxy(h.proxy, h.timeout)
	if err != nil {
		return nil, err
	}
	if h.tls {
		host, _, _ := net.SplitHostPort(h.proxy)
		tc := tls.Client(c, &tls.Config{ServerName: host})
		if err := tc.Handshake(); err != nil {
			c.Close()
			return nil, fmt.Errorf("proxy: TLS handshake with proxy %s: %w", h.proxy, err)
		}
		c = tc
	}

	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\n", addr)
	fmt.Fprintf(&b, "Host: %s\r\n", addr)
	if h.auth != "" {
		fmt.Fprintf(&b, "Proxy-Authorization: %s\r\n", h.auth)
	}
	b.WriteString("Proxy-Connection: Keep-Alive\r\n\r\n")
	if _, err := io.WriteString(c, b.String()); err != nil {
		c.Close()
		return nil, fmt.Errorf("proxy: send CONNECT: %w", err)
	}

	code, reason, err := readConnectStatus(c)
	if err != nil {
		c.Close()
		return nil, err
	}
	if code != 200 {
		c.Close()
		return nil, fmt.Errorf("proxy: CONNECT %s rejected: HTTP %d %s", addr, code, reason)
	}
	_ = c.SetDeadline(time.Time{}) // clear handshake deadline for long-lived use
	return c, nil
}

// readConnectStatus reads the response headers one byte at a time up to the
// terminating CRLFCRLF, so no bytes belonging to the tunnelled stream are
// consumed, and returns the status code and reason phrase.
func readConnectStatus(c net.Conn) (int, string, error) {
	var buf []byte
	one := make([]byte, 1)
	for {
		if _, err := io.ReadFull(c, one); err != nil {
			return 0, "", fmt.Errorf("proxy: read CONNECT response: %w", err)
		}
		buf = append(buf, one[0])
		if len(buf) >= 4 && buf[len(buf)-4] == '\r' && buf[len(buf)-3] == '\n' &&
			buf[len(buf)-2] == '\r' && buf[len(buf)-1] == '\n' {
			break
		}
		if len(buf) > 1<<16 {
			return 0, "", fmt.Errorf("proxy: CONNECT response headers too large")
		}
	}
	// First line: "HTTP/1.1 200 Connection established".
	line := string(buf)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	fields := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		return 0, "", fmt.Errorf("proxy: malformed CONNECT status line %q", strings.TrimSpace(line))
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, "", fmt.Errorf("proxy: bad CONNECT status code %q", fields[1])
	}
	reason := ""
	if len(fields) == 3 {
		reason = fields[2]
	}
	return code, reason, nil
}
