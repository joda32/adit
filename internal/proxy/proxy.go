// Package proxy tunnels the ADWS TCP connection through an HTTP or SOCKS proxy.
//
// ADWS is not HTTP — it rides WCF's net.tcp binding (raw TCP on 9389 with .NET
// Message Framing) — but that only matters to what travels *inside* the tunnel.
// A proxy forwards the TCP stream regardless of its contents:
//
//   - HTTP proxies open a raw tunnel via the CONNECT method (the same mechanism
//     HTTPS uses through a corporate proxy).
//   - SOCKS4/4a/5 tunnel TCP natively (this is what `ssh -D` exposes).
//
// This makes it possible to audit a domain reachable only through a jump host:
// point -proxy at the forwarder and adit dials the DC across it.
//
// Where the proxy protocol allows it (SOCKS5, SOCKS4a, HTTP CONNECT) the target
// hostname is sent to the proxy for *remote* resolution, so a DC name that only
// resolves on the far side of the jump host still works.
package proxy

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Dialer establishes a TCP connection to addr, possibly through a proxy. The
// signature matches nmf.DialFunc so a Dialer's Dial method can be passed
// straight through.
type Dialer interface {
	Dial(network, addr string) (net.Conn, error)
	// Describe returns a short, credential-free description for logging.
	Describe() string
}

// New parses a proxy URL and returns a Dialer. An empty string yields a direct
// dialer (no proxy). Supported schemes:
//
//	socks5://[user:pass@]host:port   socks5h:// (alias, remote DNS)
//	socks4://host:port               socks4a:// (remote DNS)
//	http://[user:pass@]host:port     https:// (TLS to the proxy itself)
func New(raw string, timeout time.Duration) (Dialer, error) {
	if strings.TrimSpace(raw) == "" {
		return direct{timeout: timeout}, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("proxy: parse %q: %w", raw, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("proxy: %q has no host:port", raw)
	}
	user := ""
	pass := ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		return &socks5{proxy: u.Host, user: user, pass: pass, timeout: timeout}, nil
	case "socks4":
		return &socks4{proxy: u.Host, user: user, remoteDNS: false, timeout: timeout}, nil
	case "socks4a":
		return &socks4{proxy: u.Host, user: user, remoteDNS: true, timeout: timeout}, nil
	case "http", "https":
		h := &httpConnect{proxy: u.Host, tls: u.Scheme == "https", timeout: timeout}
		if user != "" || pass != "" {
			h.auth = basicAuth(user, pass)
		}
		return h, nil
	default:
		return nil, fmt.Errorf("proxy: unsupported scheme %q (want socks5, socks4, socks4a, http or https)", u.Scheme)
	}
}

// direct dials without a proxy.
type direct struct{ timeout time.Duration }

func (d direct) Dial(network, addr string) (net.Conn, error) {
	return net.DialTimeout(network, addr, d.timeout)
}

func (d direct) Describe() string { return "direct (no proxy)" }

// dialProxy connects to the proxy itself and applies the handshake deadline.
func dialProxy(proxyAddr string, timeout time.Duration) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("proxy: connect to proxy %s: %w", proxyAddr, err)
	}
	if timeout > 0 {
		_ = c.SetDeadline(time.Now().Add(timeout))
	}
	return c, nil
}

func splitHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("proxy: bad target %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("proxy: bad target port in %q", addr)
	}
	return host, port, nil
}
