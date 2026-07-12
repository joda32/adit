package proxy

import (
	"fmt"
	"io"
	"net"
	"time"
)

// --- SOCKS5 (RFC 1928) with optional username/password auth (RFC 1929) ---

type socks5 struct {
	proxy   string
	user    string
	pass    string
	timeout time.Duration
}

func (s *socks5) Describe() string { return "socks5 proxy " + s.proxy + " (remote DNS)" }

func (s *socks5) Dial(network, addr string) (net.Conn, error) {
	host, port, err := splitHostPort(addr)
	if err != nil {
		return nil, err
	}
	c, err := dialProxy(s.proxy, s.timeout)
	if err != nil {
		return nil, err
	}

	// Greeting: offer no-auth, plus user/pass when credentials are set.
	methods := []byte{0x00}
	if s.user != "" || s.pass != "" {
		methods = []byte{0x02, 0x00}
	}
	greet := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := c.Write(greet); err != nil {
		c.Close()
		return nil, fmt.Errorf("proxy: socks5 greeting: %w", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(c, sel); err != nil {
		c.Close()
		return nil, fmt.Errorf("proxy: socks5 method reply: %w", err)
	}
	if sel[0] != 0x05 {
		c.Close()
		return nil, fmt.Errorf("proxy: socks5 bad version 0x%02x", sel[0])
	}
	switch sel[1] {
	case 0x00: // no auth
	case 0x02:
		if err := s.userPassAuth(c); err != nil {
			c.Close()
			return nil, err
		}
	case 0xff:
		c.Close()
		return nil, fmt.Errorf("proxy: socks5 proxy rejected offered auth methods")
	default:
		c.Close()
		return nil, fmt.Errorf("proxy: socks5 unexpected auth method 0x%02x", sel[1])
	}

	// CONNECT request.
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			c.Close()
			return nil, fmt.Errorf("proxy: socks5 hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, fmt.Errorf("proxy: socks5 connect request: %w", err)
	}

	// Reply: VER REP RSV ATYP BND.ADDR BND.PORT.
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		c.Close()
		return nil, fmt.Errorf("proxy: socks5 connect reply: %w", err)
	}
	if head[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("proxy: socks5 connect failed: %s", socks5Error(head[1]))
	}
	var bnd int
	switch head[3] {
	case 0x01:
		bnd = 4
	case 0x04:
		bnd = 16
	case 0x03:
		n := make([]byte, 1)
		if _, err := io.ReadFull(c, n); err != nil {
			c.Close()
			return nil, err
		}
		bnd = int(n[0])
	default:
		c.Close()
		return nil, fmt.Errorf("proxy: socks5 bad bound ATYP 0x%02x", head[3])
	}
	if _, err := io.CopyN(io.Discard, c, int64(bnd+2)); err != nil { // +2 for port
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

func (s *socks5) userPassAuth(c net.Conn) error {
	if len(s.user) > 255 || len(s.pass) > 255 {
		return fmt.Errorf("proxy: socks5 credential too long")
	}
	msg := []byte{0x01, byte(len(s.user))}
	msg = append(msg, s.user...)
	msg = append(msg, byte(len(s.pass)))
	msg = append(msg, s.pass...)
	if _, err := c.Write(msg); err != nil {
		return fmt.Errorf("proxy: socks5 auth: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		return fmt.Errorf("proxy: socks5 auth reply: %w", err)
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("proxy: socks5 username/password auth rejected")
	}
	return nil
}

func socks5Error(rep byte) string {
	switch rep {
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown error 0x%02x", rep)
	}
}

// --- SOCKS4 / SOCKS4a ---

type socks4 struct {
	proxy     string
	user      string
	remoteDNS bool // SOCKS4a: send the hostname for the proxy to resolve
	timeout   time.Duration
}

func (s *socks4) Describe() string {
	if s.remoteDNS {
		return "socks4a proxy " + s.proxy + " (remote DNS)"
	}
	return "socks4 proxy " + s.proxy + " (local DNS)"
}

func (s *socks4) Dial(network, addr string) (net.Conn, error) {
	host, port, err := splitHostPort(addr)
	if err != nil {
		return nil, err
	}

	var dstIP []byte
	var hostname string
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		dstIP = ip.To4()
	} else if s.remoteDNS {
		// SOCKS4a: an IP of 0.0.0.x (x != 0) tells the proxy to resolve HOSTNAME.
		dstIP = []byte{0, 0, 0, 1}
		hostname = host
	} else {
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("proxy: socks4 resolve %s: %w", host, err)
		}
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				dstIP = v4
				break
			}
		}
		if dstIP == nil {
			return nil, fmt.Errorf("proxy: socks4 has no IPv4 for %s (use socks4a for remote DNS)", host)
		}
	}

	c, err := dialProxy(s.proxy, s.timeout)
	if err != nil {
		return nil, err
	}
	req := []byte{0x04, 0x01, byte(port >> 8), byte(port)}
	req = append(req, dstIP...)
	req = append(req, s.user...)
	req = append(req, 0x00)
	if hostname != "" {
		req = append(req, hostname...)
		req = append(req, 0x00)
	}
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, fmt.Errorf("proxy: socks4 request: %w", err)
	}
	resp := make([]byte, 8)
	if _, err := io.ReadFull(c, resp); err != nil {
		c.Close()
		return nil, fmt.Errorf("proxy: socks4 reply: %w", err)
	}
	if resp[1] != 0x5a {
		c.Close()
		return nil, fmt.Errorf("proxy: socks4 request rejected (0x%02x)", resp[1])
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}
