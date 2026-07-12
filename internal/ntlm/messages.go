package ntlm

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

var ntlmSignature = []byte("NTLMSSP\x00")

const (
	msgTypeNegotiate    = 1
	msgTypeChallenge    = 2
	msgTypeAuthenticate = 3
)

// msvAvTimestamp is the AV_PAIR id carrying the server's FILETIME. [MS-NLMP] 2.2.2.1.
const msvAvTimestamp = 0x0007

// negotiateFlagsType1 is the flag set a client advertises: signing/sealing with
// key exchange, NTLMv2 (target info), extended session security, unicode,
// 128/56-bit. Matches impacket's getNTLMSSPType1(signingRequired, use_ntlmv2).
const negotiateFlagsType1 = NegotiateKeyExch | NegotiateSign | NegotiateAlwaysSign |
	NegotiateSeal | NegotiateTargetInfo | NegotiateNTLM | NegotiateExtendedSessionSecurity |
	NegotiateUnicode | RequestTarget | Negotiate128 | Negotiate56

// Client drives an NTLMv2 authentication. Zero randomness fields are filled
// from crypto/rand; tests may set them for determinism.
type Client struct {
	Domain      string
	User        string
	Password    string
	Workstation string

	flags uint32

	// Test seams; nil means "generate randomly".
	clientChallenge    []byte // 8 bytes
	exportedSessionKey []byte // 16 bytes
}

// NewClient returns a Client for the given credentials.
func NewClient(domain, user, password, workstation string) *Client {
	return &Client{
		Domain:      domain,
		User:        user,
		Password:    password,
		Workstation: workstation,
		flags:       negotiateFlagsType1,
	}
}

// Negotiate builds the NTLM NEGOTIATE (type 1) message. [MS-NLMP] 2.2.1.1.
func (c *Client) Negotiate() []byte {
	buf := make([]byte, 32)
	copy(buf[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(buf[8:], msgTypeNegotiate)
	binary.LittleEndian.PutUint32(buf[12:], c.flags)
	// DomainName and Workstation fields left zero (not supplied), as Windows
	// clients do; the workstation is carried in the type 3 message instead.
	return buf
}

// challenge holds the fields parsed from a CHALLENGE (type 2) message.
type challenge struct {
	flags           uint32
	serverChallenge []byte // 8 bytes
	targetInfo      []byte
	timestamp       []byte // 8 bytes, from AV pairs; nil if absent
}

// parseChallenge parses a type 2 message. [MS-NLMP] 2.2.1.2.
func parseChallenge(data []byte) (*challenge, error) {
	if len(data) < 48 {
		return nil, fmt.Errorf("ntlm: challenge too short (%d bytes)", len(data))
	}
	if !bytes.Equal(data[0:8], ntlmSignature) {
		return nil, fmt.Errorf("ntlm: bad challenge signature")
	}
	if mt := binary.LittleEndian.Uint32(data[8:]); mt != msgTypeChallenge {
		return nil, fmt.Errorf("ntlm: expected challenge message, got type %d", mt)
	}

	ch := &challenge{
		flags:           binary.LittleEndian.Uint32(data[20:]),
		serverChallenge: data[24:32],
	}

	// TargetInfoFields at offset 40: Len(2), MaxLen(2), BufferOffset(4).
	tiLen := int(binary.LittleEndian.Uint16(data[40:]))
	tiOff := int(binary.LittleEndian.Uint32(data[44:]))
	if tiLen > 0 {
		if tiOff < 0 || tiOff+tiLen > len(data) {
			return nil, fmt.Errorf("ntlm: target info out of bounds")
		}
		ch.targetInfo = data[tiOff : tiOff+tiLen]
		ch.timestamp = avPairValue(ch.targetInfo, msvAvTimestamp)
	}
	return ch, nil
}

// avPairValue returns the value of the AV pair with the given id, or nil.
func avPairValue(av []byte, id uint16) []byte {
	for len(av) >= 4 {
		pairID := binary.LittleEndian.Uint16(av)
		pairLen := int(binary.LittleEndian.Uint16(av[2:]))
		if pairID == 0 { // MsvAvEOL
			return nil
		}
		if 4+pairLen > len(av) {
			return nil
		}
		if pairID == id {
			return av[4 : 4+pairLen]
		}
		av = av[4+pairLen:]
	}
	return nil
}

// Authenticate consumes the server CHALLENGE and produces the AUTHENTICATE
// (type 3) message plus the sealing Session derived from the exported session
// key. [MS-NLMP] 2.2.1.3 / 3.2.5.1.2.
func (c *Client) Authenticate(type2 []byte) (type3 []byte, sess *Session, err error) {
	ch, err := parseChallenge(type2)
	if err != nil {
		return nil, nil, err
	}

	clientChallenge := c.clientChallenge
	if clientChallenge == nil {
		clientChallenge = make([]byte, 8)
		if _, err := rand.Read(clientChallenge); err != nil {
			return nil, nil, err
		}
	}

	// Use the server's timestamp when present (required by modern DCs),
	// otherwise a zero timestamp.
	timestamp := ch.timestamp
	if timestamp == nil {
		timestamp = make([]byte, 8)
	}

	key := ntowf(c.User, c.Password, c.Domain)
	ntResp, lmResp, sessionBaseKey := ComputeV2Response(
		key, ch.serverChallenge, clientChallenge, timestamp, ch.targetInfo)

	responseFlags := c.negotiatedFlags(ch.flags)

	// For NTLMv2 the key exchange key is the session base key.
	exportedSessionKey := sessionBaseKey
	var encryptedSessionKey []byte
	if responseFlags&NegotiateKeyExch != 0 {
		exportedSessionKey = c.exportedSessionKey
		if exportedSessionKey == nil {
			exportedSessionKey = make([]byte, 16)
			if _, err := rand.Read(exportedSessionKey); err != nil {
				return nil, nil, err
			}
		}
		encryptedSessionKey, err = EncryptRandomSessionKey(sessionBaseKey, exportedSessionKey)
		if err != nil {
			return nil, nil, err
		}
	}

	type3 = buildType3(responseFlags, c.Domain, c.User, c.Workstation, lmResp, ntResp, encryptedSessionKey)
	sess, err = NewSession(exportedSessionKey)
	if err != nil {
		return nil, nil, err
	}
	return type3, sess, nil
}

// negotiatedFlags reduces the client's advertised flags to those the server
// also offered. [MS-NLMP] 3.1.5.1.2.
func (c *Client) negotiatedFlags(serverFlags uint32) uint32 {
	resp := c.flags
	for _, bit := range []uint32{
		NegotiateExtendedSessionSecurity, Negotiate128, NegotiateKeyExch,
		NegotiateSeal, NegotiateSign, NegotiateAlwaysSign,
	} {
		if serverFlags&bit == 0 {
			resp &^= bit
		}
	}
	return resp
}

// buildType3 assembles the AUTHENTICATE message. Header is 64 bytes (no Version
// or MIC, matching the negotiated flag set); payload order is
// domain, user, workstation, lm, nt, session key. [MS-NLMP] 2.2.1.3.
func buildType3(flags uint32, domain, user, workstation string, lm, nt, sessionKey []byte) []byte {
	domainB := utf16le(domain)
	userB := utf16le(user)
	hostB := utf16le(workstation)

	const headerLen = 64
	var payload bytes.Buffer

	// field writes a Len/MaxLen/Offset descriptor at hdr[pos] for content that
	// will live at headerLen+payload.Len(), then appends content to payload.
	hdr := make([]byte, headerLen)
	field := func(pos int, content []byte) {
		off := headerLen + payload.Len()
		binary.LittleEndian.PutUint16(hdr[pos:], uint16(len(content)))
		binary.LittleEndian.PutUint16(hdr[pos+2:], uint16(len(content)))
		binary.LittleEndian.PutUint32(hdr[pos+4:], uint32(off))
		payload.Write(content)
	}

	copy(hdr[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(hdr[8:], msgTypeAuthenticate)

	// Descriptor slots (see NTLMAuthChallengeResponse layout): lanman, ntlm,
	// domain, user, host, session_key at 12,20,28,36,44,52; flags at 60.
	// Payload is laid out in the order fields are written below.
	field(28, domainB) // domain
	field(36, userB)   // user
	field(44, hostB)   // workstation
	field(12, lm)      // lanman
	field(20, nt)      // ntlm
	field(52, sessionKey)
	binary.LittleEndian.PutUint32(hdr[60:], flags)

	return append(hdr, payload.Bytes()...)
}
