// Package ntlm implements the subset of NTLM ([MS-NLMP]) needed to
// authenticate and then sign+seal a session for MS-NNS: NTLMv2 response
// computation, key derivation, and the extended-session-security SEAL used on
// every application message.
//
// It targets the "extended session security" (NTLM2) path with key exchange
// and 128-bit keys — what a modern domain controller negotiates. The crypto is
// validated byte-for-byte against impacket in ntlm_test.go.
package ntlm

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// Negotiate flag bits. [MS-NLMP] 2.2.2.5.
const (
	NegotiateUnicode                 uint32 = 0x00000001
	NegotiateOEM                     uint32 = 0x00000002
	RequestTarget                    uint32 = 0x00000004
	NegotiateSign                    uint32 = 0x00000010
	NegotiateSeal                    uint32 = 0x00000020
	NegotiateDatagram                uint32 = 0x00000040
	NegotiateLMKey                   uint32 = 0x00000080
	NegotiateNTLM                    uint32 = 0x00000200
	NegotiateAnonymous               uint32 = 0x00000800
	NegotiateOEMDomainSupplied       uint32 = 0x00001000
	NegotiateOEMWorkstationSupplied  uint32 = 0x00002000
	NegotiateAlwaysSign              uint32 = 0x00008000
	NegotiateTargetTypeDomain        uint32 = 0x00010000
	NegotiateExtendedSessionSecurity uint32 = 0x00080000
	NegotiateTargetInfo              uint32 = 0x00800000
	NegotiateVersion                 uint32 = 0x02000000
	Negotiate128                     uint32 = 0x20000000
	NegotiateKeyExch                 uint32 = 0x40000000
	Negotiate56                      uint32 = 0x80000000
)

// utf16le encodes s as little-endian UTF-16 (no BOM), the wire form for NTLM
// string fields.
func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func hmacMD5(key, data []byte) []byte {
	m := hmac.New(md5.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// ntowf computes the NTLMv2 one-way function:
//
//	HMAC_MD5(MD4(UTF16LE(password)), UTF16LE(upper(user) + domain))
//
// Only the user is upper-cased, matching [MS-NLMP] 3.3.2 and impacket.
func ntowf(user, password, domain string) []byte {
	h := md4.New()
	h.Write(utf16le(password))
	ntHash := h.Sum(nil)
	return hmacMD5(ntHash, utf16le(strings.ToUpper(user)+domain))
}

// ComputeV2Response builds the NTLMv2 NT and LM challenge responses, and the
// session base key, from the server challenge, a client challenge, a timestamp
// (8 bytes, little-endian FILETIME) and the server's target-info AV-pair blob.
// [MS-NLMP] 3.3.2.
func ComputeV2Response(ntowfv2, serverChallenge, clientChallenge, timestamp, targetInfo []byte) (ntResponse, lmResponse, sessionBaseKey []byte) {
	// temp = RespVer(1) HiRespVer(1) Reserved(6) Timestamp(8) ClientChal(8)
	//        Reserved(4) TargetInfo(var)
	temp := make([]byte, 0, 28+len(targetInfo))
	temp = append(temp, 0x01, 0x01, 0, 0, 0, 0, 0, 0)
	temp = append(temp, timestamp...)
	temp = append(temp, clientChallenge...)
	temp = append(temp, 0, 0, 0, 0)
	temp = append(temp, targetInfo...)

	ntProof := hmacMD5(ntowfv2, concat(serverChallenge, temp))
	ntResponse = concat(ntProof, temp)
	lmResponse = concat(hmacMD5(ntowfv2, concat(serverChallenge, clientChallenge)), clientChallenge)
	sessionBaseKey = hmacMD5(ntowfv2, ntProof)
	return ntResponse, lmResponse, sessionBaseKey
}

// signKeyMagic / sealKeyMagic are the [MS-NLMP] 3.4.5.2 / 3.4.5.3 constants.
func signKeyMagic(mode string) []byte {
	return []byte("session key to " + mode + " signing key magic constant\x00")
}

func sealKeyMagic(mode string) []byte {
	return []byte("session key to " + mode + " sealing key magic constant\x00")
}

const (
	clientToServer = "client-to-server"
	serverToClient = "server-to-client"
)

// SignKey derives a signing key from the exported session key. Requires
// extended session security (always true here). [MS-NLMP] 3.4.5.2.
func SignKey(exportedSessionKey []byte, client bool) []byte {
	mode := serverToClient
	if client {
		mode = clientToServer
	}
	h := md5.New()
	h.Write(exportedSessionKey)
	h.Write(signKeyMagic(mode))
	return h.Sum(nil)
}

// SealKey derives a sealing key from the exported session key, assuming
// extended session security with a 128-bit key. [MS-NLMP] 3.4.5.3.
func SealKey(exportedSessionKey []byte, client bool) []byte {
	mode := serverToClient
	if client {
		mode = clientToServer
	}
	h := md5.New()
	h.Write(exportedSessionKey) // 128-bit: full key
	h.Write(sealKeyMagic(mode))
	return h.Sum(nil)
}

// EncryptRandomSessionKey RC4-encrypts the exported session key with the key
// exchange key (= session base key for NTLMv2). [MS-NLMP] 3.4.5.1.
func EncryptRandomSessionKey(keyExchangeKey, exportedSessionKey []byte) ([]byte, error) {
	c, err := rc4.NewCipher(keyExchangeKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(exportedSessionKey))
	c.XORKeyStream(out, exportedSessionKey)
	return out, nil
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
