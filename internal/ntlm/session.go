package ntlm

import (
	"crypto/rc4"
	"encoding/binary"
	"fmt"
)

// signatureLen is the fixed size of an NTLM message signature with extended
// session security: Version(4) + Checksum(8) + SeqNum(4). [MS-NLMP] 2.2.2.9.1.
const signatureLen = 16

// Session holds the per-direction sealing state established after a successful
// NTLM authentication. It signs+seals outgoing messages and verifies+unseals
// incoming ones. The RC4 keystreams are continuous for the life of the session,
// so a Session is stateful and not safe for concurrent use.
type Session struct {
	clientSignKey []byte
	serverSignKey []byte
	clientSeal    *rc4.Cipher
	serverSeal    *rc4.Cipher

	sendSeq uint32
	recvSeq uint32

	// VerifyIncoming controls whether Unseal checks the server's signature.
	// The keystream is always advanced either way, so this only toggles the
	// integrity check, not wire compatibility.
	VerifyIncoming bool
}

// NewSession derives the four directional keys from the exported session key
// and returns a ready-to-use Session. The caller is the client.
func NewSession(exportedSessionKey []byte) (*Session, error) {
	clientSeal, err := rc4.NewCipher(SealKey(exportedSessionKey, true))
	if err != nil {
		return nil, err
	}
	serverSeal, err := rc4.NewCipher(SealKey(exportedSessionKey, false))
	if err != nil {
		return nil, err
	}
	return &Session{
		clientSignKey:  SignKey(exportedSessionKey, true),
		serverSignKey:  SignKey(exportedSessionKey, false),
		clientSeal:     clientSeal,
		serverSeal:     serverSeal,
		VerifyIncoming: true,
	}, nil
}

// mac computes the extended-session-security signature for a message using the
// given signing key, sequence number and (continuous) sealing cipher. The
// checksum is the RC4-encrypted first 8 bytes of HMAC_MD5(signKey, seq||msg),
// so it advances the cipher keystream by 8 bytes. [MS-NLMP] 3.4.4.2.
func mac(signKey []byte, seal *rc4.Cipher, seq uint32, message []byte) []byte {
	var seqBytes [4]byte
	binary.LittleEndian.PutUint32(seqBytes[:], seq)

	full := hmacMD5(signKey, append(seqBytes[:], message...))
	checksum := make([]byte, 8)
	seal.XORKeyStream(checksum, full[:8])

	sig := make([]byte, signatureLen)
	binary.LittleEndian.PutUint32(sig[0:], 1) // Version
	copy(sig[4:12], checksum)
	binary.LittleEndian.PutUint32(sig[12:], seq) // SeqNum
	return sig
}

// Seal encrypts and signs an outgoing message, returning signature||ciphertext
// — the exact NNS "signed payload" layout. It advances the client keystream by
// len(plaintext)+8 and increments the send sequence number.
func (s *Session) Seal(plaintext []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	s.clientSeal.XORKeyStream(ciphertext, plaintext)
	// MAC is computed over the plaintext, after the message keystream, matching
	// impacket's SEAL(handle(msg) then handle(checksum)).
	sig := mac(s.clientSignKey, s.clientSeal, s.sendSeq, plaintext)
	s.sendSeq++
	return append(sig, ciphertext...)
}

// Unseal reverses Seal for an incoming server message laid out as
// signature||ciphertext. It always advances the server keystream by
// len(ciphertext)+8 to stay aligned with the server, and (when VerifyIncoming
// is set) checks the signature.
func (s *Session) Unseal(payload []byte) ([]byte, error) {
	if len(payload) < signatureLen {
		return nil, fmt.Errorf("ntlm: sealed payload too short (%d bytes)", len(payload))
	}
	sig, ciphertext := payload[:signatureLen], payload[signatureLen:]

	plaintext := make([]byte, len(ciphertext))
	s.serverSeal.XORKeyStream(plaintext, ciphertext)

	// Recompute the signature; this also consumes the 8 checksum keystream
	// bytes the server produced, keeping the keystream aligned.
	want := mac(s.serverSignKey, s.serverSeal, s.recvSeq, plaintext)
	s.recvSeq++

	if s.VerifyIncoming && !equalConstTime(want, sig) {
		return nil, fmt.Errorf("ntlm: invalid message signature")
	}
	return plaintext, nil
}

func equalConstTime(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
