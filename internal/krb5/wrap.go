// Package krb5 implements the RFC 4121 GSS-API per-message "Wrap" tokens (with
// confidentiality) that MS-NNS uses to seal application data once a Kerberos
// security context is established. gokrb5 provides the credential, ticket and
// enctype machinery but only integrity Wrap tokens, so the sealed (encrypted)
// Wrap/Unwrap is implemented here on top of its enctype primitives.
package krb5

import (
	"encoding/binary"
	"fmt"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/crypto/etype"
	"github.com/jcmturner/gokrb5/v8/types"
)

// RFC 4121 key usage numbers for per-message tokens.
const (
	usageAcceptorSeal  = 22
	usageInitiatorSeal = 24
)

// Wrap-token header flag bits. [RFC 4121] 4.2.2.
const (
	flagSentByAcceptor = 0x01
	flagSealed         = 0x02
	flagAcceptorSubkey = 0x04
)

const wrapTokenID uint16 = 0x0504

// Session seals and unseals application data over an established Kerberos
// context. It is stateful (sequence numbers, continuous role) and not safe for
// concurrent use.
type Session struct {
	et  etype.EType
	key types.EncryptionKey

	sealUsage          uint32 // key usage when we encrypt
	unsealUsage        uint32 // key usage when we decrypt
	sealAcceptorFlag   byte   // SentByAcceptor bit we set on our tokens
	expectAcceptorFlag byte   // SentByAcceptor bit expected on incoming tokens
	extraFlags         byte   // e.g. AcceptorSubkey

	sendSeq uint64
	recvSeq uint64

	// Verify controls whether Unseal checks the incoming SentByAcceptor flag.
	Verify bool
}

// NewSession derives a sealing session from the negotiated key. initiator marks
// our role (the client is the initiator); acceptorSubkey records whether the
// acceptor supplied its own subkey (affects the flag byte only).
func NewSession(key types.EncryptionKey, initiator, acceptorSubkey bool) (*Session, error) {
	et, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, fmt.Errorf("krb5: unsupported enctype %d: %w", key.KeyType, err)
	}
	s := &Session{et: et, key: key, Verify: true}
	if initiator {
		s.sealUsage, s.unsealUsage = usageInitiatorSeal, usageAcceptorSeal
		s.sealAcceptorFlag = 0                    // our tokens: not from acceptor
		s.expectAcceptorFlag = flagSentByAcceptor // peer (acceptor) tokens: set
	} else {
		s.sealUsage, s.unsealUsage = usageAcceptorSeal, usageInitiatorSeal
		s.sealAcceptorFlag = flagSentByAcceptor
		s.expectAcceptorFlag = 0
	}
	if acceptorSubkey {
		s.extraFlags |= flagAcceptorSubkey
	}
	return s, nil
}

// header builds a 16-byte Wrap token header with EC=0 and RRC=0.
func (s *Session) header(seq uint64) []byte {
	h := make([]byte, 16)
	binary.BigEndian.PutUint16(h[0:2], wrapTokenID)
	h[2] = flagSealed | s.sealAcceptorFlag | s.extraFlags
	h[3] = 0xFF                           // filler
	binary.BigEndian.PutUint16(h[4:6], 0) // EC
	binary.BigEndian.PutUint16(h[6:8], 0) // RRC
	binary.BigEndian.PutUint64(h[8:16], seq)
	return h
}

// Seal produces a sealed Wrap token for plaintext: Header || Encrypt(plaintext ||
// Header). We send EC=0 and RRC=0 (no rotation). [RFC 4121] 4.2.6.2.
func (s *Session) Seal(plaintext []byte) ([]byte, error) {
	h := s.header(s.sendSeq)
	toEnc := make([]byte, 0, len(plaintext)+16)
	toEnc = append(toEnc, plaintext...)
	toEnc = append(toEnc, h...)

	_, enc, err := s.et.EncryptMessage(s.key.KeyValue, toEnc, s.sealUsage)
	if err != nil {
		return nil, fmt.Errorf("krb5: wrap encrypt: %w", err)
	}
	s.sendSeq++
	return append(h, enc...), nil
}

// Unseal reverses Seal for a sealed Wrap token from the peer. It un-rotates by
// the token's RRC, decrypts, and strips the trailing header + EC filler.
func (s *Session) Unseal(token []byte) ([]byte, error) {
	if len(token) < 16 {
		return nil, fmt.Errorf("krb5: wrap token too short (%d)", len(token))
	}
	if binary.BigEndian.Uint16(token[0:2]) != wrapTokenID {
		return nil, fmt.Errorf("krb5: not a wrap token")
	}
	flags := token[2]
	if flags&flagSealed == 0 {
		return nil, fmt.Errorf("krb5: wrap token not sealed")
	}
	if s.Verify && flags&flagSentByAcceptor != s.expectAcceptorFlag {
		return nil, fmt.Errorf("krb5: wrap token has unexpected sender role")
	}
	// Reject replayed / reordered tokens: the cleartext header carries the
	// sender's sequence number, which must match the next expected value.
	if s.Verify {
		if seq := binary.BigEndian.Uint64(token[8:16]); seq != s.recvSeq {
			return nil, fmt.Errorf("krb5: wrap token sequence %d, expected %d", seq, s.recvSeq)
		}
	}
	ec := int(binary.BigEndian.Uint16(token[4:6]))
	rrc := int(binary.BigEndian.Uint16(token[6:8]))

	ciphertext := rotateLeft(token[16:], rrc)
	plain, err := crypto.DecryptMessage(ciphertext, s.key, s.unsealUsage)
	if err != nil {
		return nil, fmt.Errorf("krb5: wrap decrypt: %w", err)
	}
	// plain = payload || EC filler || 16-byte header copy.
	if len(plain) < 16+ec {
		return nil, fmt.Errorf("krb5: wrap plaintext too short")
	}
	s.recvSeq++
	return plain[:len(plain)-16-ec], nil
}

// rotateLeft rotates b left by n bytes (reversing a right rotation by n).
func rotateLeft(b []byte, n int) []byte {
	if len(b) == 0 {
		return b
	}
	n %= len(b)
	out := make([]byte, 0, len(b))
	out = append(out, b[n:]...)
	return append(out, b[:n]...)
}
