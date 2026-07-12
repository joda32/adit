package krb5

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/types"
)

// testKey is a fixed AES-256 session key.
func testKey() types.EncryptionKey {
	kv := make([]byte, 32)
	for i := range kv {
		kv[i] = byte(i + 1)
	}
	return types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: kv}
}

// TestWrapRoundTripDuplex checks both directions: initiator->acceptor and
// acceptor->initiator, using two Sessions sharing the key.
func TestWrapRoundTripDuplex(t *testing.T) {
	key := testKey()
	initiator, err := NewSession(key, true, false)
	if err != nil {
		t.Fatal(err)
	}
	acceptor, err := NewSession(key, false, false)
	if err != nil {
		t.Fatal(err)
	}

	msgs := [][]byte{
		[]byte("hello adws over kerberos"),
		[]byte(""),
		bytes.Repeat([]byte{0xAB}, 1000),
	}
	for i, msg := range msgs {
		// initiator seals, acceptor unseals
		tok, err := initiator.Seal(msg)
		if err != nil {
			t.Fatalf("msg %d initiator.Seal: %v", i, err)
		}
		got, err := acceptor.Unseal(tok)
		if err != nil {
			t.Fatalf("msg %d acceptor.Unseal: %v", i, err)
		}
		if !bytes.Equal(got, msg) {
			t.Errorf("msg %d i->a mismatch", i)
		}

		// acceptor seals, initiator unseals
		tok2, err := acceptor.Seal(msg)
		if err != nil {
			t.Fatalf("msg %d acceptor.Seal: %v", i, err)
		}
		got2, err := initiator.Unseal(tok2)
		if err != nil {
			t.Fatalf("msg %d initiator.Unseal: %v", i, err)
		}
		if !bytes.Equal(got2, msg) {
			t.Errorf("msg %d a->i mismatch", i)
		}
	}
}

func TestWrapTokenStructure(t *testing.T) {
	initiator, _ := NewSession(testKey(), true, false)
	tok, err := initiator.Seal([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(tok[0:2]) != wrapTokenID {
		t.Errorf("tok id = %x", tok[0:2])
	}
	if tok[2]&flagSealed == 0 {
		t.Error("sealed flag not set")
	}
	if tok[2]&flagSentByAcceptor != 0 {
		t.Error("initiator token should not have SentByAcceptor")
	}
	if binary.BigEndian.Uint64(tok[8:16]) != 0 {
		t.Error("first token should have seq 0")
	}
}

func TestUnsealRejectsInitiatorEcho(t *testing.T) {
	// An initiator must reject a token that isn't marked SentByAcceptor.
	initiator, _ := NewSession(testKey(), true, false)
	peerInitiator, _ := NewSession(testKey(), true, false) // also initiator (wrong)
	tok, _ := peerInitiator.Seal([]byte("nope"))
	if _, err := initiator.Unseal(tok); err == nil {
		t.Fatal("expected rejection of non-acceptor token")
	}
}

// TestUnsealHandlesRRC verifies decryption of a right-rotated token (as some
// GSS peers send), by manually rotating a valid token's ciphertext.
func TestUnsealHandlesRRC(t *testing.T) {
	acceptor, _ := NewSession(testKey(), false, false)
	initiator, _ := NewSession(testKey(), true, false)

	msg := []byte("rotate me")
	tok, _ := acceptor.Seal(msg) // RRC=0
	// Re-rotate the ciphertext right by 5 and set RRC=5 in the header.
	ct := tok[16:]
	rrc := 5 % len(ct)
	rotated := append(append([]byte{}, ct[len(ct)-rrc:]...), ct[:len(ct)-rrc]...)
	newTok := append(append([]byte{}, tok[:16]...), rotated...)
	binary.BigEndian.PutUint16(newTok[6:8], uint16(rrc))

	got, err := initiator.Unseal(newTok)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("RRC unseal mismatch: %q", got)
	}
}
