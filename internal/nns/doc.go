// Package nns will implement the client side of the .NET NegotiateStream
// Protocol, [MS-NNS] — the transport-security upgrade that MC-NMF negotiates.
//
// Responsibilities (next milestone):
//
//   - Handshake framing: NNS handshake messages (message id, version, payload)
//     carrying GSS-API/SPNEGO tokens.
//   - NTLM: NTLMSSP NEGOTIATE/CHALLENGE/AUTHENTICATE, session-key derivation,
//     then per-message sign & seal (SIGNKEY/SEALKEY, RC4, HMAC-MD5). Ports the
//     logic in PyADRecon-ADWS helpers/adws/ms_nns.py (impacket ntlm.SEAL).
//   - Kerberos: SPNEGO-wrapped AP-REQ and GSS-API Wrap/Unwrap with
//     confidentiality (jcmturner/gokrb5).
//   - NNS data framing: after auth, application bytes flow as length-prefixed,
//     signed+sealed NNS data messages, reassembled across ~64 KiB fragments.
//
// The exported type will satisfy nmf.Authenticator: Authenticate(rw) runs the
// handshake over the raw post-upgrade transport and returns an io.ReadWriter
// that transparently seals writes and unseals reads.
package nns
