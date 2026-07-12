// Package nmf implements the client (initiator) side of the .NET Message
// Framing Protocol, [MC-NMF].
//
// ADWS (Active Directory Web Services, TCP/9389) exposes its SOAP endpoints
// over WCF's net.tcp binding rather than HTTP. net.tcp frames every message
// with MC-NMF: a short preamble negotiates protocol version, communication
// mode, the target "via" URI and the payload encoding; the connection is then
// (optionally) upgraded to a secure transport via MS-NNS; and application
// messages flow as length-prefixed "sized envelope" records.
//
// This package speaks only the framing. It delegates two concerns to
// interfaces so the layers above and below can be developed independently:
//
//   - Authenticator performs the MS-NNS upgrade/auth handshake and returns the
//     sealed transport used for the rest of the session. See internal/nns.
//   - Encoder serializes/deserializes the SOAP payload, i.e. the .NET Binary
//     XML encoding [MC-NBFS]/[MC-NBFSE]. See internal/nbfx.
//
// Only Duplex mode is implemented, which is what ADWS uses.
//
// Record layout and the size-encoding scheme follow [MC-NMF] sections 2.2.1
// and 2.2.2 respectively.
package nmf
