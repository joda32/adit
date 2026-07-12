"""Generate byte-exact NTLM/NNS ground-truth vectors from impacket.

We monkeypatch the two sources of nondeterminism in impacket's NTLMv2 path
(the client challenge and the exported session key) so outputs are reproducible,
then dump everything the Go implementation must reproduce.
"""
import struct, hmac, hashlib, binascii
from impacket import ntlm

H = lambda b: binascii.hexlify(b).decode()

# ---- Fixed inputs -----------------------------------------------------------
USER = "User"
DOMAIN = "Domain"
PASSWORD = "Password"
WORKSTATION = ""
SERVER_CHALLENGE = bytes.fromhex("0123456789abcdef")
CLIENT_CHALLENGE = bytes.fromhex("aaaaaaaaaaaaaaaa")
EXPORTED_SESSION_KEY = bytes(range(0x10, 0x20))  # 10 11 .. 1f
# Target info (AV pairs): NB domain "Domain", NB computer "Server", EOL
TARGET_INFO = bytes.fromhex(
    "0200" "0c00" + H("Domain".encode("utf-16-le")) +
    "0100" "0c00" + H("Server".encode("utf-16-le")) +
    "0000" "0000"
)

# Flags a Windows server typically negotiates for NNS (unicode, ntlm, sign,
# seal, ntlm2/extended session security, key exchange, target info, 128/56).
NEGOTIATE_FLAGS = (
    ntlm.NTLMSSP_NEGOTIATE_UNICODE
    | ntlm.NTLMSSP_NEGOTIATE_NTLM
    | ntlm.NTLMSSP_NEGOTIATE_SIGN
    | ntlm.NTLMSSP_NEGOTIATE_SEAL
    | ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN
    | ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    | ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH
    | ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO
    | ntlm.NTLMSSP_NEGOTIATE_VERSION
    | ntlm.NTLMSSP_NEGOTIATE_128
    | ntlm.NTLMSSP_NEGOTIATE_56
)

# ---- Deterministic mode -----------------------------------------------------
# TEST_CASE=True makes impacket use a zero timestamp and skip the impacket-
# specific SPN-target-name AV pair, so temp is fully determined by our inputs
# and matches the MS-NLMP spec construction our Go code implements.
ntlm.TEST_CASE = True

# ---- NTOWFv2 / keys ---------------------------------------------------------
# Signature: computeResponseNTLMv2(flags, serverChallenge, clientChallenge,
#                                  serverName, domain, user, password, ...)
# serverName is the target-info AV-pair blob.
resp_nt, resp_lm, session_base_key = ntlm.computeResponseNTLMv2(
    NEGOTIATE_FLAGS, SERVER_CHALLENGE, CLIENT_CHALLENGE,
    TARGET_INFO, DOMAIN, USER, PASSWORD,
)

ntowf = ntlm.NTOWFv2(USER, PASSWORD, DOMAIN)  # impacket bundles its own MD4

# KeyExchangeKey for NTLMv2 == SessionBaseKey
key_exchange_key = session_base_key
encrypted_random_session_key = ntlm.generateEncryptedSessionKey(key_exchange_key, EXPORTED_SESSION_KEY)

# ---- Signing / sealing keys -------------------------------------------------
client_signing = ntlm.SIGNKEY(NEGOTIATE_FLAGS, EXPORTED_SESSION_KEY, "Client")
server_signing = ntlm.SIGNKEY(NEGOTIATE_FLAGS, EXPORTED_SESSION_KEY, "Server")
client_sealing = ntlm.SEALKEY(NEGOTIATE_FLAGS, EXPORTED_SESSION_KEY, "Client")
server_sealing = ntlm.SEALKEY(NEGOTIATE_FLAGS, EXPORTED_SESSION_KEY, "Server")

# ---- SEAL a sample message (seq 0) ------------------------------------------
from Cryptodome.Cipher import ARC4
plaintext = b"hello adws"
c_handle = ARC4.new(client_sealing).encrypt
sealed, sig = ntlm.SEAL(
    NEGOTIATE_FLAGS, client_signing, client_sealing, plaintext, plaintext, 0, c_handle,
)

# ---- NT proof / temp for lower-level cross-check ----------------------------
def make_temp():
    ts = b"\x00" * 8
    return (b"\x01\x01" + b"\x00"*6 + ts + CLIENT_CHALLENGE + b"\x00"*4 +
            TARGET_INFO + b"\x00"*4)
temp = make_temp()
nt_proof = hmac.new(ntowf, SERVER_CHALLENGE + temp, hashlib.md5).digest()

def emit(name, val):
    print(f"{name}={val}")

print("# ===== NTLM/NNS ground-truth vectors (impacket) =====")
emit("user", USER); emit("domain", DOMAIN); emit("password", PASSWORD)
emit("server_challenge", H(SERVER_CHALLENGE))
emit("client_challenge", H(CLIENT_CHALLENGE))
emit("exported_session_key", H(EXPORTED_SESSION_KEY))
emit("target_info", H(TARGET_INFO))
emit("negotiate_flags", hex(NEGOTIATE_FLAGS))
emit("ntowfv2", H(ntowf))
emit("temp", H(temp))
emit("nt_proof_str", H(nt_proof))
emit("nt_challenge_response", H(resp_nt))
emit("lm_challenge_response", H(resp_lm))
emit("session_base_key", H(session_base_key))
emit("key_exchange_key", H(key_exchange_key))
emit("encrypted_random_session_key", H(encrypted_random_session_key))
emit("client_signing_key", H(client_signing))
emit("server_signing_key", H(server_signing))
emit("client_sealing_key", H(client_sealing))
emit("server_sealing_key", H(server_sealing))
emit("seal_plaintext", H(plaintext))
emit("seal_seqnum", "0")
emit("seal_ciphertext", H(sealed))
emit("seal_signature", H(sig.getData()))
