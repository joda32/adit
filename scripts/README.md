# scripts

## gen_vectors.py

Regenerates the NTLM/NNS/SPNEGO ground-truth vectors that the Go unit tests
assert against. Outputs (client seal, server seal, key derivation, SPNEGO
tokens, type1 message) are produced by **impacket**, the reference the Go port
mimics, using fixed deterministic inputs.

```bash
python3 -m pip install --user impacket
python3 scripts/gen_vectors.py
```

The emitted hex values are copied into the `v*` constants in
`internal/ntlm/ntlm_test.go`, `internal/nns/nns_test.go` and
`internal/spnego/spnego_test.go`. If those constants ever need updating, run
this and re-copy — do not hand-edit the vectors.

## gen_nbfx_vectors.py

Regenerates the NBFX (.NET Binary XML) golden vectors in
`internal/nbfx/nbfx_test.go` from the PyADRecon-ADWS **encoder** — the reference
this codec mirrors. Encodes the real RootDSE/Enumerate/Pull SOAP templates and
prints their exact bytes plus the reference decoder's output.

```bash
PYADRECON=/path/to/PyADRecon-ADWS python3 scripts/gen_nbfx_vectors.py
```
