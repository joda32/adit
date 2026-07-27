# Design note: Certipy-backed validation of ADCS findings

**Status:** Draft / feasibility (not implemented)
**Scope:** Optionally *validate* adit's ADCS audit findings by attempting the
corresponding action with Certipy, turning metadata-based detections into
confirmed, exploitability-proven findings.

---

## 1. Problem

adit's audit engine performs **metadata detection** of AD CS misconfigurations
(ESC1–ESC5, ESC9) by reading template/CA attributes and ACLs over ADWS. This
tells you a template *is configured* in a vulnerable way, but never proves that
the CA will actually issue an abusable certificate. Real environments produce
false positives: the CA may be offline, the template may not be published to an
issuing CA, CA-side filtering or approval may block it, etc.

**Validation** closes that gap by performing the enrollment/action and observing
the result. It also covers the ESCs adit cannot see over ADWS at all (ESC6/7/8,
which live in the CA host registry and HTTP endpoints — see §4).

The catch: for most ESCs there is no passive proof. Confirming ESC1 means
requesting a certificate with an attacker-chosen SAN — that *is* the attack. So
validation is inherently a semi-active, authenticated step and is a departure
from adit's strictly read-only posture. This note treats that as the central
design constraint.

## 2. Non-goals

- Reimplementing certificate enrollment (MS-WCCE) or relay natively in Go.
- Making validation part of the default audit run.
- Full ESC8 relay tooling (coercion + listener + relay) inside adit.
- Weakening the read-only guarantee of the detection engine.

## 3. Architecture

| Option | Assessment |
|---|---|
| **Subprocess → Certipy CLI, parse JSON** | **Recommended.** Certipy is mature, maintained, impacket-based, and emits JSON. adit shells out, passes the same credentials, parses results, and folds them into findings. Low effort, high fidelity. |
| **Native Go MS-WCCE / DCOM** | Rejected. No mature Go MS-WCCE/DCOM library exists, and adit's stack (ADWS/NMF over net.tcp) shares nothing with WCCE's RPC/DCOM enrollment or the HTTP endpoints. Multi-week protocol work to duplicate an existing tool. |

Decision: **subprocess wrapper around Certipy.** This introduces a runtime
dependency (Python + `certipy-ad`), but only when the validation flag is used;
the pure-Go detection core stays dependency-free.

## 4. Transport reality

Validation is *not* constrained to ADWS. Certipy uses whichever protocol each
step needs; adit only hands off credentials and targets.

| ESC | Validation action | Transport | adit can detect over ADWS? |
|---|---|---|---|
| ESC1 | request cert with alternate SAN/UPN/SID | WCCE (RPC/DCOM) or CES/HTTP | yes |
| ESC2 | request cert (Any-Purpose EKU) | WCCE/HTTP | yes |
| ESC3 | request enrollment-agent cert, then on-behalf-of | WCCE/HTTP | yes |
| ESC4 | **modify** template object, exploit, restore | **LDAP** (+ backup/restore) | yes |
| ESC5 | **modify** PKI object ACL, forge, restore | **LDAP** | yes |
| ESC6 | request cert with alternate SAN (relies on CA EDITF flag) | detect via **RPC** `ICertAdmin2::GetConfigEntry`; prove via WCCE | **no** (registry-only) |
| ESC7 | read/add CA officer or flip flags | **RPC** `Get/SetCASecurity` | **no** (registry-only) |
| ESC8 | web-enrollment NTLM relay | **HTTP** + coercion (RPC) | **no** (HTTP endpoint) |
| ESC9/10 | request cert with modified UPN/mapping, then auth | WCCE + LDAP | partial |

Two consequences:

- **LDAP** specifically unlocks the AD-object-writing steps for **ESC4 and
  ESC5**. Certipy's `template` backs up and restores the object, so these become
  offerable behind an explicit "modifies AD" opt-in rather than excluded.
- **ESC6/ESC7 cannot be read over LDAP or ADWS** — the SAN EDITF flag and CA
  officer roles are in the CA host registry, exposed only over RPC. So for
  ESC6/7/8, validation is not merely confirming what adit found; it is the only
  way to know at all. This strengthens the case for the validation layer.

## 5. Safety model (the actual blocker)

Validation creates real, observable artifacts and, for some ESCs, briefly
modifies the directory. The design must be safe-by-default:

1. **Off by default.** A distinct opt-in flag; never part of a normal audit.
2. **Two intrusiveness tiers:**
   - **Tier A — request-based (ESC1/2/3/6/9).** Issues a certificate. Must
     target a **required canary principal** (a dedicated low-value account, or
     the requesting user with an alternate UPN) — never auto-target
     `administrator`. The issued cert is **discarded**; validation never chains
     into `certipy auth` to obtain a privileged session.
   - **Tier B — AD-modifying (ESC4/5).** Writes template/PKI-object config over
     LDAP and relies on restore-on-success. Requires a second, louder opt-in, a
     printed warning, and a saved backup path so a mid-run crash is recoverable.
3. **ESC7 CA-config writes and ESC8 relay** are out of scope for inline
   validation. Report them as "verify manually with Certipy."
4. **Auditability.** Everything validation does is logged locally (command,
   target, canary, artifacts created) so the operator can clean up.
5. **CA-log awareness.** Documentation must state plainly that Tier A issues
   real certificates that appear in CA logs.

## 6. Credentials & network

- adit already holds what Certipy needs: `-u/-p`, or a Kerberos ccache
  (`KRB5CCNAME`) for `-k -no-pass`. Reuse them; no new secrets.
- Certipy talks to the **CA host** over RPC/HTTP and to the DC over LDAP — not
  ADWS. Reachability to the CA is required and is separate from ADWS/9389.
- **Proxy caveat:** adit's in-process SOCKS/HTTP dialer wraps its own TCP
  connections and cannot wrap a subprocess. Through a jump host, Certipy needs
  its own SOCKS path (e.g. `proxychains`, or `KRB5CCNAME` + a SOCKS env). The
  validation layer should surface this rather than silently fail.

## 7. CLI / UX sketch

```
# Detection only (unchanged, read-only, pure Go)
adit -dc dc01 -fqdn dc01.corp.local -d CORP.LOCAL -u user -p pass -audit

# + Tier A validation of request-based ESCs (issues certs to a canary)
adit ... -audit \
    -validate-adcs \
    -validate-canary 'canary$@corp.local' \
    -ca-host ca01.corp.local          # RPC/HTTP target for enrollment

# + Tier B (modifies AD; backup/restore) — separate explicit acceptance
adit ... -audit -validate-adcs -validate-modify -validate-canary '...'
```

Proposed flags:

| Flag | Meaning |
|---|---|
| `-validate-adcs` | Enable Tier A validation of ADCS findings (off by default). |
| `-validate-canary <principal>` | **Required** with `-validate-adcs`; the benign identity used for request-based checks. |
| `-ca-host <host>` | CA host for RPC/HTTP enrollment (defaults derived from CA objects). |
| `-validate-modify` | Also run Tier B (ESC4/5) AD-modifying validation with backup/restore. |
| `-certipy <path>` | Path to the certipy binary (default: `certipy` on PATH). |
| `-validate-timeout <dur>` | Per-attempt timeout. |

Preconditions checked before running: certipy present, canary set, CA reachable;
otherwise findings are marked `not-attempted` with a reason.

## 8. Finding schema change

Additive: each ADCS `Finding` gains an optional `validation` block.

```jsonc
{
  "rule_id": "AD-CS-001",
  "severity": "Critical",
  // ... existing fields ...
  "validation": {
    "status": "confirmed",        // confirmed | refuted | not-attempted | error
    "method": "certipy req (ESC1)",
    "transport": "wcce",          // wcce | http | ldap | rpc
    "detail": "CA issued a certificate with attacker-controlled SAN",
    "artifact": "cert issued to canary$@corp.local (serial 12ab…), discarded",
    "at": "2026-07-27T10:00:00Z"
  }
}
```

- `confirmed` findings can receive a confidence bump and/or re-ranking.
- `refuted` findings are retained but visibly de-emphasised (the template looked
  vulnerable but the CA did not issue) — a valuable false-positive signal.
- The dashboard renders a "validated / refuted / not attempted" badge alongside
  the severity badge.

## 9. Dependency & posture impact

- **Dependency:** Python + `certipy-ad`, required only when `-validate-adcs` is
  used. Detection and reporting stay pure-Go and dependency-free.
- **Posture:** adit is a read-only audit tool. Validation is an *active*
  capability and must be presented as clearly separate: distinct flag, prominent
  warnings, "authorized engagements only — issues real certificates." The
  read-only guarantee for the default path is preserved.
- **Versioning:** Certipy's CLI/JSON can change between major versions; the
  wrapper should pin/verify a supported version range and fail cleanly on drift.

## 10. Effort & risk

- **Tier A (request-based ESC1/2/3/6/9):** moderate — invocation, JSON parsing,
  finding correlation, canary/guardrail logic, docs. A few focused days.
- **Tier B (ESC4/5 modify):** additional care — backup/restore orchestration,
  crash-safety, louder consent.
- **Primary risks:** external dependency drift; CA reachability/proxy through
  jump hosts; and above all safe-by-default behaviour so no one inadvertently
  issues a privileged certificate or leaves AD modified.

## 11. Phased plan

1. **Phase 1:** subprocess wrapper + `-validate-adcs` (Tier A only), canary
   required, certs discarded, results folded into the `validation` block +
   dashboard badge. Also surfaces ESC6/ESC7 discovered via Certipy's RPC path.
2. **Phase 2:** Tier B (ESC4/5) behind `-validate-modify` with backup/restore.
3. **Out of scope (documented as manual):** ESC7 CA-config writes, ESC8 relay.

## 12. Open questions

- Should `refuted` findings be downgraded in severity, or only annotated?
- Canary lifecycle: does adit assume a pre-created canary, or help provision one?
- For ESC3 on-behalf-of, is confirming the enrollment-agent cert enough, or must
  the second (impersonation) request also run?
- How should the CA host be resolved when multiple CAs publish the same template?
