package audit

import (
	"regexp"
	"strings"

	"adit/internal/adws"
)

// Rules for credential exposure in readable directory attributes (G1 / PingCastle
// A-UnixPwd) and for broadened anonymous/low-privilege read access via the
// Pre-Windows 2000 Compatible Access group (PingCastle A-PreWin2000*).

func init() {
	addChecks(
		check{
			ID: "AD-USR-020", Title: "Recoverable password stored in a directory attribute",
			Category: "User", Severity: High,
			Description: "An account has a value in userPassword or unixUserPassword, which can hold a cleartext or trivially recoverable password that any authenticated user can read.",
			Risk:        "The password can be read straight from the directory and replayed to authenticate as the account.",
			Remediation: "Clear the userPassword / unixUserPassword attribute and reset the account password through supported means.",
			Fn:          (*Snapshot).ruleRecoverablePasswordAttr,
		},
		check{
			ID: "AD-USR-021", Title: "Possible password in description / info / comment",
			Category: "User", Severity: High,
			Description: "A description, info, or comment attribute appears to contain a password. These attributes are readable by any authenticated user.",
			Risk:        "A credential left in a readable text attribute can be harvested during low-privilege reconnaissance.",
			Remediation: "Remove the credential from the attribute and reset the affected password.",
			Fn:          (*Snapshot).rulePasswordInText,
		},
		check{
			ID: "AD-DOM-012", Title: "Broadened membership of Pre-Windows 2000 Compatible Access",
			Category: "Domain", Severity: High,
			Description: "The built-in Pre-Windows 2000 Compatible Access group includes Everyone, Anonymous Logon, or Authenticated Users, widening read access to directory objects and attributes.",
			Risk:        "Grants anonymous or broad low-privilege read of AD, aiding reconnaissance and some relay/escalation paths.",
			Remediation: "Remove Everyone and Anonymous Logon (and, for advanced hardening, Authenticated Users) from Pre-Windows 2000 Compatible Access.",
			Fn:          (*Snapshot).rulePreWin2000Compat,
		},
	)
}

// secretAttrs are attributes whose mere presence means a recoverable password.
var secretAttrs = []string{"userPassword", "unixUserPassword"}

// ruleRecoverablePasswordAttr flags accounts whose userPassword / unixUserPassword
// attribute is set. The value is never included in evidence (it IS the secret).
func (s *Snapshot) ruleRecoverablePasswordAttr() (out []Finding) {
	for _, u := range s.Users {
		for _, attr := range secretAttrs {
			if attrSet(u, attr) {
				out = append(out, finding(affectedOf(u),
					map[string]string{"attribute": attr, "note": "attribute is set (recoverable password)"}))
				break
			}
		}
	}
	return out
}

// textSecretAttrs are free-text attributes admins sometimes misuse to store a password.
var textSecretAttrs = []string{"description", "info", "comment"}

// rulePasswordInText flags accounts whose description/info/comment looks like it
// holds a password. Heuristic, so findings carry Medium confidence and a redacted
// preview rather than the raw value.
func (s *Snapshot) rulePasswordInText() (out []Finding) {
	scan := func(set []*adws.Object) {
		for _, o := range set {
			for _, attr := range textSecretAttrs {
				for _, v := range textVals(o, attr) {
					if looksLikePassword(v) {
						out = append(out, Finding{
							Confidence: "Medium",
							Affected:   []Affected{affectedOf(o)},
							Evidence:   map[string]string{"attribute": attr, "preview": redactPreview(v)},
						})
						break // one finding per attribute is enough
					}
				}
			}
		}
	}
	scan(s.Users)
	scan(s.Computers)
	return out
}

// preWin2000Compat is the built-in Pre-Windows 2000 Compatible Access group.
const preWin2000CompatSID = "S-1-5-32-554"

// broadReadSIDs are well-known identities that broaden directory read if present
// in Pre-Windows 2000 Compatible Access, with the severity each warrants.
var broadReadSIDs = map[string]struct {
	name string
	sev  Severity
}{
	"S-1-1-0":  {"Everyone", High},
	"S-1-5-7":  {"Anonymous Logon", High},
	"S-1-5-11": {"Authenticated Users", Medium}, // advanced hardening
}

// rulePreWin2000Compat flags broad/anonymous identities in Pre-Windows 2000
// Compatible Access.
func (s *Snapshot) rulePreWin2000Compat() (out []Finding) {
	var grp *adws.Object
	for _, g := range s.Groups {
		if objSID(g) == preWin2000CompatSID {
			grp = g
			break
		}
	}
	if grp == nil {
		return nil
	}
	for _, m := range textVals(grp, "member") {
		sid := s.memberSID(m)
		if d, ok := broadReadSIDs[sid]; ok {
			out = append(out, Finding{
				Severity: d.sev,
				Affected: []Affected{{DistinguishedName: txt(grp, "distinguishedName"), ObjectSID: sid}},
				Evidence: map[string]string{
					"group":  "Pre-Windows 2000 Compatible Access",
					"member": d.name,
					"sid":    sid,
				},
			})
		}
	}
	return out
}

// --- helpers ---

// attrSet reports whether an attribute has at least one non-empty value (text or
// binary) — userPassword is often returned as an octet string.
func attrSet(o *adws.Object, attr string) bool {
	if o == nil {
		return false
	}
	for _, v := range o.Attributes[attr] {
		if v.Text != "" || len(v.Binary) > 0 {
			return true
		}
	}
	return false
}

// memberSID resolves a group member DN to a SID. Well-known identities appear as
// foreignSecurityPrincipals (CN=<SID>,CN=ForeignSecurityPrincipals,…); otherwise
// resolve through the snapshot's DN index.
func (s *Snapshot) memberSID(dn string) string {
	if cn := leadingCN(dn); strings.HasPrefix(cn, "S-1-") {
		return cn
	}
	if o := s.dnToObj[strings.ToLower(dn)]; o != nil {
		return objSID(o)
	}
	return ""
}

// leadingCN returns the value of the first CN= RDN, unescaping backslash escapes.
func leadingCN(dn string) string {
	if len(dn) < 3 || !strings.EqualFold(dn[:3], "CN=") {
		return ""
	}
	var b strings.Builder
	for i := 3; i < len(dn); i++ {
		if dn[i] == '\\' && i+1 < len(dn) {
			b.WriteByte(dn[i+1])
			i++
			continue
		}
		if dn[i] == ',' {
			break
		}
		b.WriteByte(dn[i])
	}
	return b.String()
}

var (
	// Explicit "pw/pwd/pass/password/kennwort <sep> <value>" — strong signal.
	pwdStrongRe = regexp.MustCompile(`(?i)\b(pw|pwd|pass|passwor[dt]|kennwort)\b\s*[:=]\s*\S`)
	// A password keyword anywhere — weak; must be paired with a credential token.
	pwdWeakRe = regexp.MustCompile(`(?i)(passwor[dt]|kennwort|contrase|mot de passe)`)
)

// looksLikePassword heuristically decides whether free text holds a password.
func looksLikePassword(s string) bool {
	if pwdStrongRe.MatchString(s) {
		return true
	}
	return pwdWeakRe.MatchString(s) && hasCredentialToken(s)
}

// hasCredentialToken reports whether s contains a token that looks like an actual
// secret (>=5 chars with a digit or symbol), cutting false positives such as
// "password must be changed".
func hasCredentialToken(s string) bool {
	for _, tok := range strings.Fields(s) {
		if len(tok) >= 5 && strings.ContainsAny(tok, "0123456789!@#$%^&*") {
			return true
		}
	}
	return false
}

var pwdKeywords = map[string]bool{
	"password": true, "passwort": true, "kennwort": true, "contraseña": true, "contrasena": true,
}

// redactPreview returns a short, masked preview safe to put in a shared report:
// secret-looking tokens are collapsed to their first character, while ordinary
// words (and the password keyword) stay readable for triage.
func redactPreview(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return nonSpaceRe.ReplaceAllStringFunc(s, func(w string) string {
		key := strings.ToLower(strings.Trim(w, ":=.,;"))
		if pwdKeywords[key] {
			return w
		}
		if len(w) > 1 && (strings.ContainsAny(w, "0123456789!@#$%^&*") || len(w) >= 7) {
			return w[:1] + "***"
		}
		return w
	})
}

var nonSpaceRe = regexp.MustCompile(`\S+`)
