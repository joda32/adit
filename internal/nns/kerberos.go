package nns

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"

	"adit/internal/krb5"
)

// KerberosConfig configures Kerberos authentication. Credentials are taken from
// (in order) an explicit ccache / KRB5CCNAME, a keytab, or a password.
type KerberosConfig struct {
	Realm      string // AD domain (upper-cased)
	Username   string
	Password   string
	KDC        string // DC host[:port], used to synthesise a krb5.conf if none exists
	FQDN       string // DC FQDN, used for the default SPN
	SPN        string // service principal; defaults to HTTP/<FQDN>
	CCachePath string
	KeytabPath string
	ConfigPath string // krb5.conf path; defaults to KRB5_CONFIG or /etc/krb5.conf
}

// KerberosAuth performs Kerberos over the MS-NNS handshake and satisfies
// nmf.Authenticator.
//
// NOTE: this path is not yet validated against a live KDC. The RFC 4121 sealed
// Wrap codec (internal/krb5) is round-trip tested, but the end-to-end flow —
// SPNEGO AP-REQ, the acceptor-subkey selection below, and the exact handshake
// framing — needs a real DC to confirm.
type KerberosAuth struct{ cfg KerberosConfig }

// NewKerberos builds a Kerberos authenticator.
func NewKerberos(cfg KerberosConfig) *KerberosAuth {
	cfg.Realm = strings.ToUpper(cfg.Realm)
	if cfg.SPN == "" && cfg.FQDN != "" {
		cfg.SPN = "HTTP/" + cfg.FQDN
	}
	return &KerberosAuth{cfg: cfg}
}

// Authenticate runs the Kerberos handshake and returns the sealed transport.
func (a *KerberosAuth) Authenticate(rw io.ReadWriter) (io.ReadWriter, error) {
	cl, err := a.newClient()
	if err != nil {
		return nil, err
	}
	defer cl.Destroy()

	tkt, ticketKey, err := cl.GetServiceTicket(a.cfg.SPN)
	if err != nil {
		return nil, fmt.Errorf("kerberos: service ticket for %q: %w", a.cfg.SPN, err)
	}

	initTok, err := spnego.NewNegTokenInitKRB5(cl, tkt, ticketKey)
	if err != nil {
		return nil, fmt.Errorf("kerberos: build SPNEGO token: %w", err)
	}
	tokenBytes, err := initTok.Marshal()
	if err != nil {
		return nil, fmt.Errorf("kerberos: marshal SPNEGO token: %w", err)
	}

	// One-shot mutual-auth exchange: send AP-REQ, read the AP-REP response.
	if err := writeHandshake(rw, msgInProgress, tokenBytes); err != nil {
		return nil, fmt.Errorf("kerberos: send AP-REQ: %w", err)
	}
	id, resp, err := readHandshake(rw)
	if err != nil {
		return nil, fmt.Errorf("kerberos: read response: %w", err)
	}
	if id == msgError {
		return nil, fmt.Errorf("kerberos: authentication failed: %s", errPayload(resp))
	}

	// Per-message key: the acceptor subkey from the AP-REP if present, else the
	// ticket session key.
	sealKey, acceptorSubkey := acceptorSubkeyOrTicket(resp, ticketKey)
	session, err := krb5.NewSession(sealKey, true, acceptorSubkey)
	if err != nil {
		return nil, err
	}
	return &sealedConn{rw: rw, sealer: session}, nil
}

// newClient loads credentials (ccache, keytab, or password) into a gokrb5 client.
func (a *KerberosAuth) newClient() (*client.Client, error) {
	cfg, err := a.krb5Config()
	if err != nil {
		return nil, err
	}

	ccache := a.cfg.CCachePath
	if ccache == "" {
		ccache = strings.TrimPrefix(os.Getenv("KRB5CCNAME"), "FILE:")
	}
	if ccache != "" {
		cc, err := credentials.LoadCCache(ccache)
		if err != nil {
			return nil, fmt.Errorf("kerberos: load ccache %q: %w", ccache, err)
		}
		cl, err := client.NewFromCCache(cc, cfg, client.DisablePAFXFAST(true))
		if err != nil {
			return nil, fmt.Errorf("kerberos: client from ccache: %w", err)
		}
		return cl, nil
	}

	if a.cfg.KeytabPath != "" {
		kt, err := keytab.Load(a.cfg.KeytabPath)
		if err != nil {
			return nil, fmt.Errorf("kerberos: load keytab %q: %w", a.cfg.KeytabPath, err)
		}
		cl := client.NewWithKeytab(a.cfg.Username, a.cfg.Realm, kt, cfg, client.DisablePAFXFAST(true))
		if err := cl.Login(); err != nil {
			return nil, fmt.Errorf("kerberos: keytab login: %w", err)
		}
		return cl, nil
	}

	if a.cfg.Password != "" {
		cl := client.NewWithPassword(a.cfg.Username, a.cfg.Realm, a.cfg.Password, cfg, client.DisablePAFXFAST(true))
		if err := cl.Login(); err != nil {
			return nil, fmt.Errorf("kerberos: password login: %w", err)
		}
		return cl, nil
	}

	return nil, fmt.Errorf("kerberos: no credentials (need ccache, keytab, or password)")
}

// krb5Config loads a krb5.conf, or synthesises a minimal one from the realm/KDC.
func (a *KerberosAuth) krb5Config() (*config.Config, error) {
	path := a.cfg.ConfigPath
	if path == "" {
		path = os.Getenv("KRB5_CONFIG")
	}
	if path == "" {
		if _, err := os.Stat("/etc/krb5.conf"); err == nil {
			path = "/etc/krb5.conf"
		}
	}
	if path != "" {
		return config.Load(path)
	}
	return a.synthConfig()
}

// synthConfig builds a minimal krb5.conf from the realm and KDC.
func (a *KerberosAuth) synthConfig() (*config.Config, error) {
	if a.cfg.Realm == "" || a.cfg.KDC == "" {
		return nil, fmt.Errorf("kerberos: no krb5.conf found and cannot synthesise one (need realm + KDC)")
	}
	kdc := a.cfg.KDC
	if !strings.Contains(kdc, ":") {
		kdc += ":88"
	}
	return config.NewFromString(fmt.Sprintf(`[libdefaults]
  default_realm = %s
  dns_lookup_kdc = false
  dns_lookup_realm = false
[realms]
  %s = {
    kdc = %s
  }
`, a.cfg.Realm, a.cfg.Realm, kdc))
}

// acceptorSubkeyOrTicket extracts the acceptor subkey from the AP-REP in the
// server's SPNEGO response, falling back to the ticket session key.
func acceptorSubkeyOrTicket(resp []byte, ticketKey types.EncryptionKey) (types.EncryptionKey, bool) {
	var nt spnego.NegTokenResp
	if err := nt.Unmarshal(resp); err != nil || len(nt.ResponseToken) == 0 {
		return ticketKey, false
	}
	var kt spnego.KRB5Token
	if err := kt.Unmarshal(nt.ResponseToken); err != nil || !kt.IsAPRep() {
		return ticketKey, false
	}
	dec, err := crypto.DecryptEncPart(kt.APRep.EncPart, ticketKey, keyusage.AP_REP_ENCPART)
	if err != nil {
		return ticketKey, false
	}
	var enc messages.EncAPRepPart
	if err := enc.Unmarshal(dec); err != nil {
		return ticketKey, false
	}
	if enc.Subkey.KeyType != 0 && len(enc.Subkey.KeyValue) > 0 {
		return enc.Subkey, true
	}
	return ticketKey, false
}
