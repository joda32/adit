package nns

import (
	"strings"
	"testing"
)

func TestNewKerberosDefaults(t *testing.T) {
	a := NewKerberos(KerberosConfig{Realm: "corp.local", FQDN: "dc01.corp.local"})
	if a.cfg.Realm != "CORP.LOCAL" {
		t.Errorf("realm = %q, want upper-cased", a.cfg.Realm)
	}
	if a.cfg.SPN != "HTTP/dc01.corp.local" {
		t.Errorf("default SPN = %q", a.cfg.SPN)
	}
}

func TestNewKerberosExplicitSPN(t *testing.T) {
	a := NewKerberos(KerberosConfig{Realm: "corp.local", FQDN: "dc01.corp.local", SPN: "WSMAN/dc01.corp.local"})
	if a.cfg.SPN != "WSMAN/dc01.corp.local" {
		t.Errorf("SPN = %q, want explicit", a.cfg.SPN)
	}
}

func TestKrb5ConfigSynthesised(t *testing.T) {
	// With no config file and KRB5_CONFIG unset, a config is synthesised from
	// the realm and KDC. (Point KRB5_CONFIG at a missing file to bypass any
	// real /etc/krb5.conf on the test host.)
	t.Setenv("KRB5_CONFIG", "")
	a := NewKerberos(KerberosConfig{Realm: "corp.local", KDC: "10.0.0.1", FQDN: "dc01.corp.local"})
	a.cfg.ConfigPath = "" // force synthesis path

	// Only exercise synthesis when there's no /etc/krb5.conf to load.
	cfg, err := a.synthConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LibDefaults.DefaultRealm != "CORP.LOCAL" {
		t.Errorf("default_realm = %q", cfg.LibDefaults.DefaultRealm)
	}
	found := false
	for _, r := range cfg.Realms {
		if r.Realm == "CORP.LOCAL" {
			for _, k := range r.KDC {
				if strings.HasPrefix(k, "10.0.0.1:") {
					found = true
				}
			}
		}
	}
	if !found {
		t.Errorf("KDC not in synthesised config: %+v", cfg.Realms)
	}
}

func TestNewClientNoCredentials(t *testing.T) {
	t.Setenv("KRB5CCNAME", "")
	a := NewKerberos(KerberosConfig{Realm: "corp.local", KDC: "10.0.0.1"})
	if _, err := a.newClient(); err == nil || !strings.Contains(err.Error(), "no credentials") {
		t.Errorf("expected no-credentials error, got %v", err)
	}
}
