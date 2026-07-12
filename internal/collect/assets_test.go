package collect_test

import (
	"testing"

	"adit/internal/adws"
	"adit/internal/collect"
)

func TestPrinters(t *testing.T) {
	p := &adws.Object{Attributes: map[string][]adws.Value{
		"name":           tv("HP-LaserJet"),
		"serverName":     tv("PRINT01"),
		"printShareName": tv("HP-LaserJet"),
		"portName":       tv("IP_10.0.0.50"),
		"driverName":     tv("HP Universal Printing PCL 6"),
		"driverVersion":  tv("61600"),
		"uNCName":        tv(`\\PRINT01\HP-LaserJet`),
	}}
	q := &mockQuerier{fn: func(_, filter string, _ []string) ([]*adws.Object, error) {
		if filter == "(objectCategory=printQueue)" {
			return []*adws.Object{p}, nil
		}
		return nil, nil
	}}
	tbl, err := collect.New(q, "dc", collect.Config{}).Printers()
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]string{
		"Name": "HP-LaserJet", "Server Name": "PRINT01", "Share Name": "HP-LaserJet",
		"Port Name": "IP_10.0.0.50", "UNC Name": `\\PRINT01\HP-LaserJet`,
	}
	for h, want := range checks {
		if got := cell(t, tbl, 0, h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
}

func TestBitLocker(t *testing.T) {
	// Recovery object named with a datetime; the parent CN is the computer.
	rec := &adws.Object{Attributes: map[string][]adws.Value{
		"msFVE-RecoveryPassword": tv("123456-234567-345678-456789-567890-678901-789012-890123"),
		"msFVE-RecoveryGuid":     bv(t, "6c7d8e6f4a5b28391716151413121110"), // 16-byte GUID
		"distinguishedName":      tv(`CN=2023-01-02T03:04:05-08:00{AB12CD34},CN=WS01,OU=Workstations,DC=corp,DC=local`),
	}}
	q := &mockQuerier{fn: func(_, filter string, _ []string) ([]*adws.Object, error) {
		if filter == "(objectCategory=msFVE-RecoveryInformation)" {
			return []*adws.Object{rec}, nil
		}
		return nil, nil
	}}
	tbl, err := collect.New(q, "dc", collect.Config{}).BitLocker()
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]string{
		"Computer":         "WS01",
		"RecoveryPassword": "123456-234567-345678-456789-567890-678901-789012-890123",
		"RecoveryGuid":     "6f8e7d6c-5b4a-3928-1716-151413121110",
	}
	for h, want := range checks {
		if got := cell(t, tbl, 0, h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
}
