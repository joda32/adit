package collect

import (
	"strings"

	"adit/internal/addecode"
	"adit/internal/adws"
)

// Printers collects published print-queue objects.
func (c *Collector) Printers() (*Table, error) {
	objects, err := c.q.Query(c.baseDN, "(objectCategory=printQueue)",
		[]string{"printerName", "name", "serverName", "portName", "driverName",
			"driverVersion", "printShareName", "uNCName", "url", "whenCreated", "whenChanged"})
	if err != nil {
		return nil, err
	}
	t := &Table{Name: "Printers", Headers: []string{
		"Name", "Server Name", "Share Name", "Port Name", "Driver Name", "Driver Version",
		"UNC Name", "URL", "whenCreated", "whenChanged",
	}}
	for _, o := range objects {
		var r row
		r.str(text(o, "name"))
		r.str(text(o, "serverName"))
		r.str(text(o, "printShareName"))
		r.str(text(o, "portName"))
		r.str(text(o, "driverName"))
		r.str(text(o, "driverVersion"))
		r.str(text(o, "uNCName"))
		r.str(text(o, "url"))
		r.str(whenStr(o, "whenCreated"))
		r.str(whenStr(o, "whenChanged"))
		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

// BitLocker collects BitLocker recovery information (msFVE-RecoveryInformation).
// Recovery passwords are only returned to sufficiently privileged callers.
func (c *Collector) BitLocker() (*Table, error) {
	objects, err := c.q.Query(c.baseDN, "(objectCategory=msFVE-RecoveryInformation)",
		[]string{"name", "msFVE-RecoveryPassword", "msFVE-RecoveryGuid", "whenCreated", "distinguishedName"})
	if err != nil {
		return nil, err
	}
	t := &Table{Name: "Bitlocker", Headers: []string{
		"Computer", "RecoveryPassword", "RecoveryGuid", "whenCreated", "DistinguishedName",
	}}
	for _, o := range objects {
		dn := text(o, "distinguishedName")
		var r row
		r.str(bitlockerComputer(dn))
		r.str(text(o, "msFVE-RecoveryPassword"))
		r.str(guidText(o, "msFVE-RecoveryGuid"))
		r.str(whenStr(o, "whenCreated"))
		r.str(dn)
		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}

// bitlockerComputer returns the parent computer CN of a recovery-information DN.
// The recovery object is the first RDN; the computer is the next CN component.
// (The reference used a heuristic that mis-fires on datetime-named recovery
// objects; taking the parent CN is correct regardless of naming.)
func bitlockerComputer(dn string) string {
	parts := strings.Split(dn, ",")
	if len(parts) < 2 {
		return ""
	}
	for _, p := range parts[1:] {
		if strings.HasPrefix(p, "CN=") {
			return p[3:]
		}
	}
	return ""
}

// guidText renders a 16-byte binary GUID attribute canonically, else its text.
func guidText(o *adws.Object, attr string) string {
	if v := o.Attributes[attr]; len(v) > 0 && v[0].IsBinary && len(v[0].Binary) == 16 {
		return addecode.GUIDToString(v[0].Binary)
	}
	return text(o, attr)
}
