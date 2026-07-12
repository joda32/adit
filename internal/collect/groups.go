package collect

import "adit/internal/addecode"

var groupAttributes = []string{
	"sAMAccountName", "name", "distinguishedName", "canonicalName",
	"description", "groupType", "adminCount", "managedBy",
	"objectSid", "sIDHistory", "whenCreated", "whenChanged",
}

// Groups collects group objects (objectCategory=group).
func (c *Collector) Groups() (*Table, error) {
	objects, err := c.q.Query(c.baseDN, "(objectCategory=group)", groupAttributes)
	if err != nil {
		return nil, err
	}

	t := &Table{
		Name: "Groups",
		Headers: []string{
			"Name", "AdminCount", "GroupCategory", "GroupScope", "ManagedBy",
			"SID", "SIDHistory", "Description", "whenCreated", "whenChanged",
			"DistinguishedName", "CanonicalName",
		},
	}

	for _, o := range objects {
		category, scope := addecode.GroupCategoryScope(intText(o, "groupType"))

		var r row
		r.str(text(o, "name"))
		r.str(text(o, "adminCount"))
		r.str(category)
		r.str(scope)
		r.str(cnOf(text(o, "managedBy")))
		r.str(sidText(o, "objectSid"))
		r.str(sidListText(o, "sIDHistory"))
		r.str(text(o, "description"))
		r.str(addecode.FormatDateTime(addecode.GeneralizedTimeToTime(text(o, "whenCreated"))))
		r.str(addecode.FormatDateTime(addecode.GeneralizedTimeToTime(text(o, "whenChanged"))))
		r.str(text(o, "distinguishedName"))
		r.str(text(o, "canonicalName"))

		t.Rows = append(t.Rows, r.cells)
	}
	return t, nil
}
