package adws

import "strings"

// SOAP templates for the ADWS dialects, ported from PyADRecon-ADWS
// soap_templates.py. Placeholders use {{token}} form and are filled by
// strings.Replacer so the XML (which contains no other braces) stays literal.

const rootDSETemplate = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
    xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<s:Header>
    <a:Action s:mustUnderstand="1" xmlns="http://www.w3.org/2005/08/addressing">http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action>
    <ad:instance>ldap:389</ad:instance>
    <ad:objectReferenceProperty>11111111-1111-1111-1111-111111111111</ad:objectReferenceProperty>
    <a:MessageID>urn:uuid:{{uuid}}</a:MessageID>
    <a:ReplyTo>
        <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
    <a:To s:mustUnderstand="1">net.tcp://{{fqdn}}:9389/ActiveDirectoryWebServices/Windows/Resource</a:To>
</s:Header>
    <s:Body></s:Body>
</s:Envelope>`

const enumerateTemplate = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
    xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</a:Action>
        <ad:instance>ldap:389</ad:instance>
        <a:MessageID>urn:uuid:{{uuid}}</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">net.tcp://{{fqdn}}:9389/ActiveDirectoryWebServices/Windows/Enumeration</a:To>
    </s:Header>
    <s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
        xmlns:adlq="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery">
        <wsen:Enumerate>
            <wsen:Filter Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery">
                <adlq:LdapQuery>
                    <adlq:Filter>{{filter}}</adlq:Filter>
                    <adlq:BaseObject>{{baseobj}}</adlq:BaseObject>
                    <adlq:Scope>Subtree</adlq:Scope>
                </adlq:LdapQuery>
            </wsen:Filter>
            <ad:Selection Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1">
                {{attributes}}
            </ad:Selection>
        </wsen:Enumerate>
    </s:Body>
</s:Envelope>`

const pullTemplate = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
    xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull</a:Action>
        <ad:instance>ldap:389</ad:instance>
        <a:MessageID>urn:uuid:{{uuid}}</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">net.tcp://{{fqdn}}:9389/ActiveDirectoryWebServices/Windows/Enumeration</a:To>
    </s:Header>
    <s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
        <wsen:Pull>
            <wsen:EnumerationContext>{{enum_ctx}}</wsen:EnumerationContext>
            <wsen:MaxElements>{{max_elements}}</wsen:MaxElements>
                <ad:controls>
                    <ad:control criticality="true" type="1.2.840.113556.1.4.801">
                       <ad:controlValue xsi:type="xsd:base64Binary">MIQAAAADAgEH</ad:controlValue>
                </ad:control>
                </ad:controls>
        </wsen:Pull>
    </s:Body>
</s:Envelope>`

// selectionProperty renders the per-attribute selection block for Enumerate.
func selectionProperties(attributes []string) string {
	var b strings.Builder
	for _, a := range attributes {
		b.WriteString("<ad:SelectionProperty>addata:")
		b.WriteString(a)
		b.WriteString("</ad:SelectionProperty>\n")
	}
	return b.String()
}

func fill(tmpl string, kv ...string) string {
	return strings.NewReplacer(kv...).Replace(tmpl)
}

// escapeXML escapes a value that is interpolated into SOAP element text (the
// LDAP filter, base DN and enumeration context). Without it a value containing
// '&', '<' or '>' — legal in a DN or a dynamic -query — produces malformed XML
// or collapses entities. The DC's (and our own) XML parser unescapes it back.
func escapeXML(s string) string {
	return strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	).Replace(s)
}
