// Package adws implements the ADWS SOAP layer on top of the framed, sealed,
// binary-XML transport: WS-Transfer Get for the RootDSE and the WS-Enumeration
// Enumerate/Pull paging loop that backs every collector. It ports the request
// flow and response parsing of PyADRecon-ADWS (adws.py / adws_wrapper.py).
package adws

import (
	"crypto/rand"
	"fmt"
	"strconv"
)

// Transport is the request/response channel the client speaks over — satisfied
// by *nmf.Conn once connected to the ADWS Enumeration endpoint. One connection
// serves RootDSE, Enumerate and Pull, and is reused across queries.
type Transport interface {
	Send(xml string) error
	Recv() (string, error)
}

// Client issues ADWS queries over a Transport.
type Client struct {
	t        Transport
	fqdn     string
	pageSize int
}

// NewClient returns a Client. pageSize bounds the Pull MaxElements (default 256
// when non-positive).
func NewClient(t Transport, fqdn string, pageSize int) *Client {
	if pageSize <= 0 {
		pageSize = 256
	}
	return &Client{t: t, fqdn: fqdn, pageSize: pageSize}
}

// RootDSE holds the directory-wide contexts returned by a RootDSE query.
type RootDSE struct {
	DefaultNamingContext       string
	RootDomainNamingContext    string
	ConfigurationNamingContext string
	SchemaNamingContext        string
	NamingContexts             []string
	DomainFunctionality        string
	ForestFunctionality        string
}

// RootDSE performs a WS-Transfer Get against the Resource endpoint and returns
// the directory naming contexts and functional levels.
func (c *Client) RootDSE() (*RootDSE, error) {
	env, err := c.roundTrip(fill(rootDSETemplate, "{{uuid}}", newUUID(), "{{fqdn}}", c.fqdn))
	if err != nil {
		return nil, err
	}
	if f := checkFault(env); f != nil {
		return nil, f
	}
	// Each context is <addata:NAME><ad:value>...</ad:value></addata:NAME>.
	val := func(name string) string {
		if el := env.first(name); el != nil {
			if v := el.first("value"); v != nil {
				return v.trimText()
			}
		}
		return ""
	}
	rd := &RootDSE{
		DefaultNamingContext:       val("defaultNamingContext"),
		RootDomainNamingContext:    val("rootDomainNamingContext"),
		ConfigurationNamingContext: val("configurationNamingContext"),
		SchemaNamingContext:        val("schemaNamingContext"),
		DomainFunctionality:        val("domainFunctionality"),
		ForestFunctionality:        val("forestFunctionality"),
	}
	if el := env.first("namingContexts"); el != nil {
		for _, v := range el.findAll("value") {
			rd.NamingContexts = append(rd.NamingContexts, v.trimText())
		}
	}
	return rd, nil
}

// Query runs an LDAP filter under baseDN, selecting the given attributes, and
// returns every matching object. ADWS pages server-side; Query drives the
// Enumerate then Pull-until-EndOfSequence loop.
func (c *Client) Query(baseDN, filter string, attributes []string) ([]*Object, error) {
	ctx, err := c.enumerate(baseDN, filter, attributes)
	if err != nil {
		return nil, err
	}

	var objects []*Object
	for {
		items, done, err := c.pull(ctx)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			objects = append(objects, parseItem(item))
		}
		if done {
			break
		}
	}
	return objects, nil
}

// enumerate issues the Enumerate request and returns the enumeration context.
func (c *Client) enumerate(baseDN, filter string, attributes []string) (string, error) {
	req := fill(enumerateTemplate,
		"{{uuid}}", newUUID(),
		"{{fqdn}}", c.fqdn,
		"{{filter}}", filter,
		"{{baseobj}}", baseDN,
		"{{attributes}}", selectionProperties(attributes),
	)
	env, err := c.roundTrip(req)
	if err != nil {
		return "", err
	}
	if f := checkFault(env); f != nil {
		return "", f
	}
	ctx, ok := enumerationContext(env)
	if !ok {
		return "", fmt.Errorf("adws: no EnumerationContext in Enumerate response")
	}
	return ctx, nil
}

// pull issues one Pull for the context and returns its items and whether the
// enumeration is exhausted. A directory referral is treated as an empty,
// terminal batch, matching the reference (referrals are not chased).
func (c *Client) pull(ctx string) (items []*node, done bool, err error) {
	req := fill(pullTemplate,
		"{{uuid}}", newUUID(),
		"{{fqdn}}", c.fqdn,
		"{{enum_ctx}}", ctx,
		"{{max_elements}}", strconv.Itoa(c.pageSize),
	)
	env, err := c.roundTrip(req)
	if err != nil {
		return nil, false, err
	}
	if f := checkFault(env); f != nil {
		if f.isReferral() {
			return nil, true, nil
		}
		return nil, false, f
	}
	items, done = pullItems(env)
	return items, done, nil
}

// roundTrip sends a SOAP request and parses the response envelope.
func (c *Client) roundTrip(request string) (*node, error) {
	if err := c.t.Send(request); err != nil {
		return nil, err
	}
	resp, err := c.t.Recv()
	if err != nil {
		return nil, err
	}
	env, err := parseDOM(resp)
	if err != nil {
		return nil, fmt.Errorf("adws: parse response: %w", err)
	}
	if env == nil {
		return nil, fmt.Errorf("adws: empty response")
	}
	return env, nil
}

// newUUID returns a random RFC 4122 v4 UUID string.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
