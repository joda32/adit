package adws

import (
	"encoding/xml"
	"io"
	"strings"
)

// node is a minimal DOM element. Navigation is by local name, which is robust
// regardless of how the server binds namespace prefixes.
type node struct {
	Local    string
	Attrs    []xml.Attr
	Text     string // concatenated character data directly under this element
	Children []*node
}

// parseDOM builds a node tree from an XML string.
func parseDOM(s string) (*node, error) {
	dec := xml.NewDecoder(strings.NewReader(s))
	var root *node
	var stack []*node
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &node{Local: t.Name.Local, Attrs: t.Attr}
			if len(stack) > 0 {
				top := stack[len(stack)-1]
				top.Children = append(top.Children, n)
			} else {
				root = n
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) > 0 {
				top := stack[len(stack)-1]
				top.Text += string(t)
			}
		}
	}
	return root, nil
}

// first returns the first descendant (self excluded) with the given local name.
func (n *node) first(local string) *node {
	for _, c := range n.Children {
		if c.Local == local {
			return c
		}
		if found := c.first(local); found != nil {
			return found
		}
	}
	return nil
}

// findAll returns all descendants (self excluded) with the given local name.
func (n *node) findAll(local string) []*node {
	var out []*node
	for _, c := range n.Children {
		if c.Local == local {
			out = append(out, c)
		}
		out = append(out, c.findAll(local)...)
	}
	return out
}

// attr returns the value of the attribute with the given local name.
func (n *node) attr(local string) (string, bool) {
	for _, a := range n.Attrs {
		if a.Name.Local == local {
			return a.Value, true
		}
	}
	return "", false
}

// trimText returns the element's text with surrounding whitespace removed.
func (n *node) trimText() string { return strings.TrimSpace(n.Text) }
