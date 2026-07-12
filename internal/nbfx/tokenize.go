package nbfx

import (
	"fmt"
	"strings"
)

// parseXML tokenizes a SOAP envelope string into an encode record tree. The
// input is well-formed XML that we generate ourselves, so the tokenizer targets
// that shape: elements, attributes, text, comments, entities, self-closing tags
// and an optional XML declaration. Whitespace-only text between elements is
// dropped (matching the reference, whose text handler strips and skips empties).
func parseXML(s string) ([]eNode, error) {
	var root []eNode
	var stack []*eElem
	var text strings.Builder

	// appendNode adds n to the current element (or root).
	appendNode := func(n eNode) {
		if len(stack) == 0 {
			root = append(root, n)
		} else {
			top := stack[len(stack)-1]
			top.kids = append(top.kids, n)
		}
	}

	// flushText emits accumulated character data as a value record, unless it is
	// empty after trimming.
	flushText := func() {
		t := text.String()
		text.Reset()
		if strings.TrimSpace(t) == "" {
			return
		}
		bt, payload := typeValue(unescape(t))
		appendNode(&eText{baseType: bt, payload: payload})
	}

	i := 0
	for i < len(s) {
		c := s[i]
		if c != '<' {
			// Character data up to the next tag.
			j := strings.IndexByte(s[i:], '<')
			if j < 0 {
				text.WriteString(s[i:])
				break
			}
			text.WriteString(s[i : i+j])
			i += j
			continue
		}

		switch {
		case strings.HasPrefix(s[i:], "<!--"):
			flushText()
			end := strings.Index(s[i:], "-->")
			if end < 0 {
				return nil, fmt.Errorf("unterminated comment")
			}
			appendNode(&eComment{text: s[i+4 : i+end]})
			i += end + 3

		case strings.HasPrefix(s[i:], "<?"):
			// XML declaration / processing instruction: skip.
			end := strings.Index(s[i:], "?>")
			if end < 0 {
				return nil, fmt.Errorf("unterminated processing instruction")
			}
			i += end + 2

		case strings.HasPrefix(s[i:], "</"):
			flushText()
			end := strings.IndexByte(s[i:], '>')
			if end < 0 {
				return nil, fmt.Errorf("unterminated end tag")
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			i += end + 1

		default: // start tag or self-closing
			flushText()
			end := findTagEnd(s, i)
			if end < 0 {
				return nil, fmt.Errorf("unterminated start tag at %d", i)
			}
			inner := s[i+1 : end] // between < and >
			selfClose := strings.HasSuffix(inner, "/")
			inner = strings.TrimSuffix(inner, "/")

			tag, attrs, err := parseTag(inner)
			if err != nil {
				return nil, err
			}
			el := &eElem{head: makeElementHead(tag)}
			for _, a := range attrs {
				el.attrs = append(el.attrs, makeAttribute(a.name, a.value))
			}
			appendNode(el)
			if !selfClose {
				stack = append(stack, el)
			}
			i = end + 1
		}
	}
	return root, nil
}

// findTagEnd returns the index of the '>' that closes the tag beginning at i,
// skipping '>' characters inside quoted attribute values.
func findTagEnd(s string, i int) int {
	var quote byte
	for j := i + 1; j < len(s); j++ {
		ch := s[j]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == '>':
			return j
		}
	}
	return -1
}

type xmlAttr struct{ name, value string }

// parseTag splits a start-tag body into the tag name and its attributes.
func parseTag(inner string) (tag string, attrs []xmlAttr, err error) {
	inner = strings.TrimSpace(inner)
	// Tag name runs up to the first whitespace.
	nameEnd := strings.IndexAny(inner, " \t\r\n")
	if nameEnd < 0 {
		return inner, nil, nil
	}
	tag = inner[:nameEnd]
	rest := inner[nameEnd:]

	for {
		rest = strings.TrimLeft(rest, " \t\r\n")
		if rest == "" {
			break
		}
		eq := strings.IndexByte(rest, '=')
		if eq < 0 {
			// Valueless attribute: rare in our SOAP; skip to be lenient.
			break
		}
		name := strings.TrimSpace(rest[:eq])
		rest = strings.TrimLeft(rest[eq+1:], " \t\r\n")
		if rest == "" {
			return "", nil, fmt.Errorf("attribute %q missing value", name)
		}
		q := rest[0]
		if q != '"' && q != '\'' {
			return "", nil, fmt.Errorf("attribute %q value not quoted", name)
		}
		close := strings.IndexByte(rest[1:], q)
		if close < 0 {
			return "", nil, fmt.Errorf("attribute %q value not terminated", name)
		}
		value := rest[1 : 1+close]
		attrs = append(attrs, xmlAttr{name: name, value: unescape(value)})
		rest = rest[1+close+1:]
	}
	return tag, attrs, nil
}

// unescape resolves the XML entities that appear in our documents.
func unescape(s string) string {
	if !strings.ContainsRune(s, '&') {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '&' {
			b.WriteByte(s[i])
			i++
			continue
		}
		semi := strings.IndexByte(s[i:], ';')
		if semi < 0 {
			b.WriteString(s[i:])
			break
		}
		ent := s[i+1 : i+semi]
		switch ent {
		case "lt":
			b.WriteByte('<')
		case "gt":
			b.WriteByte('>')
		case "amp":
			b.WriteByte('&')
		case "quot":
			b.WriteByte('"')
		case "apos":
			b.WriteByte('\'')
		default:
			if r, ok := numericEntity(ent); ok {
				b.WriteRune(r)
			} else {
				b.WriteString(s[i : i+semi+1]) // leave unknown entity as-is
			}
		}
		i += semi + 1
	}
	return b.String()
}

func numericEntity(ent string) (rune, bool) {
	if len(ent) < 2 || ent[0] != '#' {
		return 0, false
	}
	var v int
	var err error
	if ent[1] == 'x' || ent[1] == 'X' {
		_, err = fmt.Sscanf(ent[2:], "%x", &v)
	} else {
		_, err = fmt.Sscanf(ent[1:], "%d", &v)
	}
	if err != nil {
		return 0, false
	}
	return rune(v), true
}
