package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
)

func InspectJSON(b []byte, maxDepth int) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	type frame struct {
		object       bool
		expectingKey bool
		keys         map[string]bool
	}
	stack := []frame{}
	for {
		t, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
		if delimiter, ok := t.(json.Delim); ok {
			switch delimiter {
			case '{', '[':
				if len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].expectingKey {
					return fmt.Errorf("invalid JSON object key")
				}
				stack = append(stack, frame{object: delimiter == '{', expectingKey: delimiter == '{', keys: map[string]bool{}})
				if len(stack) > maxDepth {
					return fmt.Errorf("JSON exceeds maximum depth %d", maxDepth)
				}
			case '}', ']':
				if len(stack) == 0 {
					return fmt.Errorf("invalid JSON structure")
				}
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].object {
					stack[len(stack)-1].expectingKey = true
				}
			}
		} else if len(stack) > 0 && stack[len(stack)-1].object {
			top := &stack[len(stack)-1]
			if top.expectingKey {
				key, ok := t.(string)
				if !ok {
					return fmt.Errorf("invalid JSON object key")
				}
				if top.keys[key] {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				top.keys[key] = true
				top.expectingKey = false
			} else {
				top.expectingKey = true
			}
		}
	}
	// Token accepts concatenated roots, so enforce a single JSON value too.
	var v any
	d = json.NewDecoder(bytes.NewReader(b))
	if err := d.Decode(&v); err != nil {
		return err
	}
	if err := d.Decode(&v); err != io.EOF {
		return fmt.Errorf("expected a single JSON document")
	}
	return nil
}

func JSONValue(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	err = json.Unmarshal(b, &out)
	return out, err
}

func Digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Canonical JSON uses recursively sorted keys, UTF-8 strings and no HTML
// escaping, matching the portable policy_hash contract.
func CanonicalJSON(v any) ([]byte, error) {
	v, err := JSONValue(v)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	var write func(any) error
	write = func(x any) error {
		switch t := x.(type) {
		case string:
			b.WriteByte('"')
			for _, r := range t {
				switch r {
				case '"', '\\':
					b.WriteByte('\\')
					b.WriteRune(r)
				case '\b':
					b.WriteString(`\b`)
				case '\f':
					b.WriteString(`\f`)
				case '\n':
					b.WriteString(`\n`)
				case '\r':
					b.WriteString(`\r`)
				case '\t':
					b.WriteString(`\t`)
				default:
					if r < 0x20 {
						fmt.Fprintf(&b, `\u%04x`, r)
					} else {
						b.WriteRune(r)
					}
				}
			}
			b.WriteByte('"')
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			b.WriteByte('{')
			for i, k := range keys {
				if i > 0 {
					b.WriteByte(',')
				}
				if err := write(k); err != nil {
					return err
				}
				b.WriteByte(':')
				if err := write(t[k]); err != nil {
					return err
				}
			}
			b.WriteByte('}')
		case []any:
			b.WriteByte('[')
			for i, e := range t {
				if i > 0 {
					b.WriteByte(',')
				}
				if err := write(e); err != nil {
					return err
				}
			}
			b.WriteByte(']')
		case float64:
			b.WriteString(strconv.FormatFloat(t, 'f', -1, 64))
		default:
			var s bytes.Buffer
			e := json.NewEncoder(&s)
			e.SetEscapeHTML(false)
			if err := e.Encode(t); err != nil {
				return err
			}
			b.Write(bytes.TrimSuffix(s.Bytes(), []byte("\n")))
		}
		return nil
	}
	err = write(v)
	return b.Bytes(), err
}
