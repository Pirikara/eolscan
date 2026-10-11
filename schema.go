package main

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
)

//go:embed schemas/*.json examples/eol-policy.example.yaml
var contracts embed.FS

var schemaOnce sync.Once
var schemaErr error
var compiledSchemas map[string]*jsonschema.Schema

func schemaValidate(name string, value any) error {
	schemaOnce.Do(func() {
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		c.AssertFormat()
		compiledSchemas = make(map[string]*jsonschema.Schema)
		files, err := contracts.ReadDir("schemas")
		if err != nil {
			schemaErr = err
			return
		}
		for _, f := range files {
			b, _ := contracts.ReadFile("schemas/" + f.Name())
			var doc map[string]any
			if err := json.Unmarshal(b, &doc); err != nil {
				schemaErr = err
				return
			}
			if err := c.AddResource(doc["$id"].(string), doc); err != nil {
				schemaErr = err
				return
			}
		}
		for _, f := range files {
			n := strings.TrimSuffix(f.Name(), ".schema.json")
			s, err := c.Compile("urn:eolscan:schema:2:" + n)
			if err != nil {
				schemaErr = err
				return
			}
			compiledSchemas[n] = s
		}
	})
	if schemaErr != nil {
		return fmt.Errorf("embedded schema: %w", schemaErr)
	}
	s, ok := compiledSchemas[name]
	if !ok {
		return fmt.Errorf("unknown embedded schema %q", name)
	}
	if err := s.Validate(value); err != nil {
		if validation, ok := err.(*jsonschema.ValidationError); ok {
			locations := []string{}
			var collect func(*jsonschema.ValidationError)
			collect = func(e *jsonschema.ValidationError) {
				if len(locations) >= 8 {
					return
				}
				if len(e.Causes) == 0 {
					locations = addUnique(locations, "/"+strings.Join(e.InstanceLocation, "/")+" ("+strings.Join(e.ErrorKind.KeywordPath(), "/")+")")
				}
				for _, cause := range e.Causes {
					collect(cause)
				}
			}
			collect(validation)
			return fmt.Errorf("schema validation failed: %s", strings.Join(locations, ", "))
		}
		return fmt.Errorf("schema validation failed")
	}
	return nil
}

func jsonValue(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	err = json.Unmarshal(b, &out)
	return out, err
}

// Decode nodes ourselves so unquoted dates remain strings, duplicate keys are
// rejected, and aliases cannot amplify input or make policy hashing ambiguous.
func decodeYAML(b []byte) (any, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var root yaml.Node
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("YAML: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("expected one YAML document")
	}
	nodes := 0
	var walk func(*yaml.Node, int) (any, error)
	walk = func(n *yaml.Node, depth int) (any, error) {
		nodes++
		if depth > 128 || nodes > 1000000 {
			return nil, fmt.Errorf("YAML structure limit exceeded")
		}
		switch n.Kind {
		case yaml.DocumentNode:
			if len(n.Content) != 1 {
				return nil, fmt.Errorf("empty YAML document")
			}
			return walk(n.Content[0], depth+1)
		case yaml.MappingNode:
			m := make(map[string]any)
			for i := 0; i < len(n.Content); i += 2 {
				k := n.Content[i]
				if k.Kind != yaml.ScalarNode || k.Tag != "!!str" {
					return nil, fmt.Errorf("YAML keys must be strings")
				}
				if _, exists := m[k.Value]; exists {
					return nil, fmt.Errorf("duplicate YAML key %q", k.Value)
				}
				v, err := walk(n.Content[i+1], depth+1)
				if err != nil {
					return nil, err
				}
				m[k.Value] = v
			}
			return m, nil
		case yaml.SequenceNode:
			a := make([]any, 0, len(n.Content))
			for _, child := range n.Content {
				v, err := walk(child, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			return a, nil
		case yaml.ScalarNode:
			switch n.Tag {
			case "!!str", "!!timestamp":
				return n.Value, nil
			case "!!null":
				return nil, nil
			case "!!bool":
				return strconv.ParseBool(strings.ToLower(n.Value))
			case "!!int", "!!float":
				var v any
				if err := n.Decode(&v); err != nil {
					return nil, err
				}
				return jsonValue(v)
			default:
				return nil, fmt.Errorf("unsupported YAML tag %q", n.Tag)
			}
		default:
			return nil, fmt.Errorf("YAML aliases are unsupported; use explicit values")
		}
	}
	return walk(&root, 0)
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Canonical JSON uses recursively sorted keys, UTF-8 strings and no HTML
// escaping, matching the portable policy_hash contract.
func canonicalJSON(v any) ([]byte, error) {
	v, err := jsonValue(v)
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
