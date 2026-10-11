package contract

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Decode nodes ourselves so unquoted dates remain strings, duplicate keys are
// rejected, and aliases cannot amplify input or make policy hashing ambiguous.
func DecodeYAML(b []byte) (any, error) {
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
				return JSONValue(v)
			default:
				return nil, fmt.Errorf("unsupported YAML tag %q", n.Tag)
			}
		default:
			return nil, fmt.Errorf("YAML aliases are unsupported; use explicit values")
		}
	}
	return walk(&root, 0)
}
