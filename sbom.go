package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

func inspectJSON(b []byte, maxDepth int) error {
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
func parseSBOM(r io.Reader, p InputPolicy) (SBOM, error) {
	b, err := io.ReadAll(io.LimitReader(r, p.MaxInputBytes+1))
	if err != nil {
		return SBOM{}, fmt.Errorf("read SBOM: %w", err)
	}
	if int64(len(b)) > p.MaxInputBytes {
		return SBOM{}, fmt.Errorf("SBOM exceeds %d bytes", p.MaxInputBytes)
	}
	if err := inspectJSON(b, p.MaxJSONDepth); err != nil {
		return SBOM{}, err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(b, &root); err != nil || root == nil {
		return SBOM{}, fmt.Errorf("SBOM must be a JSON object")
	}
	out := SBOM{Components: []Component{}, SHA256: digest(b)}
	switch {
	case root["bomFormat"] != nil:
		var format, version string
		if json.Unmarshal(root["bomFormat"], &format) != nil || format != "CycloneDX" {
			return out, fmt.Errorf("invalid CycloneDX bomFormat")
		}
		if json.Unmarshal(root["specVersion"], &version) != nil || !has([]string{"1.4", "1.5", "1.6", "1.7"}, version) {
			return out, fmt.Errorf("supported CycloneDX versions: 1.4–1.7")
		}
		type entry struct {
			Type       string            `json:"type"`
			Ref        string            `json:"bom-ref"`
			Name       string            `json:"name"`
			Version    string            `json:"version"`
			PURL       string            `json:"purl"`
			Components []json.RawMessage `json:"components"`
		}
		count := 0
		var walk func([]json.RawMessage, string, bool) error
		walk = func(items []json.RawMessage, path string, exclude bool) error {
			for i, raw := range items {
				count++
				if count > p.MaxComponents {
					return fmt.Errorf("SBOM exceeds %d components", p.MaxComponents)
				}
				var e entry
				if err := json.Unmarshal(raw, &e); err != nil {
					return fmt.Errorf("invalid CycloneDX component: %w", err)
				}
				ref := fmt.Sprintf("%s/%d", path, i)
				if path == "/metadata/component" {
					ref = path
				}
				childPath := ref + "/components"
				if e.Name == "" || e.Type == "" {
					return fmt.Errorf("CycloneDX component %s requires name and type", ref)
				}
				if e.Ref != "" {
					ref = e.Ref
				}
				if exclude || !has(p.IncludeComponentTypes, e.Type) {
					out.Excluded++
				} else {
					out.Components = append(out.Components, Component{SourceRef: ref, Name: e.Name, Version: e.Version, PURL: e.PURL})
				}
				if err := walk(e.Components, childPath, exclude); err != nil {
					return err
				}
			}
			return nil
		}
		var entries []json.RawMessage
		if raw := root["components"]; raw != nil && string(raw) != "null" {
			if err := json.Unmarshal(raw, &entries); err != nil {
				return out, fmt.Errorf("invalid components array")
			}
		}
		if raw := root["metadata"]; raw != nil {
			var meta struct {
				Component json.RawMessage `json:"component"`
			}
			if err := json.Unmarshal(raw, &meta); err != nil {
				return out, fmt.Errorf("invalid CycloneDX metadata")
			}
			if meta.Component != nil && string(meta.Component) != "null" {
				if err := walk([]json.RawMessage{meta.Component}, "/metadata/component", !p.IncludeMetadataComponent); err != nil {
					return out, err
				}
			}
		}
		if err := walk(entries, "/components", false); err != nil {
			return out, err
		}
	case root["spdxVersion"] != nil:
		var version string
		if json.Unmarshal(root["spdxVersion"], &version) != nil || version != "SPDX-2.3" {
			return out, fmt.Errorf("supported SPDX version: SPDX-2.3")
		}
		var entries []struct {
			ID           string `json:"SPDXID"`
			Name         string `json:"name"`
			Version      string `json:"versionInfo"`
			ExternalRefs []struct {
				Type    string `json:"referenceType"`
				Locator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		}
		if raw := root["packages"]; raw != nil {
			if err := json.Unmarshal(raw, &entries); err != nil {
				return out, fmt.Errorf("invalid SPDX packages")
			}
		}
		if len(entries) > p.MaxComponents {
			return out, fmt.Errorf("SBOM exceeds %d components", p.MaxComponents)
		}
		for i, e := range entries {
			if e.Name == "" {
				return out, fmt.Errorf("SPDX package requires name")
			}
			ref := e.ID
			if ref == "" {
				ref = fmt.Sprintf("/packages/%d", i)
			}
			c := Component{SourceRef: ref, Name: e.Name, Version: e.Version}
			for _, r := range e.ExternalRefs {
				if strings.EqualFold(r.Type, "purl") {
					if c.PURL != "" && c.PURL != r.Locator {
						c.PURLConflict = true
					}
					c.PURL = r.Locator
				}
			}
			out.Components = append(out.Components, c)
		}
	default:
		return out, fmt.Errorf("unsupported SBOM: expected CycloneDX 1.4–1.7 or SPDX 2.3 JSON")
	}
	return out, nil
}
