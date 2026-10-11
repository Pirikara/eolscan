// Package contract validates JSON contracts and canonicalizes structured data.
package contract

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/schemas"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

var contracts = schemas.Files()

var schemaOnce sync.Once

var schemaErr error

var compiledSchemas map[string]*jsonschema.Schema

func Validate(name string, value any) error {
	schemaOnce.Do(func() {
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		c.AssertFormat()
		compiledSchemas = make(map[string]*jsonschema.Schema)
		files, err := contracts.ReadDir(".")
		if err != nil {
			schemaErr = err
			return
		}
		for _, f := range files {
			b, _ := contracts.ReadFile(f.Name())
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
					locations = model.AddUnique(locations, "/"+strings.Join(e.InstanceLocation, "/")+" ("+strings.Join(e.ErrorKind.KeywordPath(), "/")+")")
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
