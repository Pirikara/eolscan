package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/testutil"
)

func TestDefaultPolicyMatchesExample(t *testing.T) {
	fromExample, err := config.Load(testutil.Path(t, "examples/eol-policy.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(config.Default(), fromExample) {
		t.Fatal("embedded defaults differ from the documented default policy")
	}
}

func TestEOLRuleInputRejectsMalformedScopesAndMissingThresholds(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule map[string]any
	}{
		{"missing_id", map[string]any{"any_of": []string{"ARCHIVED"}}},
		{"invalid_id", map[string]any{"id": "rule with spaces", "any_of": []string{"ARCHIVED"}}},
		{"missing_operator", map[string]any{"id": "rule"}},
		{"duplicate_conditions", map[string]any{"id": "rule", "any_of": []string{"ARCHIVED", "ARCHIVED"}}},
		{"unknown_ecosystem", map[string]any{"id": "rule", "any_of": []string{"ARCHIVED"}, "ecosystems": []string{"ruby"}}},
		{"duplicate_ecosystems", map[string]any{"id": "rule", "any_of": []string{"ARCHIVED"}, "ecosystems": []string{"gem", "gem"}}},
		{"private_repository_purl", map[string]any{"id": "rule", "any_of": []string{"ARCHIVED"}, "packages": []string{"pkg:gem/leaf?repository_url=https://private.example"}}},
		{"duplicate_packages", map[string]any{"id": "rule", "any_of": []string{"ARCHIVED"}, "packages": []string{"pkg:gem/leaf", "pkg:gem/leaf"}}},
		{"unexpected_field", map[string]any{"id": "rule", "any_of": []string{"ARCHIVED"}, "confidence": "HIGH"}},
		{"null_inactivity_threshold", map[string]any{"id": "rule", "any_of": []string{"STALE_RELEASE"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := map[string]any{"schema_version": 2, "decision": map[string]any{"eol_rules": []any{tc.rule}}}
			if tc.name == "null_inactivity_threshold" {
				input["signals"] = map[string]any{"stale_release_days": nil}
			}
			data, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "policy.yaml")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := config.Load(path); err == nil {
				t.Fatalf("accepted invalid rule: %s", data)
			}
		})
	}
}

func TestRuleOverridesReplaceDefaultsAndRespectBothScopes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	data := `schema_version: 2
signals:
  deprecated: false
  stale_release_days: null
decision:
  eol_rules:
    - id: selected-python-project
      any_of: [ARCHIVED]
      ecosystems: [pypi]
      packages: [pkg:pypi/Foo_Bar]
`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Decision.EOLRules) != 1 || p.Decision.EOLRules[0].ID != "selected-python-project" || !p.Decision.UseSupportDates {
		t.Fatal("partial rule overrides appended defaults or removed unrelated defaults")
	}
	for _, tc := range []struct {
		purl string
		want []string
	}{
		{"pkg:pypi/foo-bar@1.0.0", []string{"ARCHIVED"}},
		{"pkg:pypi/FOO.BAR@2.0.0", []string{"ARCHIVED"}},
		{"pkg:pypi/foo-bar-extra@1.0.0", []string{}},
		{"pkg:gem/foo-bar@1.0.0", []string{}},
	} {
		t.Run(tc.purl, func(t *testing.T) {
			id, reason := identity.Resolve(model.Component{PURL: tc.purl})
			if reason != "" {
				t.Fatal(reason)
			}
			if got := config.RequestedSignalsForPackage(p, id); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("scoped inputs=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestDefaultsUseAutomaticSourcesWithoutCatalogFiles(t *testing.T) {
	p := config.Default()
	bundle, err := config.LoadBundle(p, filepath.Join(t.TempDir(), "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Catalog != nil || bundle.CatalogHash != "" || p.Sources.OfficialCatalog.Enabled ||
		!p.Sources.EndoflifeDate.Enabled || !p.Sources.EndoflifeDate.UseSecuritySupportLabel {
		t.Fatalf("automatic defaults: %+v", bundle)
	}
	p.Sources.EndoflifeDate.UseSecuritySupportLabel = false
	disabled, err := config.LoadBundle(p, "")
	if err != nil || disabled.Catalog != nil || disabled.Hash == bundle.Hash {
		t.Fatalf("disable automatic scope: %+v error=%v", disabled.Catalog, err)
	}
}

func TestPolicyValidationRejectionAndMerge(t *testing.T) {
	for _, data := range []string{
		"schema_version: 1\n",
		"schema_version: 2\nschema_version: 2\n",
		"schema_version: 2\nsources:\n  unimplemented_provider:\n    enabled: true\n",
		"schema_version: 2\nversion_verification:\n  mode: optional\n",
		"schema_version: 2\nsources:\n  official_catalog:\n    enabled: true\n    path: builtin:upstream-security\n",
		"schema_version: 2\nsignals:\n  stale_release_days: null\nci:\n  fail_on_signals: [STALE_RELEASE]\n",
		"schema_version: 2\nsources:\n  deps_dev:\n    base_url: http://api.deps.dev/v3\n",
		"schema_version: 2\nsources:\n  deps_dev:\n    base_url: https://api.deps.dev/v3?token=secret\n",
		"schema_version: 2\nsources:\n  deps_dev:\n    base_url: https://user:secret@api.deps.dev/v3\n",
		"schema_version: 2\nnetwork:\n  allowed_hosts: [example.org]\n",
		"schema_version: 2\nci:\n  fail_on_signals: [STALE_RELEASE, STALE_RELEASE]\n",
		"schema_version: 2\nnetwork:\n  requests_per_second: 0\n",
		"schema_version: 2\nnetwork:\n  burst: 0\n",
		"schema_version: 2\nnetwork:\n  max_wait_seconds: 0\n",
		"schema_version: 2\nnetwork:\n  host_limits:\n    pypi.org:\n      requests_per_second: 1\n",
		"schema_version: 2\nnetwork:\n  host_limits:\n    other.invalid:\n      requests_per_second: 1\n      burst: 1\n",
		"schema_version: 2\nsources:\n  npm:\n    base_url: https://user:secret@registry.npmjs.org\n",
		"schema_version: 2\nsources:\n  pypi:\n    base_url: https://pypi.org?token=secret\n",
		"schema_version: 2\nversion_verification:\n  sources: [unknown_registry]\n",
	} {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		os.WriteFile(path, []byte(data), 0600)
		if _, err := config.Load(path); err == nil {
			t.Fatalf("accepted policy %s", data)
		}
	}
	p, err := config.Load(testutil.Path(t, "examples/eol-policy.partial.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Network.TimeoutSeconds != 8 || p.CI.MinConfidence != "MEDIUM" || !p.CI.FailOnIncompleteScan || p.CI.MaxUnknownRatio == nil {
		t.Fatalf("merge: %+v", p)
	}
}

func TestNativeProviderAndRequiredSignalSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	data := `schema_version: 2
sources:
  endoflife_date: {enabled: false}
  deps_dev: {enabled: false}
  npm: {enabled: false}
  rubygems: {enabled: false}
  github: {enabled: false}
decision:
  eol_rules: []
network:
  allowed_hosts: [pypi.org]
  host_limits:
    pypi.org: {requests_per_second: 0.5, burst: 2}
signals:
  deprecated: false
  stale_release_days: null
ci:
  fail_on_signals: [YANKED, ARCHIVED]
`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Sources.PyPI.Enabled || p.Network.HostLimits["pypi.org"].RequestsPerSecond != 0.5 || !reflect.DeepEqual(config.RequestedSignals(p), []string{"ARCHIVED", "YANKED"}) {
		t.Fatalf("merged native settings: %+v", p)
	}
}

func TestCustomEOLRulesValidateAndRequireTheirInputs(t *testing.T) {
	for _, decision := range []string{
		"eol_rules: [{id: rule, any_of: []}]",
		"eol_rules: [{id: rule, any_of: [UNKNOWN_CONDITION]}]",
		"eol_rules: [{id: rule, any_of: [DEPRECATED], all_of: [ARCHIVED]}]",
		"eol_rules: [{id: rule, any_of: [DEPRECATED]}, {id: rule, any_of: [ARCHIVED]}]",
		"eol_rules: [{id: rule, any_of: [DEPRECATED], packages: [example]}]",
	} {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		os.WriteFile(path, []byte("schema_version: 2\ndecision:\n  "+decision+"\n"), 0600)
		if _, err := config.Load(path); err == nil {
			t.Fatalf("accepted %s", decision)
		}
	}
	path := filepath.Join(t.TempDir(), "policy.yaml")
	os.WriteFile(path, []byte("schema_version: 2\nsignals:\n  deprecated: false\n  archived: false\n  stale_release_days: 365\ndecision:\n  eol_rules:\n    - id: custom\n      all_of: [ARCHIVED, STALE_RELEASE]\n"), 0600)
	p, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(config.RequestedSignals(p), []string{"ARCHIVED", "STALE_RELEASE"}) {
		t.Fatal("rule inputs were not mandatory")
	}
	before, err := config.LoadBundle(p, "")
	if err != nil {
		t.Fatal(err)
	}
	p.Decision.EOLRules[0].AnyOf, p.Decision.EOLRules[0].AllOf = p.Decision.EOLRules[0].AllOf, nil
	after, err := config.LoadBundle(p, "")
	if err != nil || before.Hash == after.Hash {
		t.Fatal("rule changes must change the policy hash")
	}
}
