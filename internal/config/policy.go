// Package config loads and validates policies, catalogs, and CI exceptions.
package config

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Pirikara/eolscan/internal/contract"
	"github.com/Pirikara/eolscan/internal/fileio"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
)

func mergeMap(dst, src map[string]any) {
	for k, v := range src {
		sm, sok := v.(map[string]any)
		dm, dok := dst[k].(map[string]any)
		if sok && dok {
			mergeMap(dm, sm)
		} else {
			dst[k] = v
		}
	}
}

func Default() model.Policy {
	b := defaultYAML
	v, err := contract.DecodeYAML(b)
	if err != nil {
		panic(err)
	}
	j, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var p model.Policy
	if err := json.Unmarshal(j, &p); err != nil {
		panic(err)
	}
	return p
}

func Load(path string) (model.Policy, error) {
	b := defaultYAML
	v, err := contract.DecodeYAML(b)
	if err != nil {
		return model.Policy{}, err
	}
	defaults := v.(map[string]any)
	if path != "" {
		b, err := fileio.ReadLimited(path, 16<<20)
		if err != nil {
			return model.Policy{}, fmt.Errorf("read config: %w", err)
		}
		input, err := contract.DecodeYAML(b)
		if err != nil {
			return model.Policy{}, err
		}
		if err := contract.Validate("policy-input", input); err != nil {
			return model.Policy{}, fmt.Errorf("config: %w", err)
		}
		mergeMap(defaults, input.(map[string]any))
	}
	if err := contract.Validate("policy", defaults); err != nil {
		return model.Policy{}, fmt.Errorf("config: %w", err)
	}
	j, _ := json.Marshal(defaults)
	var p model.Policy
	if err := json.Unmarshal(j, &p); err != nil {
		return p, err
	}
	return p, Validate(p)
}

func safeHTTPS(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Opaque == ""
}

func SafeEvidenceURL(raw string) bool {
	u, err := url.Parse(raw)
	// Query parameters are not needed for static support evidence. Rejecting
	// them also keeps credentials out of reports, hashes and diagnostics.
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Opaque == ""
}

func Validate(p model.Policy) error {
	v, err := contract.JSONValue(p)
	if err != nil {
		return err
	}
	if err := contract.Validate("policy", v); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	for _, source := range []model.RegistryPolicy{
		{Enabled: p.Sources.EndoflifeDate.Enabled, BaseURL: p.Sources.EndoflifeDate.BaseURL},
		{Enabled: p.Sources.DepsDev.Enabled, BaseURL: p.Sources.DepsDev.BaseURL},
		{Enabled: p.Sources.GitHub.Enabled, BaseURL: p.Sources.GitHub.BaseURL},
		p.Sources.NPM, p.Sources.PyPI, p.Sources.RubyGems,
	} {
		raw := source.BaseURL
		u, _ := url.Parse(raw)
		if !safeHTTPS(raw) || source.Enabled && !model.Contains(p.Network.AllowedHosts, u.Hostname()) {
			return fmt.Errorf("provider base URL must use an explicitly allowed HTTPS host without credentials, query or fragment")
		}
	}
	for host := range p.Network.HostLimits {
		if !model.Contains(p.Network.AllowedHosts, host) {
			return fmt.Errorf("network.host_limits must use an explicitly allowed host")
		}
	}
	if p.Sources.OfficialCatalog.Enabled && p.Sources.OfficialCatalog.Path == nil {
		return fmt.Errorf("official_catalog.enabled requires a path")
	}
	if p.Sources.OfficialCatalog.Enabled && model.Text(p.Sources.OfficialCatalog.Path) == "builtin:upstream-security" {
		return fmt.Errorf("the fixed builtin catalog was removed; disable official_catalog or provide a local catalog path")
	}
	if model.Contains(p.CI.FailOnSignals, "STALE_RELEASE") && p.Signals.StaleReleaseDays == nil {
		return fmt.Errorf("CI requires STALE_RELEASE but stale_release_days is null")
	}
	if model.Contains(p.CI.FailOnSignals, "STALE_REPOSITORY") && p.Signals.StaleRepositoryDays == nil {
		return fmt.Errorf("CI requires STALE_REPOSITORY but stale_repository_days is unset")
	}
	for _, pattern := range UnmaintainedPatterns(p) {
		if _, err := regexp.Compile(strings.ReplaceAll(pattern, "{package}", "example")); err != nil {
			return fmt.Errorf("unmaintained_patterns contains an invalid Go regular expression")
		}
	}
	ids := map[string]bool{}
	for _, rule := range p.Decision.EOLRules {
		if ids[rule.ID] {
			return fmt.Errorf("decision.eol_rules requires unique rule IDs")
		}
		ids[rule.ID] = true
		if model.Contains(rule.Conditions(), "STALE_RELEASE") && p.Signals.StaleReleaseDays == nil {
			return fmt.Errorf("EOL rule %s requires a non-null stale_release_days", rule.ID)
		}
		if model.Contains(rule.Conditions(), "STALE_REPOSITORY") && p.Signals.StaleRepositoryDays == nil {
			return fmt.Errorf("EOL rule %s requires stale_repository_days", rule.ID)
		}
		for _, raw := range rule.Packages {
			if _, err := identity.Base(raw); err == nil {
				continue
			}
			if _, reason := identity.Resolve(model.Component{PURL: raw}); reason != "" {
				return fmt.Errorf("EOL rule %s requires exact public package PURLs", rule.ID)
			}
		}
	}
	// Bound arithmetic, channel sizes and retries even for a hand-edited policy.
	if p.Network.MaxConcurrency > 256 || p.Network.Retries > 10 || p.Network.TimeoutSeconds > 3600 ||
		p.Input.MaxInputBytes > 1<<30 || p.Input.MaxComponents > 1000000 || p.Input.MaxJSONDepth > 1024 {
		return fmt.Errorf("config exceeds implementation resource limits")
	}
	return nil
}

func resolvePath(base, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

func LoadBundle(p model.Policy, configPath string) (model.PolicyBundle, error) {
	b := model.PolicyBundle{Policy: p}
	if err := Validate(p); err != nil {
		return b, err
	}
	base := "."
	if configPath != "" {
		base = filepath.Dir(configPath)
	}
	if p.Sources.OfficialCatalog.Enabled {
		data, err := fileio.ReadLimited(resolvePath(base, *p.Sources.OfficialCatalog.Path), 16<<20)
		if err != nil {
			return b, fmt.Errorf("read catalog: %w", err)
		}
		v, err := contract.DecodeYAML(data)
		if err != nil {
			return b, err
		}
		if err := contract.Validate("support-catalog", v); err != nil {
			return b, fmt.Errorf("catalog: %w", err)
		}
		j, _ := json.Marshal(v)
		var catalog model.Catalog
		if err := json.Unmarshal(j, &catalog); err != nil {
			return b, err
		}
		if err := ValidateCatalog(catalog); err != nil {
			return b, err
		}
		b.Catalog = &catalog
		h, _ := contract.CanonicalJSON(catalog)
		b.CatalogHash = contract.Digest(h)
	}
	if p.Exceptions.Path != nil {
		data, err := fileio.ReadLimited(resolvePath(base, *p.Exceptions.Path), 16<<20)
		if err != nil {
			return b, fmt.Errorf("read exceptions: %w", err)
		}
		v, err := contract.DecodeYAML(data)
		if err != nil {
			return b, err
		}
		if err := contract.Validate("exceptions", v); err != nil {
			return b, fmt.Errorf("exceptions: %w", err)
		}
		j, _ := json.Marshal(v)
		var exc model.Exceptions
		if err := json.Unmarshal(j, &exc); err != nil {
			return b, err
		}
		seen := map[string]bool{}
		for i := range exc.Exceptions {
			e := &exc.Exceptions[i]
			id, reason := identity.Resolve(model.Component{PURL: e.PackagePURL})
			if reason != "" || !safeEvidenceIdentity(id) {
				return b, fmt.Errorf("exceptions require a public exact PURL")
			}
			if seen[id.PURL] {
				return b, fmt.Errorf("duplicate exception PURL")
			}
			seen[id.PURL] = true
		}
		b.Exceptions = &exc
	}
	payload, err := contract.CanonicalJSON(map[string]any{"policy": p, "catalog": b.Catalog, "exceptions": b.Exceptions})
	if err != nil {
		return b, err
	}
	b.Hash = contract.Digest(payload)
	return b, nil
}

func safeEvidenceIdentity(id identity.Identity) bool { return id.PURL != "" && id.System != "" }

func RequestedSignals(p model.Policy) []string {
	return requestedSignals(p, p.Decision.EOLRules)
}

// EOL rules require their inputs even when an optional report signal is off.
// Package scopes avoid querying conditions that cannot affect this component.
func RequestedSignalsForPackage(p model.Policy, id identity.Identity) []string {
	return requestedSignals(p, ApplicableEOLRules(p, id))
}

func ApplicableEOLRules(p model.Policy, id identity.Identity) []model.EOLRule {
	out := []model.EOLRule{}
	for _, rule := range p.Decision.EOLRules {
		if len(rule.Ecosystems) > 0 && !model.Contains(rule.Ecosystems, id.Type) {
			continue
		}
		if len(rule.Packages) > 0 {
			matched := false
			for _, raw := range rule.Packages {
				if base, err := identity.Base(raw); err == nil {
					matched = matched || base == id.BasePURL
				} else if target, reason := identity.Resolve(model.Component{PURL: raw}); reason == "" {
					matched = matched || target.PURL == id.PURL
				}
			}
			if !matched {
				continue
			}
		}
		out = append(out, rule)
	}
	return out
}

func requestedSignals(p model.Policy, rules []model.EOLRule) []string {
	out := append([]string{}, p.CI.FailOnSignals...)
	if p.Signals.Deprecated {
		out = model.AddUnique(out, "DEPRECATED")
	}
	for _, signal := range []struct {
		enabled bool
		name    string
	}{
		{p.Signals.Yanked, "YANKED"}, {p.Signals.Archived, "ARCHIVED"}, {p.Signals.Quarantined, "QUARANTINED"},
	} {
		if signal.enabled {
			out = model.AddUnique(out, signal.name)
		}
	}
	if p.Signals.StaleReleaseDays != nil {
		out = model.AddUnique(out, "STALE_RELEASE")
	}
	if p.Signals.StaleRepositoryDays != nil {
		out = model.AddUnique(out, "STALE_REPOSITORY")
	}
	for _, rule := range rules {
		for _, kind := range rule.Conditions() {
			out = model.AddUnique(out, kind)
		}
	}
	// Stable order independent of configuration order.
	return model.SortedStrings(out)
}

func CleanBase(raw string) string { return strings.TrimRight(raw, "/") }

// Patterns match declarations about this project, not arbitrary mentions of
// deprecated APIs or dependencies. {package} is replaced with a quoted name.
// An explicit empty list disables text patterns; the PyPI inactive classifier
// remains an independent structured declaration.
func UnmaintainedPatterns(p model.Policy) []string {
	if p.Signals.UnmaintainedPatterns != nil {
		return *p.Signals.UnmaintainedPatterns
	}
	return []string{
		`(?im)^(?:this (?:backport )?(?:project|package|library|module|gem|tool|repository|crate)|{package}) (?:isn't|is not) maintained (?:anymore|any longer)(?:\s*[.!,:;]|\s*$)`,
		`(?im)^(?:(?:this|the) (?:project|package|library|module|gem|tool|repository|crate)|(?:the )?["'\x60]*{package}["'\x60]*(?: (?:pypi )?package)?) (?:is |has been |is now |has now been )?(?:no longer (?:being )?(?:actively )?(?:maintained|supported)|unmaintained|deprecated|not maintained)(?:\s*[.!,:;]|\s*$| in (?:favor|favour) of\b| (?:please )?use\b)`,
		`(?im)^(?:(?:(?:project|maintenance) )?status\s*:\s*)?(?:unmaintained|not maintained)\s*[.!]?\s*$`,
		`(?i)\b(?:the tool|this package|{package}) is no longer released as ["'\x60]*{package}["'\x60]* and will only be fixed in the [a-z0-9_.-]+ package\b`,
		`(?im)^(?:this (?:project|package|library|module|gem|tool)|{package}) has reached (?:end[- ]of[- ]life|eol)(?:\s*[.!,:;]|\s*$)`,
		`(?im)^{package}\s*[\[(]\s*(?:deprecated|unmaintained|retired)\s*[\])]\s*$`,
	}
}

//go:embed defaults.yaml
var defaultYAML []byte
