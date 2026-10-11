package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type InputPolicy struct {
	IncludeComponentTypes    []string `json:"include_component_types"`
	IncludeMetadataComponent bool     `json:"include_metadata_component"`
	MaxInputBytes            int64    `json:"max_input_bytes"`
	MaxComponents            int      `json:"max_components"`
	MaxJSONDepth             int      `json:"max_json_depth"`
}
type SourcePolicy struct {
	OfficialCatalog struct {
		Enabled bool    `json:"enabled"`
		Path    *string `json:"path"`
	} `json:"official_catalog"`
	EndoflifeDate struct {
		Enabled          bool   `json:"enabled"`
		BaseURL          string `json:"base_url"`
		MatchPURLExactly bool   `json:"match_purl_exactly"`
	} `json:"endoflife_date"`
	DepsDev struct {
		Enabled bool   `json:"enabled"`
		BaseURL string `json:"base_url"`
	} `json:"deps_dev"`
}
type Policy struct {
	SchemaVersion       int          `json:"schema_version"`
	Input               InputPolicy  `json:"input"`
	Sources             SourcePolicy `json:"sources"`
	VersionVerification struct {
		Mode    string   `json:"mode"`
		Sources []string `json:"sources"`
	} `json:"version_verification"`
	Signals struct {
		Deprecated       bool `json:"deprecated"`
		StaleReleaseDays *int `json:"stale_release_days"`
	} `json:"signals"`
	Notices struct {
		EOLSoonDays int `json:"eol_soon_days"`
	} `json:"notices"`
	Decision struct {
		SupportScope       string `json:"support_scope"`
		MaxEvidenceAgeDays int    `json:"max_evidence_age_days"`
	} `json:"decision"`
	Network struct {
		AllowedHosts   []string `json:"allowed_hosts"`
		TimeoutSeconds float64  `json:"timeout_seconds"`
		Retries        int      `json:"retries"`
		MaxConcurrency int      `json:"max_concurrency"`
	} `json:"network"`
	Cache struct {
		Enabled          bool    `json:"enabled"`
		PositiveTTLHours float64 `json:"positive_ttl_hours"`
		NegativeTTLHours float64 `json:"negative_ttl_hours"`
	} `json:"cache"`
	CI struct {
		FailOnStatuses       []string `json:"fail_on_statuses"`
		MinConfidence        string   `json:"min_confidence"`
		FailOnSignals        []string `json:"fail_on_signals"`
		FailOnIncompleteScan bool     `json:"fail_on_incomplete_scan"`
		MaxUnknownRatio      *float64 `json:"max_unknown_ratio"`
	} `json:"ci"`
	Exceptions struct {
		Path *string `json:"path"`
	} `json:"exceptions"`
	Output struct {
		IncludeUnknown  bool `json:"include_unknown"`
		IncludeEvidence bool `json:"include_evidence"`
	} `json:"output"`
}

type PolicyBundle struct {
	Policy      Policy
	Catalog     *Catalog
	Exceptions  *Exceptions
	Hash        string
	CatalogHash string
}

func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("file exceeds %d bytes", max)
	}
	return b, nil
}
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
func defaultPolicy() Policy {
	b, _ := contracts.ReadFile("examples/eol-policy.example.yaml")
	v, err := decodeYAML(b)
	if err != nil {
		panic(err)
	}
	j, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var p Policy
	if err := json.Unmarshal(j, &p); err != nil {
		panic(err)
	}
	return p
}
func loadPolicy(path string) (Policy, error) {
	b, _ := contracts.ReadFile("examples/eol-policy.example.yaml")
	v, err := decodeYAML(b)
	if err != nil {
		return Policy{}, err
	}
	defaults := v.(map[string]any)
	if path != "" {
		b, err := readLimited(path, 16<<20)
		if err != nil {
			return Policy{}, fmt.Errorf("read config: %w", err)
		}
		input, err := decodeYAML(b)
		if err != nil {
			return Policy{}, err
		}
		if err := schemaValidate("policy-input", input); err != nil {
			return Policy{}, fmt.Errorf("config: %w", err)
		}
		mergeMap(defaults, input.(map[string]any))
	}
	if err := schemaValidate("policy", defaults); err != nil {
		return Policy{}, fmt.Errorf("config: %w", err)
	}
	j, _ := json.Marshal(defaults)
	var p Policy
	if err := json.Unmarshal(j, &p); err != nil {
		return p, err
	}
	return p, validatePolicy(p)
}
func safeHTTPS(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Opaque == ""
}
func safeEvidenceURL(raw string) bool {
	u, err := url.Parse(raw)
	// Query parameters are not needed for static support evidence. Rejecting
	// them also keeps credentials out of reports, hashes and diagnostics.
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Opaque == ""
}
func validatePolicy(p Policy) error {
	v, err := jsonValue(p)
	if err != nil {
		return err
	}
	if err := schemaValidate("policy", v); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	for _, raw := range []string{p.Sources.EndoflifeDate.BaseURL, p.Sources.DepsDev.BaseURL} {
		u, _ := url.Parse(raw)
		if !safeHTTPS(raw) || !has(p.Network.AllowedHosts, u.Hostname()) {
			return fmt.Errorf("provider base URL must use an explicitly allowed HTTPS host without credentials, query or fragment")
		}
	}
	if p.Sources.OfficialCatalog.Enabled && p.Sources.OfficialCatalog.Path == nil {
		return fmt.Errorf("official_catalog.enabled requires a path")
	}
	if has(p.CI.FailOnSignals, "STALE_RELEASE") && p.Signals.StaleReleaseDays == nil {
		return fmt.Errorf("CI requires STALE_RELEASE but stale_release_days is null")
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
func loadBundle(p Policy, configPath string) (PolicyBundle, error) {
	b := PolicyBundle{Policy: p}
	if err := validatePolicy(p); err != nil {
		return b, err
	}
	base := "."
	if configPath != "" {
		base = filepath.Dir(configPath)
	}
	if p.Sources.OfficialCatalog.Enabled {
		data, err := readLimited(resolvePath(base, *p.Sources.OfficialCatalog.Path), 16<<20)
		if err != nil {
			return b, fmt.Errorf("read catalog: %w", err)
		}
		v, err := decodeYAML(data)
		if err != nil {
			return b, err
		}
		if err := schemaValidate("support-catalog", v); err != nil {
			return b, fmt.Errorf("catalog: %w", err)
		}
		j, _ := json.Marshal(v)
		var catalog Catalog
		if err := json.Unmarshal(j, &catalog); err != nil {
			return b, err
		}
		if err := validateCatalog(catalog); err != nil {
			return b, err
		}
		b.Catalog = &catalog
		h, _ := canonicalJSON(catalog)
		b.CatalogHash = digest(h)
	}
	if p.Exceptions.Path != nil {
		data, err := readLimited(resolvePath(base, *p.Exceptions.Path), 16<<20)
		if err != nil {
			return b, fmt.Errorf("read exceptions: %w", err)
		}
		v, err := decodeYAML(data)
		if err != nil {
			return b, err
		}
		if err := schemaValidate("exceptions", v); err != nil {
			return b, fmt.Errorf("exceptions: %w", err)
		}
		j, _ := json.Marshal(v)
		var exc Exceptions
		if err := json.Unmarshal(j, &exc); err != nil {
			return b, err
		}
		seen := map[string]bool{}
		for i := range exc.Exceptions {
			e := &exc.Exceptions[i]
			id, reason := resolveIdentity(Component{PURL: e.PackagePURL})
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
	payload, err := canonicalJSON(map[string]any{"policy": p, "catalog": b.Catalog, "exceptions": b.Exceptions})
	if err != nil {
		return b, err
	}
	b.Hash = digest(payload)
	return b, nil
}
func safeEvidenceIdentity(id Identity) bool { return id.PURL != "" && id.System != "" }
func requestedSignals(p Policy) []string {
	out := append([]string{}, p.CI.FailOnSignals...)
	if p.Signals.Deprecated {
		out = addUnique(out, "DEPRECATED")
	}
	if p.Signals.StaleReleaseDays != nil {
		out = addUnique(out, "STALE_RELEASE")
	}
	// Stable order independent of configuration order.
	return sortedStrings(out)
}
func cleanBase(raw string) string { return strings.TrimRight(raw, "/") }
