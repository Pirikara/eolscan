package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type depsKey struct {
	System  string `json:"system"`
	Name    string `json:"name"`
	Version string `json:"version"`
}
type depsVersion struct {
	Key              depsKey `json:"versionKey"`
	PublishedAt      string  `json:"publishedAt"`
	IsDeprecated     *bool   `json:"isDeprecated"`
	DeprecatedReason string  `json:"deprecatedReason"`
}
type depsPackage struct {
	Key           depsKey        `json:"packageKey"`
	Versions      *[]depsVersion `json:"versions"`
	NextPageToken string         `json:"nextPageToken"`
}

func verificationFromPublication(provider, source, checked, published, asOf string, now time.Time) VersionVerification {
	v := VersionVerification{Status: "UNVERIFIED", ProviderID: ptr(provider), SourceURL: ptr(source), CheckedAt: ptr(checked)}
	p, err := time.Parse(time.RFC3339Nano, published)
	if err != nil {
		v.ReasonCode = ptr("MISSING_PUBLICATION_DATE")
		return v
	}
	v.PublishedAt = ptr(stamp(p))
	if p.After(now) {
		v.ReasonCode = ptr("PUBLICATION_IN_FUTURE")
		return v
	}
	if utcDay(p) > asOf {
		v.Status = "NOT_RELEASED_AS_OF"
		v.ReasonCode = ptr("NOT_RELEASED_AS_OF")
		return v
	}
	v.Status = "VERIFIED"
	return v
}
func depsVersionData(ctx context.Context, t *Transport, id Identity) (depsVersion, HTTPData, error) {
	raw := apiVersionURL(t.p.Sources.DepsDev.BaseURL, id)
	data, err := t.get(ctx, raw)
	if err != nil {
		return depsVersion{}, data, err
	}
	if data.Status == 404 {
		return depsVersion{}, data, nil
	}
	var v depsVersion
	if inspectJSON(data.Body, 256) != nil || json.Unmarshal(data.Body, &v) != nil || v.Key.System == "" || v.Key.Name == "" || v.Key.Version == "" {
		t.invalidate(raw)
		return v, data, &lookupError{Code: "PROVIDER_SCHEMA_MISMATCH", Status: 200}
	}
	if strings.ToUpper(v.Key.System) != id.System || normalizedName(id.System, v.Key.Name) != id.Name ||
		normalizedVersion(id.System, v.Key.Version) != id.Version {
		t.invalidate(raw)
		return v, data, &lookupError{Code: "VERSION_CONFLICT", Status: 200}
	}
	return v, data, nil
}
func depsVerification(t *Transport, id Identity, v depsVersion, data HTTPData, err error, asOf string) VersionVerification {
	raw := apiVersionURL(t.p.Sources.DepsDev.BaseURL, id)
	result := VersionVerification{Status: "UNVERIFIED", ProviderID: ptr("deps_dev"), SourceURL: ptr(raw)}
	if data.ObservedAt != "" {
		result.CheckedAt = ptr(data.ObservedAt)
	}
	if err != nil {
		result.ReasonCode = ptr("SOURCE_ERROR")
		if e, ok := err.(*lookupError); ok {
			result.ReasonCode = ptr(e.Code)
		}
		return result
	}
	if data.Status == 404 {
		result.Status = "NOT_FOUND_IN_INDEX"
		result.ReasonCode = ptr("VERSION_NOT_FOUND_IN_INDEX")
		return result
	}
	return verificationFromPublication("deps_dev", raw, data.ObservedAt, v.PublishedAt, asOf, t.now)
}
func unknownSignal(kind, reason string) SignalEvaluation {
	return SignalEvaluation{Type: kind, Status: "UNKNOWN", ReasonCode: ptr(reason)}
}
func deprecatedSignal(t *Transport, id Identity, v depsVersion, data HTTPData, err error) (SignalEvaluation, *SignalEvidence) {
	e := unknownSignal("DEPRECATED", "NO_CAPABILITY")
	if err != nil {
		e.ReasonCode = ptr("SOURCE_ERROR")
		return e, nil
	}
	if data.Status != 200 {
		e.ReasonCode = ptr("VERSION_NOT_FOUND_IN_INDEX")
		return e, nil
	}
	raw := apiVersionURL(t.p.Sources.DepsDev.BaseURL, id)
	e.ProviderID = ptr("deps_dev")
	e.SourceURL = ptr(raw)
	e.CheckedAt = ptr(data.ObservedAt)
	// deps.dev's shared boolean does not guarantee collection of a registry's
	// negative status in every ecosystem. Explicit true is positive evidence;
	// a negative evaluation is enabled only for npm with an explicit boolean.
	if v.IsDeprecated != nil && *v.IsDeprecated {
		e.Status = "PRESENT"
		e.ReasonCode = nil
		s := SignalEvidence{Type: "DEPRECATED", ProviderID: "deps_dev", SourceURL: ptr(raw), ObservedAt: data.ObservedAt,
			Details: map[string]any{"deprecated_reason": v.DeprecatedReason}}
		return e, &s
	}
	if id.Type == "npm" && v.IsDeprecated != nil {
		e.Status = "ABSENT"
		e.ReasonCode = nil
	} else if id.Type == "npm" {
		e.ReasonCode = ptr("MISSING_DEPRECATION_STATUS")
	}
	return e, nil
}
func staleReleaseSignal(ctx context.Context, t *Transport, id Identity, asOf string) (SignalEvaluation, *SignalEvidence, []Diagnostic) {
	e := unknownSignal("STALE_RELEASE", "NO_CAPABILITY")
	ds := []Diagnostic{}
	if t.p.Signals.StaleReleaseDays == nil {
		return e, nil, ds
	}
	if asOf > utcDay(t.now) {
		e.ReasonCode = ptr("FUTURE_AS_OF")
		return e, nil, ds
	}
	// These indices have documented gaps (proxy-only Go, wheels/sdists-only
	// PyPI), so their version lists cannot prove package-wide inactivity.
	if id.Type == "golang" || id.Type == "pypi" {
		e.ReasonCode = ptr("INCOMPLETE_VERSION_INDEX")
		return e, nil, ds
	}
	raw := apiPackageURL(t.p.Sources.DepsDev.BaseURL, id)
	data, err := t.get(ctx, raw)
	ds = append(ds, providerDiagnostics("deps_dev", data.Diagnostics)...)
	if err != nil {
		e.ReasonCode = ptr("SOURCE_ERROR")
		ds = append(ds, errorDiagnostic("deps_dev", err))
		return e, nil, ds
	}
	e.ProviderID = ptr("deps_dev")
	e.SourceURL = ptr(raw)
	e.CheckedAt = ptr(data.ObservedAt)
	if data.Status == 404 {
		e.ReasonCode = ptr("PACKAGE_NOT_FOUND_IN_INDEX")
		return e, nil, ds
	}
	var p depsPackage
	if inspectJSON(data.Body, 256) != nil || json.Unmarshal(data.Body, &p) != nil || p.Versions == nil || p.Key.System == "" || p.Key.Name == "" ||
		strings.ToUpper(p.Key.System) != id.System || normalizedName(id.System, p.Key.Name) != id.Name {
		t.invalidate(raw)
		e.ReasonCode = ptr("PROVIDER_SCHEMA_MISMATCH")
		ds = append(ds, diag("PROVIDER_SCHEMA_MISMATCH", "deps_dev", "Package version list is malformed or identifies another package"))
		return e, nil, ds
	}
	if p.NextPageToken != "" || len(*p.Versions) == 0 {
		e.ReasonCode = ptr("INCOMPLETE_VERSION_LIST")
		return e, nil, ds
	}
	var latest time.Time
	seen := map[string]bool{}
	for _, v := range *p.Versions {
		if strings.ToUpper(v.Key.System) != id.System || normalizedName(id.System, v.Key.Name) != id.Name || v.Key.Version == "" || seen[v.Key.Version] {
			e.ReasonCode = ptr("INCOMPLETE_VERSION_LIST")
			return e, nil, ds
		}
		seen[v.Key.Version] = true
		when, err := time.Parse(time.RFC3339Nano, v.PublishedAt)
		if err != nil {
			e.ReasonCode = ptr("MISSING_PUBLICATION_DATE")
			return e, nil, ds
		}
		if when.After(t.now) {
			e.ReasonCode = ptr("PUBLICATION_IN_FUTURE")
			return e, nil, ds
		}
		if utcDay(when) <= asOf && when.After(latest) {
			latest = when
		}
	}
	if latest.IsZero() {
		e.ReasonCode = ptr("NO_RELEASE_AS_OF")
		return e, nil, ds
	}
	at, _ := time.Parse("2006-01-02", asOf)
	publishedDay, _ := time.Parse("2006-01-02", utcDay(latest))
	days := int(at.Sub(publishedDay).Hours() / 24)
	e.Status = "ABSENT"
	e.ReasonCode = nil
	if days > *t.p.Signals.StaleReleaseDays {
		e.Status = "PRESENT"
		s := SignalEvidence{Type: "STALE_RELEASE", ProviderID: "deps_dev", SourceURL: ptr(raw), ObservedAt: data.ObservedAt,
			Details: map[string]any{"latest_published_at": stamp(latest), "days_since_latest_release": days, "threshold_days": *t.p.Signals.StaleReleaseDays}}
		return e, &s, ds
	}
	return e, nil, ds
}
func providerDiagnostics(provider string, ds []Diagnostic) []Diagnostic {
	out := append([]Diagnostic{}, ds...)
	for i := range out {
		if out[i].ProviderID == nil {
			out[i].ProviderID = ptr(provider)
		}
	}
	return out
}

type productRef struct {
	Name string `json:"name"`
	URI  string `json:"uri"`
}
type eolIndexRow struct {
	Identifier string     `json:"identifier"`
	Product    productRef `json:"product"`
}
type eolRelease struct {
	Name         string  `json:"name"`
	EOLFrom      *string `json:"eolFrom"`
	IsEOL        *bool   `json:"isEol"`
	IsMaintained *bool   `json:"isMaintained"`
}
type eolProduct struct {
	Name        string `json:"name"`
	Identifiers *[]struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"identifiers"`
	Releases *[]eolRelease `json:"releases"`
	Links    struct {
		HTML string `json:"html"`
	} `json:"links"`
}
type EOLProvider struct {
	t         *Transport
	bundle    PolicyBundle
	once      sync.Once
	index     map[string][]productRef
	indexData HTTPData
	indexErr  error
}

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)

func eolHeader(schema, generated string) bool {
	_, err := time.Parse(time.RFC3339Nano, generated)
	return strings.HasPrefix(schema, "1.") && err == nil
}
func (p *EOLProvider) loadIndex(ctx context.Context) {
	p.once.Do(func() {
		raw := cleanBase(p.t.p.Sources.EndoflifeDate.BaseURL) + "/identifiers/purl/"
		p.index = map[string][]productRef{}
		p.indexData, p.indexErr = p.t.get(ctx, raw)
		if p.indexErr != nil {
			return
		}
		if p.indexData.Status == 404 {
			return
		}
		var response struct {
			SchemaVersion string         `json:"schema_version"`
			GeneratedAt   string         `json:"generated_at"`
			Result        *[]eolIndexRow `json:"result"`
		}
		bad := inspectJSON(p.indexData.Body, 256) != nil || json.Unmarshal(p.indexData.Body, &response) != nil ||
			response.Result == nil || !eolHeader(response.SchemaVersion, response.GeneratedAt)
		if !bad {
			for _, row := range *response.Result {
				if !strings.HasPrefix(row.Identifier, "pkg:") || row.Product.Name == "" || row.Product.URI == "" {
					bad = true
					break
				}
				parsed, inScope, err := indexPackage(row.Identifier)
				// The public index also contains OCI/OS/SWID identities and
				// qualified registry identities outside this adapter's scope.
				// They must not invalidate unrelated supported public packages.
				if !inScope {
					continue
				}
				if err != nil {
					bad = true
					break
				}
				if !p.validProductURI(row.Product) {
					bad = true
					break
				}
				base := parsed.ToString()
				if !has(p.index[base], row.Product) {
					p.index[base] = append(p.index[base], row.Product)
				}
			}
		}
		if bad {
			p.indexErr = &lookupError{Code: "PROVIDER_SCHEMA_MISMATCH", Status: 200}
			p.t.invalidate(raw)
		}
	})
}

func supportedIndexPrefix(raw string) bool {
	for kind := range systems {
		if strings.HasPrefix(strings.ToLower(raw), "pkg:"+kind+"/") {
			return true
		}
	}
	return false
}
func (p *EOLProvider) validProductURI(r productRef) bool {
	if !slugPattern.MatchString(r.Name) || r.Name == "." || r.Name == ".." {
		return false
	}
	base, err := url.Parse(cleanBase(p.t.p.Sources.EndoflifeDate.BaseURL))
	if err != nil {
		return false
	}
	u, err := url.Parse(r.URI)
	if err != nil || !allowedURL(u, p.t.p) || u.Host != base.Host {
		return false
	}
	want := cleanBase(base.Path) + "/products/" + r.Name
	return u.EscapedPath() == want || u.EscapedPath() == want+"/"
}
func (p *EOLProvider) evidence(ctx context.Context, id Identity) ([]LifecycleEvidence, []Diagnostic, string, bool) {
	out := []LifecycleEvidence{}
	ds := []Diagnostic{}
	p.loadIndex(ctx)
	ds = append(ds, providerDiagnostics("endoflife_date", p.indexData.Diagnostics)...)
	if p.indexErr != nil {
		return out, append(ds, errorDiagnostic("endoflife_date", p.indexErr)), "SOURCE_ERROR", true
	}
	refs := p.index[id.BasePURL]
	if len(refs) == 0 {
		return out, ds, "", false
	}
	if len(refs) > 1 {
		return out, ds, "AMBIGUOUS_IDENTITY", false
	}
	ref := refs[0]
	// Reconstruct from trusted base + validated slug, never fetch an SBOM URL.
	raw := cleanBase(p.t.p.Sources.EndoflifeDate.BaseURL) + "/products/" + ref.Name + "/"
	data, err := p.t.get(ctx, raw)
	ds = append(ds, providerDiagnostics("endoflife_date", data.Diagnostics)...)
	if err != nil {
		return out, append(ds, errorDiagnostic("endoflife_date", err)), "SOURCE_ERROR", true
	}
	if data.Status == 404 {
		return out, ds, "", false
	}
	var response struct {
		SchemaVersion string      `json:"schema_version"`
		GeneratedAt   string      `json:"generated_at"`
		LastModified  *string     `json:"last_modified"`
		Result        *eolProduct `json:"result"`
	}
	if inspectJSON(data.Body, 256) != nil || json.Unmarshal(data.Body, &response) != nil || response.Result == nil ||
		!eolHeader(response.SchemaVersion, response.GeneratedAt) || response.Result.Identifiers == nil || response.Result.Releases == nil ||
		!slugPattern.MatchString(response.Result.Name) {
		p.t.invalidate(raw)
		return out, append(ds, diag("PROVIDER_SCHEMA_MISMATCH", "endoflife_date", "Product details are malformed")), "SOURCE_ERROR", true
	}
	product := response.Result
	if response.LastModified != nil {
		if modified, err := time.Parse(time.RFC3339Nano, *response.LastModified); err == nil {
			response.LastModified = ptr(stamp(modified))
		} else {
			response.LastModified = nil
		}
	}
	matches := false
	for _, i := range *product.Identifiers {
		if i.Type == "purl" {
			base, err := baseIdentity(i.ID)
			if err == nil && base == id.BasePURL {
				matches = true
			}
		}
	}
	if !matches {
		return out, append(ds, diag("PROVIDER_IDENTITY_MISMATCH", "endoflife_date", "Product details do not contain the requested PURL")), "SOURCE_ERROR", true
	}
	source := product.Links.HTML
	if !safeEvidenceURL(source) {
		return out, append(ds, diag("PROVIDER_SCHEMA_MISMATCH", "endoflife_date", "Product evidence link is not a safe HTTPS URL")), "SOURCE_ERROR", true
	}
	best := -1
	chosen := []eolRelease{}
	for _, r := range *product.Releases {
		if r.Name == "" || r.IsEOL == nil || r.IsMaintained == nil {
			return out, append(ds, diag("PROVIDER_SCHEMA_MISMATCH", "endoflife_date", "Release is missing required fields")), "SOURCE_ERROR", true
		}
		if numericCycleMatches(id.Version, r.Name) {
			n := len(strings.Split(r.Name, "."))
			if n > best {
				best = n
				chosen = []eolRelease{r}
			} else if n == best {
				chosen = append(chosen, r)
			}
		}
	}
	if len(chosen) > 1 {
		for _, r := range chosen[1:] {
			if r.Name != chosen[0].Name || textOf(r.EOLFrom) != textOf(chosen[0].EOLFrom) {
				return out, ds, "AMBIGUOUS_CYCLE", false
			}
		}
		chosen = chosen[:1]
	}
	for _, r := range chosen {
		if r.EOLFrom == nil {
			continue
		}
		if _, err := time.Parse("2006-01-02", *r.EOLFrom); err != nil {
			return out, append(ds, diag("PROVIDER_SCHEMA_MISMATCH", "endoflife_date", "Invalid EOL date")), "SOURCE_ERROR", true
		}
		var review *GeneralEolReview
		if p.bundle.Catalog != nil {
			for _, candidate := range p.bundle.Catalog.GeneralEolReviews {
				if candidate.ProductSlug == product.Name && candidate.PackagePURL == id.BasePURL && candidate.MatchedCycle == r.Name && candidate.SupportScope == "upstream_security" {
					review = ptr(candidate)
					break
				}
			}
		}
		hash := digest(data.Body)
		out = append(out, LifecycleEvidence{
			ID: "endoflife_date:" + product.Name + ":" + r.Name, ProviderID: "endoflife_date", SourceClass: "CURATED_DATABASE", Claim: "GENERAL_EOL_END",
			PackagePURL: id.BasePURL, ProductSlug: ptr(product.Name), MatchedCycle: r.Name, SupportScope: "general_eol", EOLEffectiveDate: *r.EOLFrom,
			SourceURL: source, SourceField: "releases[].eolFrom", ObservedAt: data.ObservedAt, SourceUpdatedAt: response.LastModified,
			RawPayloadHash: ptr(hash), Confidence: "MEDIUM", RuleID: "R-003", GeneralEolReview: review,
		})
		if *r.IsMaintained && *r.EOLFrom <= utcDay(p.t.now) {
			ds = append(ds, diag("SUPPORT_SCOPE_DIFFERENCE", "endoflife_date", "isMaintained may include extended support; upstream EOL date is retained"))
		}
	}
	return out, ds, "", false
}
func noVersionCapability() VersionVerification {
	return VersionVerification{Status: "UNVERIFIED", ReasonCode: ptr("NO_CAPABILITY")}
}
func publicationDiagnostic(provider string, v VersionVerification) []Diagnostic {
	if v.Status == "UNVERIFIED" {
		return []Diagnostic{diag(textOf(v.ReasonCode), provider, "Exact version publication could not be verified")}
	}
	return []Diagnostic{}
}
func describeProviders() string {
	return fmt.Sprintln("official_catalog: reviewed upstream support, exact local versions, general EOL reviews") +
		fmt.Sprintln("endoflife_date: exact PURL index and general EOL dates") +
		fmt.Sprintln("deps_dev: gem/npm/pypi/maven/golang/cargo/nuget version publication; DEPRECATED and STALE_RELEASE where metadata is sufficient")
}
