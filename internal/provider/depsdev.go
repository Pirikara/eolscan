package provider

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Pirikara/eolscan/internal/contract"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/transport"
)

type DepsKey struct {
	System  string `json:"system"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type DepsVersion struct {
	Key              DepsKey `json:"versionKey"`
	PublishedAt      string  `json:"publishedAt"`
	IsDeprecated     *bool   `json:"isDeprecated"`
	DeprecatedReason string  `json:"deprecatedReason"`
	RelatedProjects  []struct {
		Key struct {
			ID string `json:"id"`
		} `json:"projectKey"`
		Provenance string `json:"relationProvenance"`
		Type       string `json:"relationType"`
	} `json:"relatedProjects"`
	Links []struct {
		Label string `json:"label"`
		URL   string `json:"url"`
	} `json:"links"`
}

func (v DepsVersion) repositories(mappingURL string) []repositoryRef {
	refs := []repositoryRef{}
	for _, project := range v.RelatedProjects {
		if project.Type == "SOURCE_REPO" {
			refs = append(refs, repositoryRef{ProjectID: project.Key.ID, MappingURL: mappingURL, Provenance: project.Provenance})
		}
	}
	if len(refs) == 0 {
		for _, link := range v.Links {
			if link.Label == "SOURCE_REPO" {
				refs = append(refs, repositoryRef{ProjectID: githubProject(link.URL), MappingURL: mappingURL, Provenance: "UNVERIFIED_METADATA"})
			}
		}
	}
	return refs
}

type depsPackage struct {
	Key           DepsKey        `json:"packageKey"`
	Versions      *[]DepsVersion `json:"versions"`
	NextPageToken string         `json:"nextPageToken"`
}

func FetchVersion(ctx context.Context, t *transport.Transport, id identity.Identity) (DepsVersion, transport.HTTPData, error) {
	raw := identity.VersionURL(t.Policy().Sources.DepsDev.BaseURL, id)
	data, err := t.Get(ctx, raw)
	if err != nil {
		return DepsVersion{}, data, err
	}
	if data.Status == 404 {
		return DepsVersion{}, data, nil
	}
	var v DepsVersion
	if contract.InspectJSON(data.Body, 256) != nil || json.Unmarshal(data.Body, &v) != nil || v.Key.System == "" || v.Key.Name == "" || v.Key.Version == "" {
		t.Invalidate(raw)
		return v, data, &transport.LookupError{Code: "PROVIDER_SCHEMA_MISMATCH", Status: 200}
	}
	if strings.ToUpper(v.Key.System) != id.System || identity.NormalizeName(id.System, v.Key.Name) != id.Name ||
		identity.NormalizeVersion(id.System, v.Key.Version) != id.Version {
		t.Invalidate(raw)
		return v, data, &transport.LookupError{Code: "VERSION_CONFLICT", Status: 200}
	}
	return v, data, nil
}

func VerifyVersion(t *transport.Transport, id identity.Identity, v DepsVersion, data transport.HTTPData, err error, asOf string) model.VersionVerification {
	raw := identity.VersionURL(t.Policy().Sources.DepsDev.BaseURL, id)
	result := model.VersionVerification{Status: "UNVERIFIED", ProviderID: model.Ptr("deps_dev"), SourceURL: model.Ptr(raw)}
	if data.ObservedAt != "" {
		result.CheckedAt = model.Ptr(data.ObservedAt)
	}
	if err != nil {
		result.ReasonCode = model.Ptr("SOURCE_ERROR")
		if e, ok := err.(*transport.LookupError); ok {
			result.ReasonCode = model.Ptr(e.Code)
		}
		return result
	}
	if data.Status == 404 {
		result.Status = "NOT_FOUND_IN_INDEX"
		result.ReasonCode = model.Ptr("VERSION_NOT_FOUND_IN_INDEX")
		return result
	}
	return VerifyPublication("deps_dev", raw, data.ObservedAt, v.PublishedAt, asOf, t.Now())
}

func Deprecation(t *transport.Transport, id identity.Identity, v DepsVersion, data transport.HTTPData, err error) (model.SignalEvaluation, *model.SignalEvidence) {
	e := UnknownSignal("DEPRECATED", "NO_CAPABILITY")
	if err != nil {
		e.ReasonCode = model.Ptr("SOURCE_ERROR")
		return e, nil
	}
	if data.Status != 200 {
		e.ReasonCode = model.Ptr("VERSION_NOT_FOUND_IN_INDEX")
		return e, nil
	}
	raw := identity.VersionURL(t.Policy().Sources.DepsDev.BaseURL, id)
	e.ProviderID = model.Ptr("deps_dev")
	e.SourceURL = model.Ptr(raw)
	e.CheckedAt = model.Ptr(data.ObservedAt)
	// deps.dev's shared boolean does not guarantee collection of a registry's
	// negative status in every ecosystem. Explicit true is positive evidence;
	// a negative evaluation is enabled for npm and NuGet with an explicit
	// boolean, whose registries supply version deprecation markers.
	if v.IsDeprecated != nil && *v.IsDeprecated {
		e.Status = "PRESENT"
		e.ReasonCode = nil
		s := model.SignalEvidence{Type: "DEPRECATED", ProviderID: "deps_dev", SourceURL: model.Ptr(raw), ObservedAt: data.ObservedAt,
			Details: map[string]any{"deprecated_reason": v.DeprecatedReason}}
		return e, &s
	}
	if (id.Type == "npm" || id.Type == "nuget") && v.IsDeprecated != nil {
		e.Status = "ABSENT"
		e.ReasonCode = nil
	} else if id.Type == "npm" || id.Type == "nuget" {
		e.ReasonCode = model.Ptr("MISSING_DEPRECATION_STATUS")
	}
	return e, nil
}

func StaleRelease(ctx context.Context, t *transport.Transport, id identity.Identity, asOf string) (model.SignalEvaluation, *model.SignalEvidence, []model.Diagnostic) {
	e := UnknownSignal("STALE_RELEASE", "NO_CAPABILITY")
	ds := []model.Diagnostic{}
	if t.Policy().Signals.StaleReleaseDays == nil {
		return e, nil, ds
	}
	if asOf > model.UTCDate(t.Now()) {
		e.ReasonCode = model.Ptr("FUTURE_AS_OF")
		return e, nil, ds
	}
	raw := identity.PackageURL(t.Policy().Sources.DepsDev.BaseURL, id)
	data, err := t.Get(ctx, raw)
	ds = append(ds, ProviderDiagnostics("deps_dev", data.Diagnostics)...)
	if err != nil {
		e.ReasonCode = model.Ptr("SOURCE_ERROR")
		ds = append(ds, transport.ErrorDiagnostic("deps_dev", err))
		return e, nil, ds
	}
	e.ProviderID = model.Ptr("deps_dev")
	e.SourceURL = model.Ptr(raw)
	e.CheckedAt = model.Ptr(data.ObservedAt)
	if data.Status == 404 {
		e.ReasonCode = model.Ptr("PACKAGE_NOT_FOUND_IN_INDEX")
		return e, nil, ds
	}
	var p depsPackage
	if contract.InspectJSON(data.Body, 256) != nil || json.Unmarshal(data.Body, &p) != nil || p.Versions == nil || p.Key.System == "" || p.Key.Name == "" ||
		strings.ToUpper(p.Key.System) != id.System || identity.NormalizeName(id.System, p.Key.Name) != id.Name {
		t.Invalidate(raw)
		e.ReasonCode = model.Ptr("PROVIDER_SCHEMA_MISMATCH")
		ds = append(ds, model.NewDiagnostic("PROVIDER_SCHEMA_MISMATCH", "deps_dev", "Package version list is malformed or identifies another package"))
		return e, nil, ds
	}
	versions := map[string][]release{}
	seen := map[string]bool{}
	for _, v := range *p.Versions {
		if strings.ToUpper(v.Key.System) != id.System || identity.NormalizeName(id.System, v.Key.Name) != id.Name || v.Key.Version == "" || seen[v.Key.Version] {
			e.ReasonCode = model.Ptr("INCOMPLETE_VERSION_LIST")
			return e, nil, ds
		}
		seen[v.Key.Version] = true
		versions[v.Key.Version] = []release{{PublishedAt: v.PublishedAt}}
	}
	// These collections cannot prove package-wide inactivity, but a verified
	// recent publication still proves that the package is not stale.
	limitedIndex := id.Type == "golang" || id.Type == "pypi"
	latest, reason := latestRelease(versions, !limitedIndex && p.NextPageToken == "", false, asOf, t.Now(), *t.Policy().Signals.StaleReleaseDays)
	if reason != "" {
		if limitedIndex && reason == "INCOMPLETE_VERSION_LIST" {
			reason = "INCOMPLETE_VERSION_INDEX"
		}
		e.ReasonCode = model.Ptr(reason)
		return e, nil, ds
	}
	days := releaseAge(latest, asOf)
	e.Status = "ABSENT"
	e.ReasonCode = nil
	if days > *t.Policy().Signals.StaleReleaseDays {
		e.Status = "PRESENT"
		s := model.SignalEvidence{Type: "STALE_RELEASE", ProviderID: "deps_dev", SourceURL: model.Ptr(raw), ObservedAt: data.ObservedAt,
			Details: map[string]any{"latest_published_at": model.Timestamp(latest), "days_since_latest_release": days, "threshold_days": *t.Policy().Signals.StaleReleaseDays}}
		return e, &s, ds
	}
	return e, nil, ds
}
