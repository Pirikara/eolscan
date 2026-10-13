package provider

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/Pirikara/eolscan/internal/contract"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/transport"
)

type release struct {
	PublishedAt string
	Platform    string
	Deprecated  *bool
	Yanked      *bool
	Reason      string
}

// packageSnapshot is immutable after parsing and shared across all SBOM
// versions of a package. Completeness refers to the available release list,
// not a reconstruction of releases removed from the registry.
type packageSnapshot struct {
	Provider, URL, ProjectStatus string
	Data                         transport.HTTPData
	Versions                     map[string][]release
	Complete                     bool
	UnassignedArtifacts          bool
	Repositories                 map[string][]repositoryRef
}

type registry struct {
	t        *transport.Transport
	mu       sync.Mutex
	packages map[string]func() (packageSnapshot, error)
}

func newRegistry(t *transport.Transport) *registry {
	return &registry{t: t, packages: map[string]func() (packageSnapshot, error){}}
}

func (r *registry) enabled(id identity.Identity) bool {
	p := r.t.Policy()
	switch id.Type {
	case "npm":
		return p.Sources.NPM.Enabled
	case "pypi":
		return p.Sources.PyPI.Enabled
	case "gem":
		return p.Sources.RubyGems.Enabled
	}
	return false
}

func (r *registry) load(ctx context.Context, id identity.Identity) (packageSnapshot, error) {
	key := id.BasePURL
	r.mu.Lock()
	read := r.packages[key]
	if read == nil {
		read = sync.OnceValues(func() (packageSnapshot, error) {
			switch id.Type {
			case "npm":
				return r.npm(ctx, id)
			case "pypi":
				return r.pypi(ctx, id)
			case "gem":
				return r.rubygems(ctx, id)
			}
			return packageSnapshot{}, &transport.LookupError{Code: "NO_CAPABILITY"}
		})
		r.packages[key] = read
	}
	r.mu.Unlock()
	return read()
}

func (r *registry) decode(ctx context.Context, raw, accept string, out any) (transport.HTTPData, error) {
	data, err := r.t.GetWithAccept(ctx, raw, accept)
	if err != nil || data.Status != 200 {
		return data, err
	}
	if contract.InspectJSON(data.Body, 256) != nil || json.Unmarshal(data.Body, out) != nil {
		r.t.InvalidateWithAccept(raw, accept)
		return data, &transport.LookupError{Code: "PROVIDER_SCHEMA_MISMATCH", Status: 200}
	}
	return data, nil
}

func (r *registry) mismatch(s packageSnapshot, accept string) (packageSnapshot, error) {
	r.t.InvalidateWithAccept(s.URL, accept)
	return s, &transport.LookupError{Code: "PROVIDER_SCHEMA_MISMATCH", Status: 200}
}

func (s packageSnapshot) records(id identity.Identity) []release {
	all := s.Versions[id.Version]
	if id.Platform == "" {
		return all
	}
	matched := []release{}
	for _, v := range all {
		if v.Platform == id.Platform {
			matched = append(matched, v)
		}
	}
	return matched
}

func (s packageSnapshot) verify(id identity.Identity, asOf string, now time.Time, err error) model.VersionVerification {
	v := model.VersionVerification{Status: "UNVERIFIED", ProviderID: model.Nullable(s.Provider), SourceURL: model.Nullable(s.URL), CheckedAt: model.Nullable(s.Data.ObservedAt)}
	if err != nil {
		v.ReasonCode = model.Ptr("SOURCE_ERROR")
		if e, ok := err.(*transport.LookupError); ok {
			v.ReasonCode = model.Ptr(e.Code)
		}
		return v
	}
	records := s.records(id)
	if len(records) == 0 {
		v.Status, v.ReasonCode = "NOT_FOUND_IN_INDEX", model.Ptr("VERSION_NOT_FOUND_IN_INDEX")
		return v
	}
	var earliest time.Time
	for _, item := range records {
		at, err := time.Parse(time.RFC3339Nano, item.PublishedAt)
		if err == nil && (earliest.IsZero() || at.Before(earliest)) {
			earliest = at
		}
	}
	if earliest.IsZero() {
		v.ReasonCode = model.Ptr("MISSING_PUBLICATION_DATE")
		return v
	}
	return VerifyPublication(s.Provider, s.URL, s.Data.ObservedAt, model.Timestamp(earliest), asOf, now)
}

func (s packageSnapshot) evaluation(kind, status, reason string) model.SignalEvaluation {
	return model.SignalEvaluation{Type: kind, Status: status, ReasonCode: model.Nullable(reason), ProviderID: model.Nullable(s.Provider), SourceURL: model.Nullable(s.URL), CheckedAt: model.Nullable(s.Data.ObservedAt)}
}

func (s packageSnapshot) signal(kind string, id identity.Identity, asOf string, t *transport.Transport, err error) (model.SignalEvaluation, *model.SignalEvidence) {
	unknown := func(reason string) (model.SignalEvaluation, *model.SignalEvidence) {
		return s.evaluation(kind, "UNKNOWN", reason), nil
	}
	if err != nil {
		return unknown("SOURCE_ERROR")
	}
	if s.Data.Status != 200 {
		return unknown("PACKAGE_NOT_FOUND_IN_INDEX")
	}
	positive := false
	details := map[string]any{}
	switch kind {
	case "DEPRECATED":
		if s.Provider == "pypi" {
			if s.ProjectStatus == "" {
				return unknown("MISSING_PROJECT_STATUS")
			}
			positive = s.ProjectStatus == "deprecated"
			details["project_status"] = s.ProjectStatus
		} else if s.Provider == "npm" {
			vs := s.records(id)
			if len(vs) == 0 {
				return unknown("VERSION_NOT_FOUND_IN_INDEX")
			}
			if vs[0].Deprecated == nil {
				return unknown("MISSING_DEPRECATION_STATUS")
			}
			positive = *vs[0].Deprecated
			details["deprecated_reason"] = vs[0].Reason
		} else {
			return unknown("NO_CAPABILITY")
		}
	case "ARCHIVED", "QUARANTINED":
		if s.Provider != "pypi" {
			return unknown("NO_CAPABILITY")
		}
		if s.ProjectStatus == "" {
			return unknown("MISSING_PROJECT_STATUS")
		}
		positive = kind == "ARCHIVED" && s.ProjectStatus == "archived" || kind == "QUARANTINED" && s.ProjectStatus == "quarantined"
		details["project_status"] = s.ProjectStatus
	case "YANKED":
		if s.Provider != "pypi" && s.Provider != "rubygems" {
			return unknown("NO_CAPABILITY")
		}
		vs := s.records(id)
		if len(vs) == 0 {
			return unknown("VERSION_NOT_FOUND_IN_INDEX")
		}
		positive = true
		unknownCount := 0
		reasons := []string{}
		for _, v := range vs {
			if v.Yanked == nil {
				unknownCount++
			} else if !*v.Yanked {
				positive = false
			}
			if v.Yanked != nil && *v.Yanked && v.Reason != "" {
				reasons = model.AddUnique(reasons, v.Reason)
			}
		}
		if positive && unknownCount > 0 {
			return unknown("MISSING_YANK_STATUS")
		}
		if positive && s.Provider == "pypi" && !s.Complete {
			return unknown("INCOMPLETE_ARTIFACT_LIST")
		}
		details["scope"] = "all_available_artifacts_for_version"
		details["artifact_count"] = len(vs)
		if len(reasons) > 0 {
			sort.Strings(reasons)
			details["yanked_reasons"] = reasons
		}
	case "STALE_RELEASE":
		if t.Policy().Signals.StaleReleaseDays == nil {
			return unknown("NO_CAPABILITY")
		}
		if asOf > model.UTCDate(t.Now()) {
			return unknown("FUTURE_AS_OF")
		}
		latest, reason := latestRelease(s.Versions, s.Complete, s.UnassignedArtifacts, asOf, t.Now(), *t.Policy().Signals.StaleReleaseDays)
		if reason != "" {
			return unknown(reason)
		}
		days := releaseAge(latest, asOf)
		positive = days > *t.Policy().Signals.StaleReleaseDays
		details["latest_published_at"], details["days_since_latest_release"], details["threshold_days"] = model.Timestamp(latest), days, *t.Policy().Signals.StaleReleaseDays
	default:
		return unknown("NO_CAPABILITY")
	}
	if !positive {
		return s.evaluation(kind, "ABSENT", ""), nil
	}
	return s.evaluation(kind, "PRESENT", ""), &model.SignalEvidence{Type: kind, ProviderID: s.Provider, SourceURL: model.Ptr(s.URL), ObservedAt: s.Data.ObservedAt, Details: details}
}
