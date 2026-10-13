// Package provider adapts support catalogs, registries, deps.dev, and endoflife.date.
package provider

import (
	"fmt"
	"time"

	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/transport"
)

func VerifyPublication(provider, source, checked, published, asOf string, now time.Time) model.VersionVerification {
	v := model.VersionVerification{Status: "UNVERIFIED", ProviderID: model.Ptr(provider), SourceURL: model.Ptr(source), CheckedAt: model.Ptr(checked)}
	p, err := time.Parse(time.RFC3339Nano, published)
	if err != nil {
		v.ReasonCode = model.Ptr("MISSING_PUBLICATION_DATE")
		return v
	}
	v.PublishedAt = model.Ptr(model.Timestamp(p))
	if p.After(now) {
		v.ReasonCode = model.Ptr("PUBLICATION_IN_FUTURE")
		return v
	}
	if model.UTCDate(p) > asOf {
		v.Status = "NOT_RELEASED_AS_OF"
		v.ReasonCode = model.Ptr("NOT_RELEASED_AS_OF")
		return v
	}
	v.Status = "VERIFIED"
	return v
}

func UnknownSignal(kind, reason string) model.SignalEvaluation {
	return model.SignalEvaluation{Type: kind, Status: "UNKNOWN", ReasonCode: model.Ptr(reason)}
}

func ProviderDiagnostics(provider string, ds []model.Diagnostic) []model.Diagnostic {
	out := append([]model.Diagnostic{}, ds...)
	for i := range out {
		if out[i].ProviderID == nil {
			out[i].ProviderID = model.Ptr(provider)
		}
	}
	return out
}

func NoVersionCapability() model.VersionVerification {
	return model.VersionVerification{Status: "UNVERIFIED", ReasonCode: model.Ptr("NO_CAPABILITY")}
}

func PublicationDiagnostic(provider string, v model.VersionVerification) []model.Diagnostic {
	if v.Status == "UNVERIFIED" {
		return []model.Diagnostic{model.NewDiagnostic(model.Text(v.ReasonCode), provider, "Exact version publication could not be verified")}
	}
	return []model.Diagnostic{}
}

func DescribeProviders() string {
	return fmt.Sprintln("official_catalog: reviewed upstream support, exact local versions, general EOL reviews") +
		fmt.Sprintln("endoflife_date: automatic exact-PURL lifecycle lookup; explicit security end dates (MEDIUM) and general EOL evidence") +
		fmt.Sprintln("npm: exact versions and publication; DEPRECATED and STALE_RELEASE") +
		fmt.Sprintln("pypi: Index API publication; DEPRECATED, ARCHIVED, QUARANTINED, YANKED, and STALE_RELEASE") +
		fmt.Sprintln("rubygems: exact versions and publication; YANKED where explicit, and STALE_RELEASE") +
		fmt.Sprintln("github: source-repository ARCHIVED; publisher metadata or verified origin maps a package version to its repository") +
		fmt.Sprintln("deps_dev: gem/npm/pypi/maven/golang/cargo/nuget version publication; DEPRECATED and STALE_RELEASE where metadata is sufficient")
}

func NewEOL(t *transport.Transport, bundle model.PolicyBundle) *EOLProvider {
	return &EOLProvider{t: t, bundle: bundle}
}
