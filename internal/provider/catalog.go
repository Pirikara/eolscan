package provider

import (
	"strings"
	"time"

	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
)

func CatalogEvidence(bundle model.PolicyBundle, id identity.Identity, now time.Time) []model.LifecycleEvidence {
	out := []model.LifecycleEvidence{}
	if bundle.Catalog == nil {
		return out
	}
	// Select the most specific numeric mapping, while exact mappings have
	// precedence for prereleases or named/date cycles.
	best := -1
	exact := false
	for _, e := range bundle.Catalog.Entries {
		if e.PackagePURL != id.BasePURL {
			continue
		}
		if e.Match == "exact_versions" && model.Contains(e.Versions, id.Version) {
			exact = true
		}
		if e.Match == "numeric_segment_prefix" && identity.NumericSegmentsMatch(identity.SeriesVersion(id), e.MatchedCycle) {
			n := len(strings.Split(e.MatchedCycle, "."))
			if n > best {
				best = n
			}
		}
	}
	for _, e := range bundle.Catalog.Entries {
		if e.PackagePURL != id.BasePURL {
			continue
		}
		applies := e.Match == "exact_versions" && model.Contains(e.Versions, id.Version)
		if !exact {
			applies = e.Match == "numeric_segment_prefix" && identity.NumericSegmentsMatch(identity.SeriesVersion(id), e.MatchedCycle) && len(strings.Split(e.MatchedCycle, ".")) == best
		}
		if !applies {
			continue
		}
		rule := "R-001"
		if e.Claim == "UPSTREAM_SECURITY_WINDOW" {
			rule = "R-002"
		}
		out = append(out, model.LifecycleEvidence{
			ID: e.ID, ProviderID: "official_catalog", SourceClass: "OFFICIAL", Claim: e.Claim, PackagePURL: id.BasePURL,
			MatchedCycle: e.MatchedCycle, SupportScope: e.SupportScope, SupportStartDate: e.SupportStartDate,
			EOLEffectiveDate: e.EOLEffectiveDate, SourceURL: e.EvidenceURL, SourceField: "entries[].eol_effective_date",
			ObservedAt: model.Timestamp(now), ReviewedAt: model.Ptr(e.ReviewedAt), ValidUntil: model.Ptr(e.ValidUntil),
			RawPayloadHash: model.Ptr(bundle.CatalogHash), Confidence: "HIGH", RuleID: rule,
			SupersededBy: e.SupersededBy, SupersessionSourceURL: e.SupersessionSourceURL,
		})
	}
	return out
}

func LocalVersion(bundle model.PolicyBundle, id identity.Identity, asOf string, now time.Time) (model.VersionVerification, bool, []model.Diagnostic) {
	ds := []model.Diagnostic{}
	if bundle.Catalog == nil || !model.Contains(bundle.Policy.VersionVerification.Sources, "official_catalog") {
		return model.VersionVerification{}, false, ds
	}
	for _, a := range bundle.Catalog.VerifiedVersions {
		if a.PackagePURL != id.PURL {
			continue
		}
		if !model.Active(a.ReviewedAt, a.ValidUntil, model.UTCDate(now)) {
			ds = append(ds, model.NewDiagnostic("STALE_EVIDENCE", "official_catalog", "Local version assertion is expired or not yet reviewed"))
			continue
		}
		return VerifyPublication("official_catalog", a.SourceURL, model.Timestamp(now), a.PublishedAt, asOf, now), true, ds
	}
	return model.VersionVerification{}, false, ds
}
