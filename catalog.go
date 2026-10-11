package main

import (
	"fmt"
	"strings"
	"time"
)

func validateCatalog(c Catalog) error {
	entries := map[string]CatalogEntry{}
	assertions := map[string]bool{}
	reviews := map[string]bool{}
	targets := map[string]bool{}
	for _, e := range c.Entries {
		if strings.HasPrefix(e.ID, "endoflife_date:") {
			return fmt.Errorf("catalog entry ID uses a reserved provider prefix")
		}
		if _, ok := entries[e.ID]; ok {
			return fmt.Errorf("duplicate catalog entry ID %q", e.ID)
		}
		base, err := baseIdentity(e.PackagePURL)
		if err != nil || base != e.PackagePURL {
			return fmt.Errorf("catalog entry requires a canonical versionless PURL")
		}
		if !safeEvidenceURL(e.EvidenceURL) || !safeEvidenceURLOrNil(e.SupersessionSourceURL) {
			return fmt.Errorf("catalog evidence URL must be HTTPS without credentials or query")
		}
		if e.ReviewedAt > e.ValidUntil {
			return fmt.Errorf("catalog review follows expiry")
		}
		if e.SupportStartDate != nil && *e.SupportStartDate >= e.EOLEffectiveDate {
			return fmt.Errorf("support window must have positive duration")
		}
		for _, v := range e.Versions {
			id, reason := resolveIdentity(Component{PURL: e.PackagePURL + "@" + v})
			if reason != "" || id.Version != v {
				return fmt.Errorf("exact_versions requires exact canonical versions")
			}
		}
		entries[e.ID] = e
	}
	for _, a := range c.VerifiedVersions {
		id, reason := resolveIdentity(Component{PURL: a.PackagePURL})
		if reason != "" || id.PURL != a.PackagePURL {
			return fmt.Errorf("version assertion requires a canonical exact PURL")
		}
		if assertions[id.PURL] {
			return fmt.Errorf("duplicate version assertion")
		}
		assertions[id.PURL] = true
		published, _ := time.Parse(time.RFC3339Nano, a.PublishedAt)
		if a.ReviewedAt > a.ValidUntil || utcDay(published) > a.ReviewedAt {
			return fmt.Errorf("invalid assertion review/publication/expiry order")
		}
		if !safeEvidenceURL(a.SourceURL) {
			return fmt.Errorf("version assertion URL must be HTTPS without credentials or query")
		}
	}
	for _, r := range c.GeneralEolReviews {
		if reviews[r.ID] {
			return fmt.Errorf("duplicate general EOL review ID")
		}
		reviews[r.ID] = true
		base, err := baseIdentity(r.PackagePURL)
		if err != nil || base != r.PackagePURL {
			return fmt.Errorf("review requires canonical versionless PURL")
		}
		if strings.ContainsAny(r.ProductSlug+r.MatchedCycle, "*?") {
			return fmt.Errorf("wildcard general EOL reviews are prohibited")
		}
		key := r.ProductSlug + "\x00" + base + "\x00" + r.MatchedCycle + "\x00" + r.SupportScope
		if targets[key] {
			return fmt.Errorf("duplicate general EOL review target")
		}
		targets[key] = true
		if r.ReviewedAt > r.ValidUntil || !safeEvidenceURL(r.EvidenceURL) {
			return fmt.Errorf("invalid general EOL review dates or URL")
		}
	}
	for _, e := range c.Entries {
		seen := map[string]bool{e.ID: true}
		next := e.SupersededBy
		for next != nil {
			t, ok := entries[*next]
			if !ok || seen[*next] {
				return fmt.Errorf("supersession has a missing target or cycle")
			}
			if t.PackagePURL != e.PackagePURL || t.MatchedCycle != e.MatchedCycle || t.SupportScope != e.SupportScope ||
				t.Match != e.Match || strings.Join(t.Versions, "\x00") != strings.Join(e.Versions, "\x00") {
				return fmt.Errorf("supersession must have identical applicability")
			}
			seen[*next] = true
			next = t.SupersededBy
		}
	}
	return nil
}
func safeEvidenceURLOrNil(v *string) bool { return v == nil || safeEvidenceURL(*v) }

func catalogEvidence(bundle PolicyBundle, id Identity, now time.Time) []LifecycleEvidence {
	out := []LifecycleEvidence{}
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
		if e.Match == "exact_versions" && has(e.Versions, id.Version) {
			exact = true
		}
		if e.Match == "numeric_segment_prefix" && numericSegmentsMatch(id.Version, e.MatchedCycle) {
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
		applies := e.Match == "exact_versions" && has(e.Versions, id.Version)
		if !exact {
			applies = e.Match == "numeric_segment_prefix" && numericSegmentsMatch(id.Version, e.MatchedCycle) && len(strings.Split(e.MatchedCycle, ".")) == best
		}
		if !applies {
			continue
		}
		rule := "R-001"
		if e.Claim == "UPSTREAM_SECURITY_WINDOW" {
			rule = "R-002"
		}
		out = append(out, LifecycleEvidence{
			ID: e.ID, ProviderID: "official_catalog", SourceClass: "OFFICIAL", Claim: e.Claim, PackagePURL: id.BasePURL,
			MatchedCycle: e.MatchedCycle, SupportScope: e.SupportScope, SupportStartDate: e.SupportStartDate,
			EOLEffectiveDate: e.EOLEffectiveDate, SourceURL: e.EvidenceURL, SourceField: "entries[].eol_effective_date",
			ObservedAt: stamp(now), ReviewedAt: ptr(e.ReviewedAt), ValidUntil: ptr(e.ValidUntil),
			RawPayloadHash: ptr(bundle.CatalogHash), Confidence: "HIGH", RuleID: rule,
			SupersededBy: e.SupersededBy, SupersessionSourceURL: e.SupersessionSourceURL,
		})
	}
	return out
}
func localVersion(bundle PolicyBundle, id Identity, asOf string, now time.Time) (VersionVerification, bool, []Diagnostic) {
	ds := []Diagnostic{}
	if bundle.Catalog == nil || !has(bundle.Policy.VersionVerification.Sources, "official_catalog") {
		return VersionVerification{}, false, ds
	}
	for _, a := range bundle.Catalog.VerifiedVersions {
		if a.PackagePURL != id.PURL {
			continue
		}
		if !active(a.ReviewedAt, a.ValidUntil, utcDay(now)) {
			ds = append(ds, diag("STALE_EVIDENCE", "official_catalog", "Local version assertion is expired or not yet reviewed"))
			continue
		}
		return verificationFromPublication("official_catalog", a.SourceURL, stamp(now), a.PublishedAt, asOf, now), true, ds
	}
	return VersionVerification{}, false, ds
}
