package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
)

func ValidateCatalog(c model.Catalog) error {
	entries := map[string]model.CatalogEntry{}
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
		base, err := identity.Base(e.PackagePURL)
		if err != nil || base != e.PackagePURL {
			return fmt.Errorf("catalog entry requires a canonical versionless PURL")
		}
		if !SafeEvidenceURL(e.EvidenceURL) || !safeEvidenceURLOrNil(e.SupersessionSourceURL) {
			return fmt.Errorf("catalog evidence URL must be HTTPS without credentials or query")
		}
		if e.ReviewedAt > e.ValidUntil {
			return fmt.Errorf("catalog review follows expiry")
		}
		if e.SupportStartDate != nil && *e.SupportStartDate >= e.EOLEffectiveDate {
			return fmt.Errorf("support window must have positive duration")
		}
		for _, v := range e.Versions {
			id, reason := identity.Resolve(model.Component{PURL: e.PackagePURL + "@" + v})
			if reason != "" || id.Version != v {
				return fmt.Errorf("exact_versions requires exact canonical versions")
			}
		}
		entries[e.ID] = e
	}
	for _, a := range c.VerifiedVersions {
		id, reason := identity.Resolve(model.Component{PURL: a.PackagePURL})
		if reason != "" || id.PURL != a.PackagePURL {
			return fmt.Errorf("version assertion requires a canonical exact PURL")
		}
		if assertions[id.PURL] {
			return fmt.Errorf("duplicate version assertion")
		}
		assertions[id.PURL] = true
		published, _ := time.Parse(time.RFC3339Nano, a.PublishedAt)
		if a.ReviewedAt > a.ValidUntil || model.UTCDate(published) > a.ReviewedAt {
			return fmt.Errorf("invalid assertion review/publication/expiry order")
		}
		if !SafeEvidenceURL(a.SourceURL) {
			return fmt.Errorf("version assertion URL must be HTTPS without credentials or query")
		}
	}
	for _, r := range c.GeneralEolReviews {
		if reviews[r.ID] {
			return fmt.Errorf("duplicate general EOL review ID")
		}
		reviews[r.ID] = true
		base, err := identity.Base(r.PackagePURL)
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
		if r.ReviewedAt > r.ValidUntil || !SafeEvidenceURL(r.EvidenceURL) {
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

func safeEvidenceURLOrNil(v *string) bool { return v == nil || SafeEvidenceURL(*v) }
