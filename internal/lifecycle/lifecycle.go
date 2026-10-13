// Package lifecycle evaluates support evidence and maintenance signals without I/O.
package lifecycle

import (
	"sort"
	"time"

	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
)

func Evaluate(r *model.ComponentResult, id identity.Identity, p model.Policy, asOf string, now time.Time) {
	eligible := []model.LifecycleEvidence{}
	reasons := []string{}
	byID := map[string]model.LifecycleEvidence{}
	for _, e := range r.Evidence {
		byID[e.ID] = e
	}
	for _, e := range r.Evidence {
		if e.PackagePURL != id.BasePURL {
			continue
		}
		if e.SourceClass == "OFFICIAL" {
			if e.ReviewedAt == nil || e.ValidUntil == nil || !model.Active(model.Text(e.ReviewedAt), model.Text(e.ValidUntil), model.UTCDate(now)) {
				reasons = model.AddUnique(reasons, "STALE_EVIDENCE")
				r.Diagnostics = append(r.Diagnostics, model.NewDiagnostic("STALE_EVIDENCE", e.ProviderID, "Official support evidence is expired or not yet reviewed"))
				continue
			}
		} else {
			observed, err := time.Parse(time.RFC3339Nano, e.ObservedAt)
			if err != nil || observed.After(now) || now.Sub(observed).Hours()/24 > float64(p.Decision.MaxEvidenceAgeDays) {
				reasons = model.AddUnique(reasons, "STALE_EVIDENCE")
				continue
			}
			if e.Claim == "CURATED_SECURITY_END" {
				if !p.Sources.EndoflifeDate.UseSecuritySupportLabel || e.ProviderID != "endoflife_date" ||
					e.SourceField != "releases[].eolFrom" || !model.SecuritySupportLabel(model.Text(e.SourceLabel)) ||
					e.SupportScope != "upstream_security" || e.ProductSlug == nil || e.Confidence != "MEDIUM" {
					reasons = model.AddUnique(reasons, "SECURITY_SCOPE_UNCONFIRMED")
					continue
				}
			} else {
				review := e.GeneralEolReview
				if review == nil || review.PackagePURL != id.BasePURL || e.ProductSlug == nil || review.ProductSlug != *e.ProductSlug ||
					review.MatchedCycle != e.MatchedCycle || review.SupportScope != "upstream_security" ||
					!model.Active(review.ReviewedAt, review.ValidUntil, model.UTCDate(now)) {
					reasons = model.AddUnique(reasons, "GENERAL_EOL_UNREVIEWED")
					if review != nil {
						r.Diagnostics = append(r.Diagnostics, model.NewDiagnostic("STALE_EVIDENCE", e.ProviderID, "General EOL review is expired, future or does not match"))
					}
					continue
				}
			}
		}
		if e.SupersededBy != nil && e.SupersessionSourceURL != nil {
			replacement, exists := byID[*e.SupersededBy]
			// A formally withdrawn claim does not become valid again when the
			// replacement expires. The reviewed withdrawal record itself and an
			// existing replacement with identical applicability supply the proof.
			if exists && replacement.PackagePURL == e.PackagePURL && replacement.MatchedCycle == e.MatchedCycle &&
				replacement.SupportScope == e.SupportScope {
				r.Diagnostics = append(r.Diagnostics, model.NewDiagnostic("EVIDENCE_SUPERSEDED", e.ProviderID, "Officially superseded evidence retained for audit"))
				continue
			}
		}
		eligible = append(eligible, e)
	}
	// Equivalent claims from one primary source do not count as independent
	// evidence. Choose a stable ID after freshness and applicability checks.
	sort.Slice(eligible, func(i, j int) bool { return eligible[i].ID < eligible[j].ID })
	unique := []model.LifecycleEvidence{}
	seen := map[string]bool{}
	for _, e := range eligible {
		key := e.SourceClass + "\x00" + e.SourceURL + "\x00" + e.PackagePURL + "\x00" + e.MatchedCycle + "\x00" + e.Claim + "\x00" + e.EOLEffectiveDate + "\x00" + model.Text(e.SupportStartDate)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, e)
		}
	}
	eligible = unique
	tier := ""
	for _, e := range eligible {
		if e.SourceClass == "OFFICIAL" {
			tier = "OFFICIAL"
			break
		}
		tier = "CURATED_DATABASE"
	}
	top := []model.LifecycleEvidence{}
	for _, e := range eligible {
		if e.SourceClass == tier {
			top = append(top, e)
		}
	}
	conflict := false
	if len(top) > 0 {
		end := top[0].EOLEffectiveDate
		start := ""
		cycle := top[0].MatchedCycle
		for _, e := range top {
			if e.MatchedCycle != cycle {
				r.UnknownReasons = model.AddUnique(r.UnknownReasons, "AMBIGUOUS_CYCLE")
			}
			if e.EOLEffectiveDate != end {
				conflict = true
			}
			if e.Claim == "UPSTREAM_SECURITY_WINDOW" {
				if start != "" && start != model.Text(e.SupportStartDate) {
					conflict = true
				}
				start = model.Text(e.SupportStartDate)
			}
		}
		disagree := false
		for _, e := range eligible {
			if e.SourceClass != tier && e.EOLEffectiveDate != end {
				disagree = true
			}
		}
		if disagree {
			r.Diagnostics = append(r.Diagnostics, model.NewDiagnostic("SOURCE_DISAGREEMENT", "", "Lower tier evidence disagrees with official evidence"))
			r.RuleIDs = model.AddUnique(r.RuleIDs, "R-008")
		}
	}
	if conflict {
		r.Diagnostics = append(r.Diagnostics, model.NewDiagnostic("CONFLICT", "", "Highest tier support dates conflict, including future dates"))
		r.RuleIDs = model.AddUnique(r.RuleIDs, "R-007")
	}
	if r.VersionVerification.Status != "VERIFIED" {
		switch r.VersionVerification.Status {
		case "NOT_FOUND_IN_INDEX":
			r.UnknownReasons = model.AddUnique(r.UnknownReasons, "VERSION_NOT_FOUND_IN_INDEX")
		case "NOT_RELEASED_AS_OF":
			r.UnknownReasons = model.AddUnique(r.UnknownReasons, "NOT_RELEASED_AS_OF")
		default:
			code := model.Text(r.VersionVerification.ReasonCode)
			if code == "PUBLICATION_IN_FUTURE" || code == "VERSION_CONFLICT" {
				r.UnknownReasons = model.AddUnique(r.UnknownReasons, code)
			} else {
				r.UnknownReasons = model.AddUnique(r.UnknownReasons, "VERSION_UNVERIFIED")
			}
		}
		r.RuleIDs = model.AddUnique(r.RuleIDs, "R-011")
		if conflict {
			r.UnknownReasons = model.AddUnique(r.UnknownReasons, "CONFLICT")
		}
		return
	}
	if conflict {
		r.UnknownReasons = model.AddUnique(r.UnknownReasons, "CONFLICT")
		return
	}
	if model.Contains(r.UnknownReasons, "AMBIGUOUS_CYCLE") || model.Contains(r.UnknownReasons, "AMBIGUOUS_IDENTITY") {
		r.RuleIDs = model.AddUnique(r.RuleIDs, "R-006")
		return
	}
	if len(top) == 0 {
		for _, reason := range reasons {
			r.UnknownReasons = model.AddUnique(r.UnknownReasons, reason)
		}
		if len(r.UnknownReasons) == 0 {
			r.UnknownReasons = append(r.UnknownReasons, "NO_LIFECYCLE_EVIDENCE")
		}
		r.RuleIDs = model.AddUnique(r.RuleIDs, "R-006")
		return
	}
	end := top[0].EOLEffectiveDate
	if asOf >= end {
		r.Lifecycle = "EOL"
		r.Confidence = model.Ptr(top[0].Confidence)
		if tier == "OFFICIAL" {
			r.RuleIDs = model.AddUnique(r.RuleIDs, "R-001")
		} else if top[0].Claim == "CURATED_SECURITY_END" {
			r.RuleIDs = model.AddUnique(r.RuleIDs, "R-012")
		} else {
			r.RuleIDs = model.AddUnique(r.RuleIDs, "R-003")
		}
	} else {
		for _, e := range top {
			if e.Claim == "UPSTREAM_SECURITY_WINDOW" && e.SupportStartDate != nil && *e.SupportStartDate <= asOf {
				r.Lifecycle = "SUPPORTED"
				r.Confidence = model.Ptr("HIGH")
				r.RuleIDs = model.AddUnique(r.RuleIDs, "R-002")
				break
			}
		}
	}
	if r.Lifecycle == "UNKNOWN" {
		reason := "NO_LIFECYCLE_EVIDENCE"
		if tier == "CURATED_DATABASE" {
			reason = "GENERAL_EOL_ONLY"
			if top[0].Claim == "CURATED_SECURITY_END" {
				reason = "SECURITY_END_ONLY"
			}
		}
		r.UnknownReasons = model.AddUnique(r.UnknownReasons, reason)
		r.RuleIDs = model.AddUnique(r.RuleIDs, "R-006")
		return
	}
	r.UnknownReasons = []string{}
	r.EOLEffectiveDate = model.Ptr(end)
	r.MatchedCycle = model.Ptr(top[0].MatchedCycle)
	// Retain all independent eligible top claims for EOL; continued support is
	// justified specifically by the explicit security window(s).
	sort.Slice(top, func(i, j int) bool { return top[i].ID < top[j].ID })
	for _, e := range top {
		if r.Lifecycle == "SUPPORTED" && e.Claim != "UPSTREAM_SECURITY_WINDOW" {
			continue
		}
		r.SelectedEvidenceIDs = model.AddUnique(r.SelectedEvidenceIDs, e.ID)
	}
	if r.Lifecycle == "SUPPORTED" {
		a, _ := time.Parse("2006-01-02", asOf)
		e, _ := time.Parse("2006-01-02", end)
		days := int(e.Sub(a).Hours() / 24)
		if days > 0 && days <= p.Notices.EOLSoonDays {
			r.Notices = append(r.Notices, model.Notice{Type: "EOL_SOON", DaysRemaining: days, EvidenceID: r.SelectedEvidenceIDs[0], RuleID: "R-009"})
			r.RuleIDs = model.AddUnique(r.RuleIDs, "R-009")
		}
	}
}
