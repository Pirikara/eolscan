package lifecycle

import (
	"time"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
)

// EvaluateEOLRules applies the caller's definition of EOL to collected facts.
// It never creates a support date or claims official support has ended merely
// because a policy classifies a maintenance finding as EOL.
func EvaluateEOLRules(r *model.ComponentResult, id identity.Identity, p model.Policy, asOf string, now time.Time) {
	r.SupportAssessment = model.SupportAssessment{
		Lifecycle: r.Lifecycle, Confidence: r.Confidence, EOLEffectiveDate: r.EOLEffectiveDate,
		MatchedCycle: r.MatchedCycle, SelectedEvidenceIDs: append([]string{}, r.SelectedEvidenceIDs...),
		UnknownReasons: append([]string{}, r.UnknownReasons...),
	}
	r.EOLRuleEvaluations = []model.EOLRuleEvaluation{}
	matched := false
	unresolved := false
	for _, rule := range config.ApplicableEOLRules(p, id) {
		evaluation := model.EOLRuleEvaluation{RuleID: rule.ID, Status: "ABSENT", MatchedSignals: []string{}, UnknownSignals: []string{}}
		absent := false
		for _, kind := range rule.Conditions() {
			status := "UNKNOWN"
			for _, signal := range r.SignalEvaluations {
				if signal.Type == kind {
					status = signal.Status
					break
				}
			}
			// Live registry/repository flags do not establish their status on a
			// different date. Release-date comparisons have their own as-of logic.
			if kind != "STALE_RELEASE" && asOf != model.UTCDate(now) {
				status = "UNKNOWN"
			}
			switch status {
			case "PRESENT":
				evaluation.MatchedSignals = append(evaluation.MatchedSignals, kind)
			case "ABSENT":
				absent = true
			default:
				evaluation.UnknownSignals = append(evaluation.UnknownSignals, kind)
			}
		}
		if len(rule.AnyOf) > 0 {
			if len(evaluation.MatchedSignals) > 0 {
				evaluation.Status = "PRESENT"
			} else if len(evaluation.UnknownSignals) > 0 {
				evaluation.Status = "UNKNOWN"
			}
		} else if !absent {
			if len(evaluation.UnknownSignals) > 0 {
				evaluation.Status = "UNKNOWN"
			} else {
				evaluation.Status = "PRESENT"
			}
		}
		if r.VersionVerification.Status != "VERIFIED" {
			evaluation.Status = "UNKNOWN"
			evaluation.ReasonCode = model.Ptr("VERSION_UNVERIFIED")
		} else if evaluation.Status == "UNKNOWN" {
			evaluation.ReasonCode = model.Ptr("CONDITION_UNAVAILABLE")
			if asOf != model.UTCDate(now) {
				evaluation.ReasonCode = model.Ptr("STATUS_TIME_UNAVAILABLE")
			}
		}
		matched = matched || evaluation.Status == "PRESENT"
		unresolved = unresolved || evaluation.Status == "UNKNOWN"
		r.EOLRuleEvaluations = append(r.EOLRuleEvaluations, evaluation)
	}
	if r.Lifecycle == "EOL" && p.Decision.UseSupportDates {
		r.EOLBasis = model.Ptr("SUPPORT_DATE")
		return
	}
	if matched {
		r.Lifecycle = "EOL"
		r.EOLBasis = model.Ptr("POLICY_RULE")
		r.Confidence = model.Ptr("MEDIUM")
		r.EOLEffectiveDate, r.MatchedCycle = nil, nil
		r.SelectedEvidenceIDs, r.Notices, r.UnknownReasons = []string{}, []model.Notice{}, []string{}
		r.RuleIDs = model.AddUnique(r.RuleIDs, "R-013")
		return
	}
	if r.Lifecycle == "EOL" { // The policy has disabled the support-date criterion.
		r.Lifecycle = "UNKNOWN"
		r.Confidence, r.EOLEffectiveDate, r.MatchedCycle = nil, nil, nil
		r.SelectedEvidenceIDs, r.Notices = []string{}, []model.Notice{}
		r.UnknownReasons = model.AddUnique(r.UnknownReasons, "SUPPORT_DATES_DISABLED")
	}
	if unresolved {
		r.Incomplete = true
		if r.Lifecycle == "SUPPORTED" {
			r.Lifecycle = "UNKNOWN"
			r.Confidence, r.EOLEffectiveDate, r.MatchedCycle = nil, nil, nil
			r.SelectedEvidenceIDs, r.Notices = []string{}, []model.Notice{}
		}
		r.UnknownReasons = model.AddUnique(r.UnknownReasons, "EOL_RULE_UNRESOLVED")
		return
	}
	// A completed rule evaluation with no match is useful information even
	// when a dependency has no published security-support window. It does
	// not certify upstream support. Unavailable or conflicting date evidence
	// still prevents a conclusive result when that criterion is enabled.
	dateUnavailable := false
	if p.Decision.UseSupportDates {
		for _, reason := range r.SupportAssessment.UnknownReasons {
			dateUnavailable = dateUnavailable || model.Contains([]string{"SOURCE_ERROR", "CONFLICT", "STALE_EVIDENCE", "AMBIGUOUS_IDENTITY", "AMBIGUOUS_CYCLE"}, reason)
		}
	}
	if r.Lifecycle == "UNKNOWN" && r.VersionVerification.Status == "VERIFIED" && !dateUnavailable &&
		(len(p.Decision.EOLRules) > 0 || !p.Decision.UseSupportDates) {
		r.Lifecycle = "NO_EOL_DETECTED"
		r.UnknownReasons = []string{}
	}
}
