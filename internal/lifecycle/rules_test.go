package lifecycle_test

import (
	"testing"
	"time"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/lifecycle"
	"github.com/Pirikara/eolscan/internal/model"
)

func TestEOLConditionsUseThreeValuedLogic(t *testing.T) {
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	id, _ := identity.Resolve(model.Component{PURL: "pkg:npm/transitive-leaf@1.0.0"})
	for _, tc := range []struct {
		name, operator, first, second, ruleStatus, lifecycle string
		incomplete                                           bool
	}{
		{"any_positive_unknown", "any", "PRESENT", "UNKNOWN", "PRESENT", "EOL", false},
		{"any_negative_unknown", "any", "ABSENT", "UNKNOWN", "UNKNOWN", "UNKNOWN", true},
		{"any_two_negatives", "any", "ABSENT", "ABSENT", "ABSENT", "NO_EOL_DETECTED", false},
		{"all_two_positives", "all", "PRESENT", "PRESENT", "PRESENT", "EOL", false},
		{"all_positive_unknown", "all", "PRESENT", "UNKNOWN", "UNKNOWN", "UNKNOWN", true},
		{"all_negative_unknown", "all", "ABSENT", "UNKNOWN", "ABSENT", "NO_EOL_DETECTED", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := config.Default()
			rule := model.EOLRule{ID: "custom"}
			if tc.operator == "any" {
				rule.AnyOf = []string{"DEPRECATED", "ARCHIVED"}
			} else {
				rule.AllOf = []string{"DEPRECATED", "ARCHIVED"}
			}
			p.Decision.EOLRules = []model.EOLRule{rule}
			r := model.ComponentResult{Lifecycle: "UNKNOWN", VersionVerification: model.VersionVerification{Status: "VERIFIED"},
				UnknownReasons: []string{"NO_LIFECYCLE_EVIDENCE"}, SignalEvaluations: []model.SignalEvaluation{{Type: "DEPRECATED", Status: tc.first}, {Type: "ARCHIVED", Status: tc.second}}}
			lifecycle.EvaluateEOLRules(&r, id, p, "2026-10-13", now)
			if r.Lifecycle != tc.lifecycle || r.EOLRuleEvaluations[0].Status != tc.ruleStatus || r.Incomplete != tc.incomplete {
				t.Fatalf("result: %+v", r)
			}
			if r.Lifecycle == "EOL" && (model.Text(r.EOLBasis) != "POLICY_RULE" || r.EOLEffectiveDate != nil || len(r.UnknownReasons) != 0) {
				t.Fatalf("policy EOL fabricated a date: %+v", r)
			}
			if r.SupportAssessment.Lifecycle != "UNKNOWN" {
				t.Fatal("policy EOL became an official support conclusion")
			}
		})
	}
}

func TestEOLRuleScopesVersionAndEvaluationDate(t *testing.T) {
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	id, _ := identity.Resolve(model.Component{PURL: "pkg:gem/transitive-leaf@1.0.0"})
	for _, tc := range []struct {
		name, verification, asOf, want string
		rule                           model.EOLRule
		evaluations                    int
	}{
		{"unverified", "UNVERIFIED", "2026-10-13", "UNKNOWN", model.EOLRule{ID: "archived", AnyOf: []string{"ARCHIVED"}}, 1},
		{"historical_flag", "VERIFIED", "2026-10-12", "UNKNOWN", model.EOLRule{ID: "archived", AnyOf: []string{"ARCHIVED"}}, 1},
		{"future_flag", "VERIFIED", "2026-10-14", "UNKNOWN", model.EOLRule{ID: "archived", AnyOf: []string{"ARCHIVED"}}, 1},
		{"ecosystem_scope", "VERIFIED", "2026-10-13", "NO_EOL_DETECTED", model.EOLRule{ID: "archived", AnyOf: []string{"ARCHIVED"}, Ecosystems: []string{"npm"}}, 0},
		{"base_package_scope", "VERIFIED", "2026-10-13", "EOL", model.EOLRule{ID: "archived", AnyOf: []string{"ARCHIVED"}, Packages: []string{"pkg:gem/transitive-leaf"}}, 1},
		{"exact_version_scope", "VERIFIED", "2026-10-13", "NO_EOL_DETECTED", model.EOLRule{ID: "archived", AnyOf: []string{"ARCHIVED"}, Packages: []string{"pkg:gem/transitive-leaf@2.0.0"}}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := config.Default()
			p.Decision.EOLRules = []model.EOLRule{tc.rule}
			r := model.ComponentResult{Lifecycle: "UNKNOWN", VersionVerification: model.VersionVerification{Status: tc.verification}, UnknownReasons: []string{"NO_LIFECYCLE_EVIDENCE"}, SignalEvaluations: []model.SignalEvaluation{{Type: "ARCHIVED", Status: "PRESENT"}}}
			lifecycle.EvaluateEOLRules(&r, id, p, tc.asOf, now)
			if r.Lifecycle != tc.want || len(r.EOLRuleEvaluations) != tc.evaluations {
				t.Fatalf("result: %+v", r)
			}
		})
	}
}

func TestMaintenanceRulesPreserveFormalSupportAndRespectDateCriterion(t *testing.T) {
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	id, _ := identity.Resolve(model.Component{PURL: "pkg:npm/transitive-leaf@1.0.0"})
	for _, tc := range []struct {
		name, formal, signal, want, basis string
		useDates                          bool
	}{
		{"rule_matches_supported_version", "SUPPORTED", "PRESENT", "EOL", "POLICY_RULE", true},
		{"date_criterion_enabled", "EOL", "ABSENT", "EOL", "SUPPORT_DATE", true},
		{"date_criterion_disabled", "EOL", "ABSENT", "NO_EOL_DETECTED", "", false},
		{"rule_matches_conflicting_dates", "UNKNOWN", "PRESENT", "EOL", "POLICY_RULE", true},
		{"unmatched_rule_cannot_resolve_conflicting_dates", "UNKNOWN", "ABSENT", "UNKNOWN", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := config.Default()
			p.Decision.UseSupportDates = tc.useDates
			p.Decision.EOLRules = []model.EOLRule{{ID: "retired", AnyOf: []string{"DEPRECATED"}}}
			r := model.ComponentResult{Lifecycle: tc.formal, VersionVerification: model.VersionVerification{Status: "VERIFIED"},
				UnknownReasons: []string{}, SelectedEvidenceIDs: []string{}, SignalEvaluations: []model.SignalEvaluation{{Type: "DEPRECATED", Status: tc.signal}}}
			if tc.formal == "UNKNOWN" {
				r.UnknownReasons = []string{"CONFLICT"}
			} else {
				end := "2026-12-01"
				if tc.formal == "EOL" {
					end = "2026-10-01"
				}
				r.Confidence, r.EOLEffectiveDate, r.MatchedCycle = model.Ptr("HIGH"), model.Ptr(end), model.Ptr("1")
				r.SelectedEvidenceIDs = []string{"official"}
			}
			lifecycle.EvaluateEOLRules(&r, id, p, "2026-10-13", now)
			if r.Lifecycle != tc.want || model.Text(r.EOLBasis) != tc.basis || r.SupportAssessment.Lifecycle != tc.formal {
				t.Fatalf("support/rule result: %+v", r)
			}
			if tc.basis == "POLICY_RULE" && (r.EOLEffectiveDate != nil || r.MatchedCycle != nil || len(r.SelectedEvidenceIDs) != 0 || model.Text(r.Confidence) != "MEDIUM") {
				t.Fatalf("rule match retained a support-date conclusion: %+v", r)
			}
			if tc.formal != "UNKNOWN" && (model.Text(r.SupportAssessment.Confidence) != "HIGH" || len(r.SupportAssessment.SelectedEvidenceIDs) != 1) {
				t.Fatal("formal support evidence was lost")
			}
			if tc.formal == "UNKNOWN" && !model.Contains(r.SupportAssessment.UnknownReasons, "CONFLICT") {
				t.Fatal("formal date conflict was lost")
			}
		})
	}
}
