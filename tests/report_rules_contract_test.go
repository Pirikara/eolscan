package acceptance

import (
	"encoding/json"
	"testing"

	"github.com/Pirikara/eolscan/internal/model"
	reporting "github.com/Pirikara/eolscan/internal/report"
	"github.com/Pirikara/eolscan/internal/testutil"
)

func cloneReport(t *testing.T, original model.Report) model.Report {
	t.Helper()
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var report model.Report
	if err := json.Unmarshal(b, &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func TestPolicyEOLReportsRejectInconsistentProofAndGates(t *testing.T) {
	p := rulePolicy(model.EOLRule{ID: "deprecated", AnyOf: []string{"DEPRECATED"}})
	stub := testutil.NewStub()
	npmSource(t, stub, "", "No longer supported", "2020-01-01T00:00:00Z")
	base := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:npm/transitive-leaf@1.0.0"), false)
	for _, tc := range []struct {
		name string
		edit func(*model.Report)
	}{
		{"missing_evaluations", func(r *model.Report) { r.Results[0].EOLRuleEvaluations = []model.EOLRuleEvaluation{} }},
		{"unknown_rule_id", func(r *model.Report) { r.Results[0].EOLRuleEvaluations[0].RuleID = "not-configured" }},
		{"wrong_matched_condition", func(r *model.Report) { r.Results[0].EOLRuleEvaluations[0].MatchedSignals = []string{"ARCHIVED"} }},
		{"missing_positive_evidence", func(r *model.Report) { r.Results[0].Signals = []model.SignalEvidence{} }},
		{"fabricated_end_date", func(r *model.Report) { r.Results[0].EOLEffectiveDate = model.Ptr("2026-10-01") }},
		{"fabricated_high_confidence", func(r *model.Report) { r.Results[0].Confidence = model.Ptr("HIGH") }},
		{"future_publication", func(r *model.Report) {
			r.Results[0].VersionVerification.PublishedAt = model.Ptr("2026-10-12T00:00:00Z")
		}},
		{"historical_live_flag", func(r *model.Report) { r.AsOf = "2026-10-10" }},
		{"summary_relabels_eol", func(r *model.Report) { r.Summary.EOL, r.Summary.NoEOLDetected = 0, 1 }},
		{"summary_hides_component_failure", func(r *model.Report) { r.Summary.CIFailureCount = 0 }},
		{"summary_fabricates_coverage", func(r *model.Report) { r.Summary.AssessmentCoverage = 0.5 }},
		{"gate_hides_component_failure", func(r *model.Report) { r.CIGate.Passed, r.CIGate.ViolationCodes = true, []string{} }},
		{"component_hides_policy_violation", func(r *model.Report) {
			r.Results[0].CIFailure = false
			r.Summary.CIFailureCount = 0
			r.CIGate.Passed, r.CIGate.ViolationCodes = true, []string{}
		}},
		{"unknown_input_hides_incomplete", func(r *model.Report) {
			row := &r.Results[0]
			row.Lifecycle, row.Confidence, row.EOLBasis = "UNKNOWN", nil, nil
			row.Signals = []model.SignalEvidence{}
			row.SignalEvaluations[0].Status, row.SignalEvaluations[0].ReasonCode = "UNKNOWN", model.Ptr("NO_CAPABILITY")
			row.EOLRuleEvaluations[0] = model.EOLRuleEvaluation{RuleID: "deprecated", Status: "UNKNOWN", MatchedSignals: []string{}, UnknownSignals: []string{"DEPRECATED"}, ReasonCode: model.Ptr("CONDITION_UNAVAILABLE")}
			row.UnknownReasons = []string{"EOL_RULE_UNRESOLVED"}
			row.CIFailure, row.Incomplete = false, false
			r.Summary.EOL, r.Summary.Unknown, r.Summary.CIFailureCount, r.Summary.AssessmentCoverage = 0, 1, 0, 0
			r.CIGate.Passed, r.CIGate.ViolationCodes, r.CIGate.Incomplete = true, []string{}, false
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := cloneReport(t, base)
			tc.edit(&report)
			if err := reporting.Validate(report, p); err == nil {
				t.Fatal("accepted a report that contradicts its EOL proof or CI policy")
			}
		})
	}
}
