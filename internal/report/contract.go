package report

import (
	"fmt"
	"reflect"
	"time"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/contract"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/lifecycle"
	"github.com/Pirikara/eolscan/internal/model"
)

func ExitCode(r model.Report) int {
	if model.Contains(r.CIGate.ViolationCodes, "COMPONENT_POLICY_VIOLATION") || model.Contains(r.CIGate.ViolationCodes, "MAX_UNKNOWN_RATIO_EXCEEDED") {
		return 1
	}
	if model.Contains(r.CIGate.ViolationCodes, "INCOMPLETE_SCAN") || model.Contains(r.CIGate.ViolationCodes, "NO_COMPONENTS") {
		return 3
	}
	return 0
}

func Validate(r model.Report, p model.Policy) error {
	v, err := contract.JSONValue(r)
	if err != nil {
		return err
	}
	if err := contract.Validate("report", v); err != nil {
		return err
	}
	runAt, _ := time.Parse(time.RFC3339Nano, r.GeneratedAt)
	for _, row := range r.Results {
		id, identityReason := identity.Resolve(model.Component{PURL: model.Text(row.PURL), Version: model.Text(row.Version)})
		requested := config.RequestedSignals(p)
		if identityReason == "" {
			requested = config.RequestedSignalsForPackage(p, id)
		}
		if len(row.SignalEvaluations) != len(requested) {
			return fmt.Errorf("signal evaluation coverage")
		}
		for _, e := range row.SignalEvaluations {
			if !model.Contains(requested, e.Type) {
				return fmt.Errorf("unrequested signal")
			}
			if e.Status == "UNKNOWN" && model.Contains(p.CI.FailOnSignals, e.Type) && !row.Incomplete {
				return fmt.Errorf("required signal must mark incomplete")
			}
			positive := false
			for _, s := range row.Signals {
				if s.Type == e.Type {
					positive = true
				}
			}
			if e.Status == "PRESENT" && !positive || e.Status == "ABSENT" && positive {
				return fmt.Errorf("signal evidence inconsistent with evaluation")
			}
		}
		// Recompute policy matches from the retained support assessment and
		// signal results. A report cannot label a configured rule as matched
		// merely because a CI signal was selected.
		expected := row
		expected.Lifecycle, expected.Confidence = row.SupportAssessment.Lifecycle, row.SupportAssessment.Confidence
		expected.EOLEffectiveDate, expected.MatchedCycle = row.SupportAssessment.EOLEffectiveDate, row.SupportAssessment.MatchedCycle
		expected.SelectedEvidenceIDs = append([]string{}, row.SupportAssessment.SelectedEvidenceIDs...)
		expected.UnknownReasons = append([]string{}, row.SupportAssessment.UnknownReasons...)
		expected.EOLBasis = nil
		lifecycle.EvaluateEOLRules(&expected, id, p, r.AsOf, runAt)
		if expected.Lifecycle != row.Lifecycle || model.Text(expected.EOLBasis) != model.Text(row.EOLBasis) ||
			model.Text(expected.Confidence) != model.Text(row.Confidence) || !reflect.DeepEqual(expected.EOLRuleEvaluations, row.EOLRuleEvaluations) {
			return fmt.Errorf("EOL result contradicts configured rules")
		}
		if expected.Incomplete && !row.Incomplete {
			return fmt.Errorf("unavailable EOL conditions must mark incomplete")
		}
		if identityReason == "" {
			support := model.ComponentResult{Lifecycle: "UNKNOWN", VersionVerification: row.VersionVerification, Evidence: row.Evidence,
				UnknownReasons: append([]string{}, row.SupportAssessment.UnknownReasons...), SelectedEvidenceIDs: []string{}, Notices: []model.Notice{}}
			lifecycle.Evaluate(&support, id, p, r.AsOf, runAt)
			if support.Lifecycle != row.SupportAssessment.Lifecycle || model.Text(support.Confidence) != model.Text(row.SupportAssessment.Confidence) ||
				model.Text(support.EOLEffectiveDate) != model.Text(row.SupportAssessment.EOLEffectiveDate) ||
				model.Text(support.MatchedCycle) != model.Text(row.SupportAssessment.MatchedCycle) ||
				!reflect.DeepEqual(support.SelectedEvidenceIDs, row.SupportAssessment.SelectedEvidenceIDs) {
				return fmt.Errorf("support assessment contradicts eligible evidence")
			}
		} else if row.SupportAssessment.Lifecycle != "UNKNOWN" {
			return fmt.Errorf("invalid identity cannot have a support conclusion")
		}
		if row.Lifecycle != "UNKNOWN" {
			pub, err := time.Parse(time.RFC3339Nano, model.Text(row.VersionVerification.PublishedAt))
			if err != nil || pub.After(runAt) || model.UTCDate(pub) > r.AsOf {
				return fmt.Errorf("version publication after evaluation/run")
			}
			for _, id := range row.SelectedEvidenceIDs {
				found := false
				for _, e := range row.Evidence {
					if e.ID != id {
						continue
					}
					found = true
					if e.EOLEffectiveDate != model.Text(row.EOLEffectiveDate) || e.MatchedCycle != model.Text(row.MatchedCycle) || e.Confidence != model.Text(row.Confidence) {
						return fmt.Errorf("selected evidence projection mismatch")
					}
					if row.Lifecycle == "SUPPORTED" && (e.Claim != "UPSTREAM_SECURITY_WINDOW" || model.Text(e.SupportStartDate) > r.AsOf || e.EOLEffectiveDate <= r.AsOf) {
						return fmt.Errorf("support requires applicable window")
					}
				}
				if !found {
					return fmt.Errorf("selected evidence missing")
				}
			}
		}
		for _, selected := range row.SupportAssessment.SelectedEvidenceIDs {
			found := false
			for _, evidence := range row.Evidence {
				found = found || evidence.ID == selected
			}
			if !found {
				return fmt.Errorf("support evidence missing")
			}
		}
		for _, n := range row.Notices {
			if !model.Contains(row.SelectedEvidenceIDs, n.EvidenceID) {
				return fmt.Errorf("notice must reference selected evidence")
			}
		}
	}
	if r.Summary.InScope != r.Summary.EOL+r.Summary.Supported+r.Summary.NoEOLDetected+r.Summary.Unknown {
		return fmt.Errorf("summary is inconsistent")
	}
	if r.Summary.InScope == 0 && (r.CIGate.Passed || !r.CIGate.Incomplete || !model.Contains(r.CIGate.ViolationCodes, "NO_COMPONENTS")) {
		return fmt.Errorf("empty scans must fail with NO_COMPONENTS")
	}
	return nil
}
