package report

import (
	"fmt"
	"time"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/contract"
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
		requested := config.RequestedSignals(p)
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
		for _, n := range row.Notices {
			if !model.Contains(row.SelectedEvidenceIDs, n.EvidenceID) {
				return fmt.Errorf("notice must reference selected evidence")
			}
		}
	}
	if r.Summary.InScope != r.Summary.EOL+r.Summary.Supported+r.Summary.Unknown {
		return fmt.Errorf("summary is inconsistent")
	}
	if r.Summary.InScope == 0 && (r.CIGate.Passed || !r.CIGate.Incomplete || !model.Contains(r.CIGate.ViolationCodes, "NO_COMPONENTS")) {
		return fmt.Errorf("empty scans must fail with NO_COMPONENTS")
	}
	return nil
}
