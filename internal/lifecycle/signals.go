package lifecycle

import (
	"sort"

	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/provider"
)

// Combine equivalent provider assessments before applying required-signal
// completeness. An unavailable lookup does not override a successful lookup;
// disagreement between successful providers remains UNKNOWN.
func AggregateSignals(requested []string, evaluations []model.SignalEvaluation, evidence []model.SignalEvidence) ([]model.SignalEvaluation, []model.SignalEvidence, []model.Diagnostic) {
	out := []model.SignalEvaluation{}
	ds := []model.Diagnostic{}
	sort.SliceStable(evaluations, func(i, j int) bool {
		a, b := evaluations[i], evaluations[j]
		if model.Text(a.ProviderID) != model.Text(b.ProviderID) {
			return model.Text(a.ProviderID) < model.Text(b.ProviderID)
		}
		return model.Text(a.SourceURL) < model.Text(b.SourceURL)
	})
	for _, kind := range requested {
		positive := []model.SignalEvaluation{}
		negative := []model.SignalEvaluation{}
		unknown := []model.SignalEvaluation{}
		for _, e := range evaluations {
			if e.Type != kind {
				continue
			}
			switch e.Status {
			case "PRESENT":
				positive = append(positive, e)
			case "ABSENT":
				negative = append(negative, e)
			default:
				unknown = append(unknown, e)
			}
		}
		switch {
		// Registry project markers and source-repository archival are different
		// scopes. A positive in either scope satisfies the ARCHIVED condition.
		// A negative in one scope cannot hide an unavailable check in the other.
		case (kind == "ARCHIVED" || kind == "DECLARED_UNMAINTAINED") && len(positive) > 0:
			out = append(out, positive[0])
		case (kind == "ARCHIVED" || kind == "DECLARED_UNMAINTAINED") && len(negative) > 0:
			chosen := negative[0]
			for _, unavailable := range unknown {
				if model.Text(unavailable.ReasonCode) != "NO_CAPABILITY" {
					chosen = unavailable
					break
				}
			}
			out = append(out, chosen)
		case len(positive) > 0 && len(negative) > 0:
			out = append(out, provider.UnknownSignal(kind, "SIGNAL_CONFLICT"))
			ds = append(ds, model.NewDiagnostic("SIGNAL_CONFLICT", "", "Equivalent providers disagree on signal "+kind))
		case len(positive) > 0:
			out = append(out, positive[0])
		case len(negative) > 0:
			out = append(out, negative[0])
		case len(unknown) > 0:
			chosen := unknown[0]
			for _, unavailable := range unknown {
				if model.Text(unavailable.ReasonCode) != "NO_CAPABILITY" {
					chosen = unavailable
					break
				}
			}
			out = append(out, chosen)
		default:
			out = append(out, provider.UnknownSignal(kind, "NO_CAPABILITY"))
		}
	}
	signals := []model.SignalEvidence{}
	seen := map[string]bool{}
	for _, s := range evidence {
		if !model.Contains(requested, s.Type) {
			continue
		}
		key := s.Type + "\x00" + s.ProviderID + "\x00" + model.Text(s.SourceURL)
		if !seen[key] {
			seen[key] = true
			signals = append(signals, s)
		}
	}
	return out, signals, ds
}
