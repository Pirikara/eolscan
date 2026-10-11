package main

import "sort"

// Combine equivalent provider assessments before applying required-signal
// completeness. An unavailable lookup does not override a successful lookup;
// disagreement between successful providers remains UNKNOWN.
func aggregateSignals(requested []string, evaluations []SignalEvaluation, evidence []SignalEvidence) ([]SignalEvaluation, []SignalEvidence, []Diagnostic) {
	out := []SignalEvaluation{}
	ds := []Diagnostic{}
	sort.SliceStable(evaluations, func(i, j int) bool {
		a, b := evaluations[i], evaluations[j]
		if textOf(a.ProviderID) != textOf(b.ProviderID) {
			return textOf(a.ProviderID) < textOf(b.ProviderID)
		}
		return textOf(a.SourceURL) < textOf(b.SourceURL)
	})
	for _, kind := range requested {
		positive := []SignalEvaluation{}
		negative := []SignalEvaluation{}
		unknown := []SignalEvaluation{}
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
		case len(positive) > 0 && len(negative) > 0:
			out = append(out, unknownSignal(kind, "SIGNAL_CONFLICT"))
			ds = append(ds, diag("SIGNAL_CONFLICT", "", "Equivalent providers disagree on signal "+kind))
		case len(positive) > 0:
			out = append(out, positive[0])
		case len(negative) > 0:
			out = append(out, negative[0])
		case len(unknown) > 0:
			out = append(out, unknown[0])
		default:
			out = append(out, unknownSignal(kind, "NO_CAPABILITY"))
		}
	}
	signals := []SignalEvidence{}
	seen := map[string]bool{}
	for _, s := range evidence {
		if !has(requested, s.Type) {
			continue
		}
		key := s.Type + "\x00" + s.ProviderID + "\x00" + textOf(s.SourceURL)
		if !seen[key] {
			seen[key] = true
			signals = append(signals, s)
		}
	}
	return out, signals, ds
}
