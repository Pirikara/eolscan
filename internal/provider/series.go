package provider

import (
	"context"
	"strings"
	"time"

	"github.com/Pirikara/eolscan/internal/contract"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/transport"
)

type seriesSnapshot struct {
	data                transport.HTTPData
	url, product, label string
	mapped              bool
	release             *eolRelease
}

type LifecycleMetadata struct {
	Evidence         []model.LifecycleEvidence
	Diagnostics      []model.Diagnostic
	Reason           string
	Failed           bool
	SeriesEvaluation *model.SignalEvaluation
	SeriesEvidence   *model.SignalEvidence
}

// Collect shares one exact-PURL lookup between formal support assessment and
// the organization's broader release-series EOL criterion.
func (p *EOLProvider) Collect(ctx context.Context, id identity.Identity, asOf string, includeSeries bool) LifecycleMetadata {
	var snapshot seriesSnapshot
	var out LifecycleMetadata
	out.Evidence, out.Diagnostics, out.Reason, out.Failed = p.evidence(ctx, id, &snapshot)
	if includeSeries {
		evaluation, evidence := p.seriesSignal(snapshot, id, asOf, out.Reason, out.Failed)
		out.SeriesEvaluation, out.SeriesEvidence = &evaluation, evidence
	}
	return out
}

func (p *EOLProvider) seriesSignal(s seriesSnapshot, id identity.Identity, asOf, reason string, failed bool) (model.SignalEvaluation, *model.SignalEvidence) {
	e := model.SignalEvaluation{Type: "RELEASE_SERIES_EOL", Status: "UNKNOWN", ProviderID: model.Ptr("endoflife_date"), SourceURL: model.Nullable(s.url), CheckedAt: model.Nullable(s.data.ObservedAt)}
	unknown := func(code string) (model.SignalEvaluation, *model.SignalEvidence) {
		e.ReasonCode = model.Ptr(code)
		return e, nil
	}
	if failed || reason != "" {
		if reason == "" {
			reason = "SOURCE_ERROR"
		}
		return unknown(reason)
	}
	observed, err := time.Parse(time.RFC3339Nano, s.data.ObservedAt)
	if err != nil || observed.After(p.t.Now()) || p.t.Now().Sub(observed).Hours() > float64(p.t.Policy().Decision.MaxEvidenceAgeDays)*24 {
		return unknown("STALE_EVIDENCE")
	}
	// ABSENT means the successfully read feed has no applicable EOL claim.
	// It does not assert that the package or release series is supported.
	if s.release == nil {
		if s.mapped && !numericSeriesVersion(identity.SeriesVersion(id)) {
			return unknown("UNSUPPORTED_VERSION_SCHEME")
		}
		e.Status = "ABSENT"
		return e, nil
	}
	r := s.release
	details := map[string]any{"product_slug": s.product, "matched_cycle": r.Name, "support_label": s.label, "support_scope": "general_eol", "raw_payload_hash": contract.Digest(s.data.Body)}
	positive := false
	if r.EOLFrom != nil {
		// Date validity and same-series contradictions are checked before this
		// comparison by the shared lookup, including future conflicting dates.
		positive = *r.EOLFrom <= asOf
		details["eol_effective_date"], details["source_field"] = *r.EOLFrom, "releases[].eolFrom"
	} else {
		if asOf != model.UTCDate(p.t.Now()) {
			return unknown("STATUS_TIME_UNAVAILABLE")
		}
		positive = *r.IsEOL
		details["source_field"] = "releases[].isEol"
	}
	if !positive {
		e.Status = "ABSENT"
		return e, nil
	}
	e.Status = "PRESENT"
	return e, &model.SignalEvidence{Type: e.Type, ProviderID: "endoflife_date", SourceURL: model.Nullable(s.url), ObservedAt: s.data.ObservedAt, Details: details}
}

func numericSeriesVersion(version string) bool {
	// Reuse the same numeric matcher without accepting a calendar series.
	version = strings.TrimPrefix(version, "v")
	return identity.NumericCycleMatches(version, version)
}
