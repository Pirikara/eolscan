// Package scanner orchestrates verification, evidence, evaluation, and CI gates.
package scanner

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/lifecycle"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/provider"
	reporting "github.com/Pirikara/eolscan/internal/report"
	"github.com/Pirikara/eolscan/internal/transport"
	"github.com/Pirikara/eolscan/internal/version"
)

type Scanner struct {
	bundle    model.PolicyBundle
	transport *transport.Transport
	eol       *provider.EOLProvider
	metadata  *provider.MetadataResolver
	now       time.Time
	asOf      string
}

// New creates a scanner with a shared HTTP transport and execution clock.
func New(bundle model.PolicyBundle, client *http.Client, now time.Time, asOf string, offline bool) *Scanner {
	t := transport.New(client, bundle.Policy, now, offline)
	return NewWithTransport(bundle, t, asOf)
}

// NewWithTransport accepts an injected transport and uses its execution clock.
func NewWithTransport(bundle model.PolicyBundle, t *transport.Transport, asOf string) *Scanner {
	s := &Scanner{bundle: bundle, transport: t, now: t.Now(), asOf: asOf}
	s.eol = provider.NewEOL(t, bundle)
	s.metadata = provider.NewMetadataResolver(t)
	return s
}

func (s *Scanner) component(ctx context.Context, c model.Component) model.ComponentResult {
	p := s.bundle.Policy
	r := model.ComponentResult{
		SourceRef: c.SourceRef, PURL: model.Nullable(identity.RedactPURL(c.PURL)), Name: c.Name, Version: model.Nullable(c.Version),
		Lifecycle: "UNKNOWN", VersionVerification: model.VersionVerification{Status: "NOT_APPLICABLE"},
		Signals: []model.SignalEvidence{}, SignalEvaluations: []model.SignalEvaluation{}, SelectedEvidenceIDs: []string{},
		Notices: []model.Notice{}, UnknownReasons: []string{}, RuleIDs: []string{}, Evidence: []model.LifecycleEvidence{}, Diagnostics: []model.Diagnostic{},
	}
	id, reason := identity.Resolve(c)
	requested := config.RequestedSignals(p)
	if reason != "" {
		r.UnknownReasons = append(r.UnknownReasons, reason)
		r.VersionVerification.ReasonCode = model.Ptr(reason)
		r.RuleIDs = model.AddUnique(r.RuleIDs, "R-011")
		for _, kind := range requested {
			r.SignalEvaluations = append(r.SignalEvaluations, provider.UnknownSignal(kind, "INVALID_IDENTITY"))
		}
	} else {
		r.PURL = model.Ptr(id.PURL)
		r.Version = model.Ptr(id.Version)
		r.Evidence = provider.CatalogEvidence(s.bundle, id, s.now)
		local, localOK, ds := provider.LocalVersion(s.bundle, id, s.asOf, s.now)
		r.Diagnostics = append(r.Diagnostics, ds...)
		var assertion *model.VersionVerification
		if localOK {
			assertion = &local
		}
		metadata := s.metadata.Resolve(ctx, id, s.asOf, assertion, requested)
		r.VersionVerification = metadata.Version
		r.SignalEvaluations = metadata.Evaluations
		r.Signals = metadata.Signals
		r.Diagnostics = append(r.Diagnostics, metadata.Diagnostics...)
		if r.VersionVerification.Status == "UNVERIFIED" {
			r.Incomplete = true
			if model.Text(r.VersionVerification.ReasonCode) != "NO_CAPABILITY" {
				r.UnknownReasons = model.AddUnique(r.UnknownReasons, "SOURCE_ERROR")
			}
		}
		if len(r.Signals) > 0 {
			r.RuleIDs = model.AddUnique(r.RuleIDs, "R-005")
		}
		eolUnavailable := false
		if p.Sources.EndoflifeDate.Enabled {
			e, ds, reason, failed := s.eol.Evidence(ctx, id)
			r.Evidence = append(r.Evidence, e...)
			r.Diagnostics = append(r.Diagnostics, ds...)
			if reason != "" {
				r.UnknownReasons = model.AddUnique(r.UnknownReasons, reason)
			}
			eolUnavailable = failed
		}
		lifecycle.Evaluate(&r, id, p, s.asOf, s.now)
		if eolUnavailable {
			// A reviewed local official claim is a higher tier alternative to
			// the unavailable curated lookup, even when it derives UNKNOWN.
			officialAlternative := false
			for _, e := range r.Evidence {
				if e.SourceClass == "OFFICIAL" && e.ReviewedAt != nil && e.ValidUntil != nil && model.Active(*e.ReviewedAt, *e.ValidUntil, model.UTCDate(s.now)) {
					officialAlternative = true
				}
			}
			if !officialAlternative {
				r.Incomplete = true
			}
		}
	}
	merged, signals, signalDiagnostics := lifecycle.AggregateSignals(requested, r.SignalEvaluations, r.Signals)
	r.SignalEvaluations, r.Signals = merged, signals
	r.Diagnostics = append(r.Diagnostics, signalDiagnostics...)
	for _, e := range r.SignalEvaluations {
		if e.Status == "UNKNOWN" && model.Contains(p.CI.FailOnSignals, e.Type) {
			r.Incomplete = true
		}
	}
	s.applyCI(&r)
	normalizeResult(&r)
	return r
}

func normalizeResult(r *model.ComponentResult) {
	sort.Strings(r.RuleIDs)
	sort.Strings(r.UnknownReasons)
	sort.Strings(r.SelectedEvidenceIDs)
	sort.Slice(r.Evidence, func(i, j int) bool { return r.Evidence[i].ID < r.Evidence[j].ID })
	// Identical claims from the same primary source are counted once.
	evidence := []model.LifecycleEvidence{}
	seen := map[string]bool{}
	for _, e := range r.Evidence {
		key := e.SourceURL + "\x00" + e.PackagePURL + "\x00" + e.MatchedCycle + "\x00" + e.Claim + "\x00" + e.EOLEffectiveDate + "\x00" + model.Text(e.SupportStartDate)
		if seen[key] {
			continue
		}
		seen[key] = true
		evidence = append(evidence, e)
	}
	// Keep referenced claims, including formal supersession references. IDs
	// selected by the evaluator must never disappear during deduplication.
	for _, e := range r.Evidence {
		if (model.Contains(r.SelectedEvidenceIDs, e.ID) || e.SupersededBy != nil) && !evidenceIDExists(evidence, e.ID) {
			evidence = append(evidence, e)
		}
	}
	r.Evidence = evidence
	sort.Slice(r.Evidence, func(i, j int) bool { return r.Evidence[i].ID < r.Evidence[j].ID })
	sort.Slice(r.Signals, func(i, j int) bool { return r.Signals[i].Type < r.Signals[j].Type })
	sort.Slice(r.SignalEvaluations, func(i, j int) bool { return r.SignalEvaluations[i].Type < r.SignalEvaluations[j].Type })
	sort.SliceStable(r.Diagnostics, func(i, j int) bool {
		a, b := r.Diagnostics[i], r.Diagnostics[j]
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		if model.Text(a.ProviderID) != model.Text(b.ProviderID) {
			return model.Text(a.ProviderID) < model.Text(b.ProviderID)
		}
		return a.Message < b.Message
	})
	ds := []model.Diagnostic{}
	seen = map[string]bool{}
	for _, d := range r.Diagnostics {
		key := d.Code + "\x00" + model.Text(d.ProviderID) + "\x00" + d.Message
		if !seen[key] {
			seen[key] = true
			ds = append(ds, d)
		}
	}
	r.Diagnostics = ds
}

func evidenceIDExists(es []model.LifecycleEvidence, id string) bool {
	for _, e := range es {
		if e.ID == id {
			return true
		}
	}
	return false
}

func (s *Scanner) applyCI(r *model.ComponentResult) {
	p := s.bundle.Policy
	status := model.Contains(p.CI.FailOnStatuses, r.Lifecycle) && (r.Lifecycle == "UNKNOWN" || p.CI.MinConfidence == "MEDIUM" || model.Text(r.Confidence) == "HIGH")
	signal := false
	for _, e := range r.SignalEvaluations {
		if e.Status == "PRESENT" && model.Contains(p.CI.FailOnSignals, e.Type) {
			signal = true
		}
	}
	r.CIFailure = status || signal
	if s.bundle.Exceptions != nil {
		for _, e := range s.bundle.Exceptions.Exceptions {
			id, reason := identity.Resolve(model.Component{PURL: e.PackagePURL})
			if reason != "" || id.PURL != model.Text(r.PURL) {
				continue
			}
			if e.ExpiresOn < model.UTCDate(s.now) {
				r.Diagnostics = append(r.Diagnostics, model.NewDiagnostic("EXPIRED_EXCEPTION", "", "CI exception has expired"))
				continue
			}
			if r.CIFailure {
				r.CIFailure = false
				r.ExceptionApplied = true
				r.RuleIDs = model.AddUnique(r.RuleIDs, "R-010")
			}
		}
	}
}

// Scan evaluates each component and returns a validated, deterministic report.
func (s *Scanner) Scan(ctx context.Context, sbom model.SBOM) (model.Report, error) {
	report := model.Report{
		SchemaVersion: version.ReportSchema, ToolVersion: version.Current, AsOf: s.asOf, Projection: s.asOf > model.UTCDate(s.now),
		GeneratedAt: model.Timestamp(s.now), InputSHA256: sbom.SHA256, PolicyHash: s.bundle.Hash,
		Summary: model.Summary{Excluded: sbom.Excluded}, CIGate: model.CIGate{ViolationCodes: []string{}},
		Results: make([]model.ComponentResult, len(sbom.Components)),
	}
	jobs := make(chan int)
	var workers sync.WaitGroup
	var internalMu sync.Mutex
	var internalErr error
	count := s.bundle.Policy.Network.MaxConcurrency
	if count > len(sbom.Components) {
		count = len(sbom.Components)
	}
	for i := 0; i < count; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				func() {
					defer func() {
						if recover() != nil {
							internalMu.Lock()
							internalErr = fmt.Errorf("internal component processing error")
							internalMu.Unlock()
						}
					}()
					report.Results[index] = s.component(ctx, sbom.Components[index])
				}()
			}
		}()
	}
	for i := range sbom.Components {
		jobs <- i
	}
	close(jobs)
	workers.Wait()
	if internalErr != nil {
		return report, internalErr
	}
	sort.SliceStable(report.Results, func(i, j int) bool {
		a, b := report.Results[i], report.Results[j]
		if (a.PURL == nil) != (b.PURL == nil) {
			return a.PURL != nil
		}
		if model.Text(a.PURL) != model.Text(b.PURL) {
			return model.Text(a.PURL) < model.Text(b.PURL)
		}
		return a.SourceRef < b.SourceRef
	})
	report.Summary.InScope = len(report.Results)
	for _, r := range report.Results {
		switch r.Lifecycle {
		case "EOL":
			report.Summary.EOL++
		case "SUPPORTED":
			report.Summary.Supported++
		default:
			report.Summary.Unknown++
		}
		if r.CIFailure {
			report.Summary.CIFailureCount++
		}
		if r.Incomplete {
			report.CIGate.Incomplete = true
		}
		for _, d := range r.Diagnostics {
			if d.Code == "SOURCE_ERROR" || d.Code == "PROVIDER_SCHEMA_MISMATCH" || d.Code == "VERSION_CONFLICT" ||
				d.Code == "MISSING_PUBLICATION_DATE" || d.Code == "PUBLICATION_IN_FUTURE" || d.Code == "PROVIDER_IDENTITY_MISMATCH" ||
				d.Code == "PROVIDER_RESPONSE_TOO_LARGE" || d.Code == "UNSAFE_PROVIDER_URL" ||
				d.Code == "RATE_LIMITED" || d.Code == "RATE_LIMIT_WAIT_TIMEOUT" {
				report.Summary.ProviderErrorCount++
			}
		}
	}
	if report.Summary.InScope > 0 {
		report.Summary.AssessmentCoverage = float64(report.Summary.EOL+report.Summary.Supported) / float64(report.Summary.InScope)
	}
	if report.Summary.CIFailureCount > 0 {
		report.CIGate.ViolationCodes = append(report.CIGate.ViolationCodes, "COMPONENT_POLICY_VIOLATION")
	}
	p := s.bundle.Policy
	ratio := 0.0
	if report.Summary.InScope > 0 {
		ratio = float64(report.Summary.Unknown) / float64(report.Summary.InScope)
	}
	if p.CI.MaxUnknownRatio != nil && ratio > *p.CI.MaxUnknownRatio {
		report.CIGate.ViolationCodes = append(report.CIGate.ViolationCodes, "MAX_UNKNOWN_RATIO_EXCEEDED")
	}
	if p.CI.FailOnIncompleteScan && report.CIGate.Incomplete {
		report.CIGate.ViolationCodes = append(report.CIGate.ViolationCodes, "INCOMPLETE_SCAN")
	}
	report.CIGate.Passed = len(report.CIGate.ViolationCodes) == 0
	if err := reporting.Validate(report, p); err != nil {
		return report, fmt.Errorf("report contract: %w", err)
	}
	return report, nil
}

// CacheHits returns cache metrics without exposing transport internals.
func (s *Scanner) CacheHits() int64 { return s.transport.CacheHits() }
