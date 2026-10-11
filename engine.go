package main

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

type Scanner struct {
	bundle    PolicyBundle
	transport *Transport
	eol       *EOLProvider
	now       time.Time
	asOf      string
}

func newScanner(bundle PolicyBundle, client *http.Client, now time.Time, asOf string, offline bool) *Scanner {
	t := newTransport(client, bundle.Policy, now, offline)
	s := &Scanner{bundle: bundle, transport: t, now: now, asOf: asOf}
	s.eol = &EOLProvider{t: t, bundle: bundle}
	return s
}
func (s *Scanner) component(ctx context.Context, c Component) ComponentResult {
	p := s.bundle.Policy
	r := ComponentResult{
		SourceRef: c.SourceRef, PURL: nullable(redactPURL(c.PURL)), Name: c.Name, Version: nullable(c.Version),
		Lifecycle: "UNKNOWN", VersionVerification: VersionVerification{Status: "NOT_APPLICABLE"},
		Signals: []SignalEvidence{}, SignalEvaluations: []SignalEvaluation{}, SelectedEvidenceIDs: []string{},
		Notices: []Notice{}, UnknownReasons: []string{}, RuleIDs: []string{}, Evidence: []LifecycleEvidence{}, Diagnostics: []Diagnostic{},
	}
	id, reason := resolveIdentity(c)
	requested := requestedSignals(p)
	if reason != "" {
		r.UnknownReasons = append(r.UnknownReasons, reason)
		r.VersionVerification.ReasonCode = ptr(reason)
		r.RuleIDs = addUnique(r.RuleIDs, "R-011")
		for _, kind := range requested {
			r.SignalEvaluations = append(r.SignalEvaluations, unknownSignal(kind, "INVALID_IDENTITY"))
		}
	} else {
		r.PURL = ptr(id.PURL)
		r.Version = ptr(id.Version)
		r.Evidence = catalogEvidence(s.bundle, id, s.now)
		local, localOK, ds := localVersion(s.bundle, id, s.asOf, s.now)
		r.Diagnostics = append(r.Diagnostics, ds...)
		var remote depsVersion
		var data HTTPData
		var remoteErr error
		needsVersion := !localOK && has(p.VersionVerification.Sources, "deps_dev")
		needsDeprecated := has(requested, "DEPRECATED")
		remoteFetched := p.Sources.DepsDev.Enabled && (needsVersion || needsDeprecated)
		if remoteFetched {
			remote, data, remoteErr = depsVersionData(ctx, s.transport, id)
			r.Diagnostics = append(r.Diagnostics, providerDiagnostics("deps_dev", data.Diagnostics)...)
			if remoteErr != nil {
				r.Diagnostics = append(r.Diagnostics, errorDiagnostic("deps_dev", remoteErr))
			}
		}
		if localOK {
			r.VersionVerification = local
		} else if remoteFetched && has(p.VersionVerification.Sources, "deps_dev") {
			r.VersionVerification = depsVerification(s.transport, id, remote, data, remoteErr, s.asOf)
			r.Diagnostics = append(r.Diagnostics, publicationDiagnostic("deps_dev", r.VersionVerification)...)
		} else {
			r.VersionVerification = noVersionCapability()
		}
		if r.VersionVerification.Status == "UNVERIFIED" {
			r.Incomplete = true
			if remoteErr != nil || has([]string{"MISSING_PUBLICATION_DATE", "PUBLICATION_IN_FUTURE"}, textOf(r.VersionVerification.ReasonCode)) {
				r.UnknownReasons = addUnique(r.UnknownReasons, "SOURCE_ERROR")
			}
		}
		for _, kind := range requested {
			e := unknownSignal(kind, "NO_CAPABILITY")
			var evidence *SignalEvidence
			switch kind {
			case "DEPRECATED":
				if remoteFetched {
					e, evidence = deprecatedSignal(s.transport, id, remote, data, remoteErr)
				}
			case "STALE_RELEASE":
				if p.Sources.DepsDev.Enabled {
					var ds []Diagnostic
					e, evidence, ds = staleReleaseSignal(ctx, s.transport, id, s.asOf)
					r.Diagnostics = append(r.Diagnostics, ds...)
				}
			}
			r.SignalEvaluations = append(r.SignalEvaluations, e)
			if evidence != nil {
				r.Signals = append(r.Signals, *evidence)
				r.RuleIDs = addUnique(r.RuleIDs, "R-005")
			}
		}
		eolUnavailable := false
		if p.Sources.EndoflifeDate.Enabled {
			e, ds, reason, failed := s.eol.evidence(ctx, id)
			r.Evidence = append(r.Evidence, e...)
			r.Diagnostics = append(r.Diagnostics, ds...)
			if reason != "" {
				r.UnknownReasons = addUnique(r.UnknownReasons, reason)
			}
			eolUnavailable = failed
		}
		evaluateLifecycle(&r, id, p, s.asOf, s.now)
		if eolUnavailable {
			// A reviewed local official claim is a higher tier alternative to
			// the unavailable curated lookup, even when it derives UNKNOWN.
			officialAlternative := false
			for _, e := range r.Evidence {
				if e.SourceClass == "OFFICIAL" && e.ReviewedAt != nil && e.ValidUntil != nil && active(*e.ReviewedAt, *e.ValidUntil, utcDay(s.now)) {
					officialAlternative = true
				}
			}
			if !officialAlternative {
				r.Incomplete = true
			}
		}
	}
	merged, signals, signalDiagnostics := aggregateSignals(requested, r.SignalEvaluations, r.Signals)
	r.SignalEvaluations, r.Signals = merged, signals
	r.Diagnostics = append(r.Diagnostics, signalDiagnostics...)
	for _, e := range r.SignalEvaluations {
		if e.Status == "UNKNOWN" && has(p.CI.FailOnSignals, e.Type) {
			r.Incomplete = true
		}
	}
	s.applyCI(&r)
	normalizeResult(&r)
	return r
}
func normalizeResult(r *ComponentResult) {
	sort.Strings(r.RuleIDs)
	sort.Strings(r.UnknownReasons)
	sort.Strings(r.SelectedEvidenceIDs)
	sort.Slice(r.Evidence, func(i, j int) bool { return r.Evidence[i].ID < r.Evidence[j].ID })
	// Identical claims from the same primary source are counted once.
	evidence := []LifecycleEvidence{}
	seen := map[string]bool{}
	for _, e := range r.Evidence {
		key := e.SourceURL + "\x00" + e.PackagePURL + "\x00" + e.MatchedCycle + "\x00" + e.Claim + "\x00" + e.EOLEffectiveDate + "\x00" + textOf(e.SupportStartDate)
		if seen[key] {
			continue
		}
		seen[key] = true
		evidence = append(evidence, e)
	}
	// Keep referenced claims, including formal supersession references. IDs
	// selected by the evaluator must never disappear during deduplication.
	for _, e := range r.Evidence {
		if (has(r.SelectedEvidenceIDs, e.ID) || e.SupersededBy != nil) && !evidenceIDExists(evidence, e.ID) {
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
		if textOf(a.ProviderID) != textOf(b.ProviderID) {
			return textOf(a.ProviderID) < textOf(b.ProviderID)
		}
		return a.Message < b.Message
	})
	ds := []Diagnostic{}
	seen = map[string]bool{}
	for _, d := range r.Diagnostics {
		key := d.Code + "\x00" + textOf(d.ProviderID) + "\x00" + d.Message
		if !seen[key] {
			seen[key] = true
			ds = append(ds, d)
		}
	}
	r.Diagnostics = ds
}
func evidenceIDExists(es []LifecycleEvidence, id string) bool {
	for _, e := range es {
		if e.ID == id {
			return true
		}
	}
	return false
}
func (s *Scanner) applyCI(r *ComponentResult) {
	p := s.bundle.Policy
	status := has(p.CI.FailOnStatuses, r.Lifecycle) && (r.Lifecycle == "UNKNOWN" || p.CI.MinConfidence == "MEDIUM" || textOf(r.Confidence) == "HIGH")
	signal := false
	for _, e := range r.SignalEvaluations {
		if e.Status == "PRESENT" && has(p.CI.FailOnSignals, e.Type) {
			signal = true
		}
	}
	r.CIFailure = status || signal
	if s.bundle.Exceptions != nil {
		for _, e := range s.bundle.Exceptions.Exceptions {
			id, reason := resolveIdentity(Component{PURL: e.PackagePURL})
			if reason != "" || id.PURL != textOf(r.PURL) {
				continue
			}
			if e.ExpiresOn < utcDay(s.now) {
				r.Diagnostics = append(r.Diagnostics, diag("EXPIRED_EXCEPTION", "", "CI exception has expired"))
				continue
			}
			if r.CIFailure {
				r.CIFailure = false
				r.ExceptionApplied = true
				r.RuleIDs = addUnique(r.RuleIDs, "R-010")
			}
		}
	}
}
func (s *Scanner) scan(ctx context.Context, sbom SBOM) (Report, error) {
	report := Report{
		SchemaVersion: "2.0", ToolVersion: toolVersion, AsOf: s.asOf, Projection: s.asOf > utcDay(s.now),
		GeneratedAt: stamp(s.now), InputSHA256: sbom.SHA256, PolicyHash: s.bundle.Hash,
		Summary: Summary{Excluded: sbom.Excluded}, CIGate: CIGate{ViolationCodes: []string{}},
		Results: make([]ComponentResult, len(sbom.Components)),
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
		if textOf(a.PURL) != textOf(b.PURL) {
			return textOf(a.PURL) < textOf(b.PURL)
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
				d.Code == "PROVIDER_RESPONSE_TOO_LARGE" || d.Code == "UNSAFE_PROVIDER_URL" {
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
	if err := validateRuntimeReport(report, p); err != nil {
		return report, fmt.Errorf("report contract: %w", err)
	}
	return report, nil
}
func reportExit(r Report) int {
	if has(r.CIGate.ViolationCodes, "COMPONENT_POLICY_VIOLATION") || has(r.CIGate.ViolationCodes, "MAX_UNKNOWN_RATIO_EXCEEDED") {
		return 1
	}
	if has(r.CIGate.ViolationCodes, "INCOMPLETE_SCAN") {
		return 3
	}
	return 0
}
func validateRuntimeReport(r Report, p Policy) error {
	v, err := jsonValue(r)
	if err != nil {
		return err
	}
	if err := schemaValidate("report", v); err != nil {
		return err
	}
	runAt, _ := time.Parse(time.RFC3339Nano, r.GeneratedAt)
	for _, row := range r.Results {
		requested := requestedSignals(p)
		if len(row.SignalEvaluations) != len(requested) {
			return fmt.Errorf("signal evaluation coverage")
		}
		for _, e := range row.SignalEvaluations {
			if !has(requested, e.Type) {
				return fmt.Errorf("unrequested signal")
			}
			if e.Status == "UNKNOWN" && has(p.CI.FailOnSignals, e.Type) && !row.Incomplete {
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
			pub, err := time.Parse(time.RFC3339Nano, textOf(row.VersionVerification.PublishedAt))
			if err != nil || pub.After(runAt) || utcDay(pub) > r.AsOf {
				return fmt.Errorf("version publication after evaluation/run")
			}
			for _, id := range row.SelectedEvidenceIDs {
				found := false
				for _, e := range row.Evidence {
					if e.ID != id {
						continue
					}
					found = true
					if e.EOLEffectiveDate != textOf(row.EOLEffectiveDate) || e.MatchedCycle != textOf(row.MatchedCycle) || e.Confidence != textOf(row.Confidence) {
						return fmt.Errorf("selected evidence projection mismatch")
					}
					if row.Lifecycle == "SUPPORTED" && (e.Claim != "UPSTREAM_SECURITY_WINDOW" || textOf(e.SupportStartDate) > r.AsOf || e.EOLEffectiveDate <= r.AsOf) {
						return fmt.Errorf("support requires applicable window")
					}
				}
				if !found {
					return fmt.Errorf("selected evidence missing")
				}
			}
		}
		for _, n := range row.Notices {
			if !has(row.SelectedEvidenceIDs, n.EvidenceID) {
				return fmt.Errorf("notice must reference selected evidence")
			}
		}
	}
	if r.Summary.InScope != r.Summary.EOL+r.Summary.Supported+r.Summary.Unknown {
		return fmt.Errorf("summary is inconsistent")
	}
	return nil
}
