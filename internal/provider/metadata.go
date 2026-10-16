package provider

import (
	"context"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/transport"
)

type Metadata struct {
	Version     model.VersionVerification
	Evaluations []model.SignalEvaluation
	Signals     []model.SignalEvidence
	Diagnostics []model.Diagnostic
}

// MetadataResolver collects publication and maintenance facts. It cannot
// create lifecycle evidence or infer security support from registry status.
type MetadataResolver struct {
	t        *transport.Transport
	registry *registry
}

func NewMetadataResolver(t *transport.Transport) *MetadataResolver {
	return &MetadataResolver{t: t, registry: newRegistry(t)}
}

func registrySignal(kind, ecosystem string) bool {
	switch kind {
	case "STALE_RELEASE":
		return ecosystem == "npm" || ecosystem == "pypi" || ecosystem == "gem"
	case "DEPRECATED":
		return ecosystem == "npm" || ecosystem == "pypi"
	case "YANKED":
		return ecosystem == "pypi" || ecosystem == "gem"
	case "ARCHIVED":
		return ecosystem == "npm" || ecosystem == "pypi" || ecosystem == "gem"
	case "DECLARED_UNMAINTAINED":
		return ecosystem == "npm" || ecosystem == "pypi" || ecosystem == "gem"
	case "QUARANTINED":
		return ecosystem == "pypi"
	}
	return false
}

func terminalVersion(v model.VersionVerification) bool {
	return v.Status == "VERIFIED" || v.Status == "NOT_RELEASED_AS_OF"
}

func (m *MetadataResolver) Resolve(ctx context.Context, id identity.Identity, asOf string, local *model.VersionVerification, requested []string, known ...model.SignalEvaluation) Metadata {
	out := Metadata{Version: NoVersionCapability(), Evaluations: []model.SignalEvaluation{}, Signals: []model.SignalEvidence{}, Diagnostics: []model.Diagnostic{}}
	if local != nil {
		out.Version = *local
	}
	p := m.t.Policy()
	needsRepository := p.Sources.GitHub.Enabled && (model.Contains(requested, "ARCHIVED") || model.Contains(requested, "STALE_REPOSITORY") || model.Contains(requested, "DECLARED_UNMAINTAINED"))
	needsNativeVersion := !terminalVersion(out.Version) && model.Contains(p.VersionVerification.Sources, "registries")
	needsNativeSignals := false
	for _, kind := range requested {
		needsNativeSignals = needsNativeSignals || registrySignal(kind, id.Type)
	}
	primary := map[string]model.SignalEvaluation{}
	refs := []repositoryRef{}
	for _, kind := range requested {
		primary[kind] = UnknownSignal(kind, "NO_CAPABILITY")
	}
	if m.registry.enabled(id) && (needsNativeVersion || needsNativeSignals) {
		pkg, err := m.registry.load(ctx, id)
		out.Diagnostics = append(out.Diagnostics, ProviderDiagnostics(pkg.Provider, pkg.Data.Diagnostics)...)
		if err != nil {
			out.Diagnostics = append(out.Diagnostics, transport.ErrorDiagnostic(pkg.Provider, err))
		}
		versionPkg, versionErr := pkg, err
		var detail packageSnapshot
		var detailErr error
		hasDetail := id.Type == "gem" && id.Platform == "" && err == nil &&
			(needsNativeVersion && len(pkg.records(id)) == 0 || model.Contains(requested, "YANKED") && missingYankStatus(pkg.records(id)) ||
				needsRepository)
		if hasDetail {
			detail, detailErr = m.registry.gemVersion(ctx, id)
			out.Diagnostics = append(out.Diagnostics, ProviderDiagnostics("rubygems", detail.Data.Diagnostics)...)
			if detailErr != nil {
				out.Diagnostics = append(out.Diagnostics, transport.ErrorDiagnostic("rubygems", detailErr))
			}
			if len(pkg.records(id)) == 0 {
				versionPkg, versionErr = detail, detailErr
			}
		}
		if needsNativeVersion {
			out.Version = versionPkg.verify(id, asOf, m.t.Now(), versionErr)
			out.Diagnostics = append(out.Diagnostics, PublicationDiagnostic(versionPkg.Provider, out.Version)...)
		}
		if err == nil && pkg.Data.Status == 200 && len(pkg.records(id)) > 0 {
			refs = append(refs, pkg.Repositories[id.Version]...)
			if id.Type == "pypi" && needsRepository && (pkg.ProjectStatus != "archived" || model.Contains(requested, "DECLARED_UNMAINTAINED") || model.Contains(requested, "STALE_REPOSITORY")) {
				found, data, repoErr := m.registry.pypiRepositories(ctx, id)
				refs = append(refs, found...)
				out.Diagnostics = append(out.Diagnostics, ProviderDiagnostics("pypi", data.Diagnostics)...)
				if repoErr != nil {
					out.Diagnostics = append(out.Diagnostics, transport.ErrorDiagnostic("pypi", repoErr))
				}
			}
		}
		// Exact version details can supply publication and repository metadata
		// independently of a missing or outdated package-wide version list.
		if hasDetail && detailErr == nil && detail.Data.Status == 200 {
			refs = append(refs, detail.Repositories[id.Version]...)
		}
		for _, kind := range requested {
			if kind == "DECLARED_UNMAINTAINED" {
				continue
			}
			if !registrySignal(kind, id.Type) {
				continue
			}
			snapshot, signalErr := pkg, err
			if kind == "YANKED" && hasDetail {
				snapshot, signalErr = supplementGemYanks(pkg, detail, id), detailErr
			}
			e, evidence := snapshot.signal(kind, id, asOf, m.t, signalErr)
			primary[kind] = e
			if evidence != nil {
				out.Signals = append(out.Signals, *evidence)
			}
		}
	}
	// deps.dev certifies a gem version, but not an exact platform artifact.
	needsDepsVersion := !terminalVersion(out.Version) && model.Contains(p.VersionVerification.Sources, "deps_dev") && !(id.Type == "gem" && id.Platform != "")
	needsDepsDeprecated := model.Contains(requested, "DEPRECATED") && primary["DEPRECATED"].Status == "UNKNOWN"
	needsDepsRepository := needsRepository && len(refs) == 0 &&
		(primary["ARCHIVED"].Status != "PRESENT" || model.Contains(requested, "STALE_REPOSITORY") || model.Contains(requested, "DECLARED_UNMAINTAINED"))
	if p.Sources.DepsDev.Enabled && (needsDepsVersion || needsDepsDeprecated || needsDepsRepository) {
		v, data, err := FetchVersion(ctx, m.t, id)
		out.Diagnostics = append(out.Diagnostics, ProviderDiagnostics("deps_dev", data.Diagnostics)...)
		if err != nil {
			out.Diagnostics = append(out.Diagnostics, transport.ErrorDiagnostic("deps_dev", err))
		}
		if needsDepsVersion {
			out.Version = VerifyVersion(m.t, id, v, data, err, asOf)
		}
		if err == nil && data.Status == 200 {
			refs = append(refs, v.repositories(identity.VersionURL(p.Sources.DepsDev.BaseURL, id))...)
		}
		if model.Contains(requested, "DEPRECATED") {
			e, evidence := Deprecation(m.t, id, v, data, err)
			out.Evaluations = append(out.Evaluations, e)
			if evidence != nil {
				out.Signals = append(out.Signals, *evidence)
			}
		}
	}
	if p.Sources.GitHub.Enabled && model.Contains(requested, "ARCHIVED") && primary["ARCHIVED"].Status != "PRESENT" {
		e, evidence, ds := repositoryArchival(ctx, m.t, refs)
		out.Evaluations = append(out.Evaluations, e)
		out.Diagnostics = append(out.Diagnostics, ds...)
		if evidence != nil {
			out.Signals = append(out.Signals, *evidence)
		}
	}
	declarationEvaluations := append(append([]model.SignalEvaluation{}, known...), out.Evaluations...)
	skipDeclaration := declarationCanBeSkipped(p, id, asOf, m.t, out.Version, declarationEvaluations, primary)
	if model.Contains(requested, "DECLARED_UNMAINTAINED") && !skipDeclaration {
		declaredPresent := false
		if m.registry.enabled(id) {
			e, evidence, ds := m.registry.declaredUnmaintained(ctx, id)
			declaredPresent = e.Status == "PRESENT"
			out.Evaluations = append(out.Evaluations, e)
			out.Diagnostics = append(out.Diagnostics, ds...)
			if evidence != nil {
				out.Signals = append(out.Signals, *evidence)
			}
		}
		if needsRepository && !declaredPresent {
			e, evidence, ds := repositoryDeclaration(ctx, m.t, refs, id)
			out.Evaluations = append(out.Evaluations, e)
			out.Diagnostics = append(out.Diagnostics, ds...)
			if evidence != nil {
				out.Signals = append(out.Signals, *evidence)
			}
		}
	}
	if model.Contains(requested, "DECLARED_UNMAINTAINED") && skipDeclaration {
		primary["DECLARED_UNMAINTAINED"] = UnknownSignal("DECLARED_UNMAINTAINED", "NOT_NEEDED_FOR_EOL")
	}
	if p.Sources.GitHub.Enabled && model.Contains(requested, "STALE_REPOSITORY") {
		e, evidence, ds := repositoryInactivity(ctx, m.t, refs, asOf)
		out.Evaluations = append(out.Evaluations, e)
		out.Diagnostics = append(out.Diagnostics, ds...)
		if evidence != nil {
			out.Signals = append(out.Signals, *evidence)
		}
	}
	if p.Sources.DepsDev.Enabled && model.Contains(requested, "STALE_RELEASE") && primary["STALE_RELEASE"].Status == "UNKNOWN" {
		e, evidence, diagnostics := StaleRelease(ctx, m.t, id, asOf)
		out.Evaluations = append(out.Evaluations, e)
		out.Diagnostics = append(out.Diagnostics, diagnostics...)
		if evidence != nil {
			out.Signals = append(out.Signals, *evidence)
		}
	}
	for _, kind := range requested {
		out.Evaluations = append(out.Evaluations, primary[kind])
	}
	out.Diagnostics = append(out.Diagnostics, PublicationDiagnostic(model.Text(out.Version.ProviderID), out.Version)...)
	return out
}

// Avoid another API request when a verified live fact already satisfies an
// independent OR rule. CI-required declarations are always evaluated. The
// skipped condition remains UNKNOWN in the report, never an invented absence.
func declarationCanBeSkipped(p model.Policy, id identity.Identity, asOf string, t *transport.Transport, verification model.VersionVerification, evaluations []model.SignalEvaluation, primary map[string]model.SignalEvaluation) bool {
	if verification.Status != "VERIFIED" || asOf != model.UTCDate(t.Now()) || model.Contains(p.CI.FailOnSignals, "DECLARED_UNMAINTAINED") {
		return false
	}
	for _, kind := range []string{"ARCHIVED", "DEPRECATED", "RELEASE_SERIES_EOL"} {
		positive, negative := primary[kind].Status == "PRESENT", primary[kind].Status == "ABSENT"
		for _, e := range evaluations {
			if e.Type == kind {
				positive = positive || e.Status == "PRESENT"
				negative = negative || e.Status == "ABSENT"
			}
		}
		if !positive || kind != "ARCHIVED" && negative {
			continue
		}
		for _, rule := range config.ApplicableEOLRules(p, id) {
			if model.Contains(rule.AnyOf, kind) || len(rule.AllOf) == 1 && rule.AllOf[0] == kind {
				return true
			}
		}
	}
	return false
}

// Version details certify one platform. Keep other platform/ABI records so a
// positive result cannot silently mean that every artifact was checked.
func supplementGemYanks(pkg, detail packageSnapshot, id identity.Identity) packageSnapshot {
	if detail.Data.Status != 200 {
		return detail
	}
	records := append([]release{}, pkg.records(id)...)
	if len(records) == 0 {
		records = append(records, release{})
	}
	for _, extra := range detail.records(id) {
		matched, index := 0, 0
		for i, existing := range records {
			if existing.Platform == extra.Platform {
				matched++
				index = i
			}
		}
		if matched == 1 {
			records[index].Yanked = extra.Yanked
		} else {
			records = append(records, extra)
		}
	}
	detail.Versions = map[string][]release{id.Version: records}
	return detail
}

func missingYankStatus(records []release) bool {
	if len(records) == 0 {
		return true
	}
	for _, v := range records {
		if v.Yanked == nil {
			return true
		}
	}
	return false
}
