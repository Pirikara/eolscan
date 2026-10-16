package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/contract"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/transport"
)

// Reuse archival's provenance, rename and repository-identity verification.
// Transport memoization shares the repository request across all conditions.
func repositoryState(ctx context.Context, t *transport.Transport, refs []repositoryRef, kind string) (model.SignalEvaluation, transport.HTTPData, []model.Diagnostic) {
	e, _, ds := repositoryArchival(ctx, t, refs)
	e.Type = kind
	if e.Status == "UNKNOWN" {
		if kind == "DECLARED_UNMAINTAINED" && model.Text(e.ReasonCode) == "NO_GITHUB_SOURCE_REPOSITORY" {
			e.ReasonCode = model.Ptr("NO_CAPABILITY")
		}
		return e, transport.HTTPData{}, ds
	}
	data, err := t.Get(ctx, model.Text(e.SourceURL))
	if err != nil {
		e.Status, e.ReasonCode = "UNKNOWN", model.Ptr("SOURCE_ERROR")
	}
	return e, data, ds
}

func repositoryInactivity(ctx context.Context, t *transport.Transport, refs []repositoryRef, asOf string) (model.SignalEvaluation, *model.SignalEvidence, []model.Diagnostic) {
	e, data, ds := repositoryState(ctx, t, refs, "STALE_REPOSITORY")
	unknown := func(reason string) (model.SignalEvaluation, *model.SignalEvidence, []model.Diagnostic) {
		e.Status, e.ReasonCode = "UNKNOWN", model.Ptr(reason)
		return e, nil, ds
	}
	if e.Status == "UNKNOWN" {
		return e, nil, ds
	}
	if t.Policy().Signals.StaleRepositoryDays == nil {
		return unknown("NO_CAPABILITY")
	}
	if asOf != model.UTCDate(t.Now()) {
		return unknown("STATUS_TIME_UNAVAILABLE")
	}
	var doc struct {
		PushedAt *string `json:"pushed_at"`
	}
	if json.Unmarshal(data.Body, &doc) != nil || doc.PushedAt == nil {
		return unknown("MISSING_REPOSITORY_ACTIVITY")
	}
	at, err := time.Parse(time.RFC3339Nano, *doc.PushedAt)
	if err != nil || at.After(t.Now()) {
		return unknown("INVALID_REPOSITORY_ACTIVITY")
	}
	days := releaseAge(at, asOf)
	e.Status, e.ReasonCode = "ABSENT", nil
	if days <= *t.Policy().Signals.StaleRepositoryDays {
		return e, nil, ds
	}
	e.Status = "PRESENT"
	return e, &model.SignalEvidence{Type: e.Type, ProviderID: "github", SourceURL: e.SourceURL, ObservedAt: data.ObservedAt,
		Details: map[string]any{"source_field": "pushed_at", "last_pushed_at": model.Timestamp(at), "days_since_last_push": days, "threshold_days": *t.Policy().Signals.StaleRepositoryDays, "scope": "source_repository", "raw_payload_hash": contract.Digest(data.Body)}}, ds
}

func repositoryDeclaration(ctx context.Context, t *transport.Transport, refs []repositoryRef, id identity.Identity) (model.SignalEvaluation, *model.SignalEvidence, []model.Diagnostic) {
	e, repository, ds := repositoryState(ctx, t, refs, "DECLARED_UNMAINTAINED")
	if e.Status == "UNKNOWN" {
		return e, nil, ds
	}
	var repo struct {
		FullName string `json:"full_name"`
	}
	_ = json.Unmarshal(repository.Body, &repo) // Verified by repositoryState.
	raw := config.CleanBase(t.Policy().Sources.GitHub.BaseURL) + "/repos/" + strings.ToLower(repo.FullName) + "/readme"
	data, err := t.Get(ctx, raw)
	ds = append(ds, ProviderDiagnostics("github", data.Diagnostics)...)
	e.Status, e.SourceURL, e.CheckedAt = "UNKNOWN", model.Ptr(raw), model.Nullable(data.ObservedAt)
	unknown := func(reason string) (model.SignalEvaluation, *model.SignalEvidence, []model.Diagnostic) {
		e.ReasonCode = model.Ptr(reason)
		return e, nil, ds
	}
	if err != nil {
		ds = append(ds, transport.ErrorDiagnostic("github", err))
		return unknown("SOURCE_ERROR")
	}
	if data.Status != 200 {
		return unknown("README_NOT_FOUND")
	}
	resolved := data.ResolvedURL
	if resolved == "" {
		resolved = raw
	}
	u, parseErr := url.Parse(resolved)
	want, _ := url.Parse(raw)
	if parseErr != nil || !transport.AllowedURL(u, t.Policy()) || u.Host != want.Host || !strings.EqualFold(u.Path, want.Path) {
		return unknown("PROVIDER_IDENTITY_MISMATCH")
	}
	var doc struct {
		Type     string `json:"type"`
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
		Path     string `json:"path"`
		Size     *int   `json:"size"`
	}
	if contract.InspectJSON(data.Body, 256) != nil || json.Unmarshal(data.Body, &doc) != nil ||
		doc.Type != "file" || doc.Encoding != "base64" || doc.Path == "" || doc.Size == nil || *doc.Size < 0 {
		t.Invalidate(raw)
		ds = append(ds, model.NewDiagnostic("PROVIDER_SCHEMA_MISMATCH", "github", "README response is malformed"))
		return unknown("PROVIDER_SCHEMA_MISMATCH")
	}
	if *doc.Size > maxDeclarationBytes || len(doc.Content) > maxDeclarationBytes*2 {
		return unknown("DECLARATION_TOO_LARGE")
	}
	content, err := base64.StdEncoding.DecodeString(doc.Content)
	if err != nil || len(content) != *doc.Size {
		return unknown("PROVIDER_SCHEMA_MISMATCH")
	}
	e, evidence := declaration("github", raw, "readme.content", string(content), nil, id, data, t.Policy())
	if evidence != nil {
		evidence.Details["repository"] = "https://github.com/" + repo.FullName
		evidence.Details["scope"] = "source_repository_declaration"
	}
	return e, evidence, ds
}
