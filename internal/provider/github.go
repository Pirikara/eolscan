package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/contract"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/transport"
)

type repositoryRef struct {
	ProjectID, MappingURL, Provenance string
}

var githubSegment = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// Only publisher-declared source links are passed here. Metadata URLs are
// parsed into an identity; the URL itself is never fetched.
func githubProject(raw string) string {
	if strings.HasPrefix(raw, "github.com/") {
		raw = "https://" + raw
	}
	if strings.HasPrefix(raw, "git@github.com:") {
		raw = "https://github.com/" + strings.TrimPrefix(raw, "git@github.com:")
	}
	raw = strings.TrimPrefix(raw, "git+")
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Host, "github.com") || u.RawQuery != "" || u.Opaque != "" ||
		!model.Contains([]string{"https", "http", "git", "ssh"}, u.Scheme) || u.User != nil && (u.Scheme != "ssh" || u.User.String() != "git") {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return ""
	}
	owner, name := parts[0], strings.TrimSuffix(parts[1], ".git")
	if !githubSegment.MatchString(owner) || !githubSegment.MatchString(name) || owner == "." || owner == ".." || name == "." || name == ".." {
		return ""
	}
	return "github.com/" + strings.ToLower(owner+"/"+name)
}

func repositoryMetadata(raw json.RawMessage, mappingURL string) []repositoryRef {
	var value string
	if json.Unmarshal(raw, &value) != nil {
		var doc struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(raw, &doc) != nil {
			return nil
		}
		value = doc.URL
	}
	if id := githubProject(value); id != "" {
		return []repositoryRef{{ProjectID: id, MappingURL: mappingURL, Provenance: "REGISTRY_METADATA"}}
	}
	return nil
}

func repositoryArchival(ctx context.Context, t *transport.Transport, refs []repositoryRef) (model.SignalEvaluation, *model.SignalEvidence, []model.Diagnostic) {
	unknown := func(reason string, ds []model.Diagnostic) (model.SignalEvaluation, *model.SignalEvidence, []model.Diagnostic) {
		e := UnknownSignal("ARCHIVED", reason)
		e.ProviderID = model.Ptr("github")
		return e, nil, ds
	}
	if !t.Policy().Sources.GitHub.Enabled {
		return unknown("NO_CAPABILITY", nil)
	}
	// Prefer verified origin/attestation mappings. Multiple equally trusted
	// source repositories are ambiguous, rather than independently archived.
	selected := map[string]repositoryRef{}
	tier := 0
	for _, ref := range refs {
		project := githubProject(ref.ProjectID)
		if project == "" {
			continue
		}
		rank := 1
		if model.Contains([]string{"SLSA_ATTESTATION", "GO_ORIGIN", "PYPI_PUBLISH_ATTESTATION", "RUBYGEMS_PUBLISH_ATTESTATION"}, ref.Provenance) {
			rank = 2
		}
		if rank > tier {
			tier, selected = rank, map[string]repositoryRef{}
		}
		if rank == tier {
			selected[project] = ref
		}
	}
	if len(selected) == 0 {
		return unknown("NO_GITHUB_SOURCE_REPOSITORY", nil)
	}
	if len(selected) != 1 {
		return unknown("AMBIGUOUS_SOURCE_REPOSITORY", nil)
	}
	var project string
	var ref repositoryRef
	for project, ref = range selected {
	}
	name := strings.TrimPrefix(project, "github.com/")
	raw := config.CleanBase(t.Policy().Sources.GitHub.BaseURL) + "/repos/" + name
	data, err := t.Get(ctx, raw)
	ds := ProviderDiagnostics("github", data.Diagnostics)
	e := model.SignalEvaluation{Type: "ARCHIVED", Status: "UNKNOWN", ProviderID: model.Ptr("github"), SourceURL: model.Ptr(raw), CheckedAt: model.Nullable(data.ObservedAt)}
	if err != nil {
		ds = append(ds, transport.ErrorDiagnostic("github", err))
		e.ReasonCode = model.Ptr("SOURCE_ERROR")
		return e, nil, ds
	}
	if data.Status != 200 {
		e.ReasonCode = model.Ptr("REPOSITORY_NOT_FOUND")
		return e, nil, ds
	}
	var doc struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
		Archived *bool  `json:"archived"`
	}
	resolved := data.ResolvedURL
	if resolved == "" {
		resolved = raw
	}
	u, urlErr := url.Parse(resolved)
	base, _ := url.Parse(t.Policy().Sources.GitHub.BaseURL)
	// Evaluate identity only after decoding. A renamed repository is accepted
	// when the same API redirects to its canonical identity.
	decodeErr := contract.InspectJSON(data.Body, 256)
	if decodeErr == nil {
		decodeErr = json.Unmarshal(data.Body, &doc)
	}
	validIdentity := false
	if urlErr == nil && transport.AllowedURL(u, t.Policy()) && u.Host == base.Host && githubProject("github.com/"+doc.FullName) != "" {
		prefix := strings.TrimRight(base.Path, "/")
		validIdentity = strings.EqualFold(u.Path, prefix+"/repos/"+doc.FullName) ||
			doc.ID > 0 && u.Path == prefix+"/repositories/"+fmt.Sprint(doc.ID)
	}
	if decodeErr != nil || doc.Archived == nil || !validIdentity {
		t.Invalidate(raw)
		e.ReasonCode = model.Ptr("PROVIDER_SCHEMA_MISMATCH")
		ds = append(ds, model.NewDiagnostic("PROVIDER_SCHEMA_MISMATCH", "github", "Repository identity or archived status could not be verified"))
		return e, nil, ds
	}
	if !*doc.Archived {
		e.Status, e.ReasonCode = "ABSENT", nil
		return e, nil, ds
	}
	e.Status, e.ReasonCode = "PRESENT", nil
	return e, &model.SignalEvidence{Type: "ARCHIVED", ProviderID: "github", SourceURL: model.Ptr(raw), ObservedAt: data.ObservedAt,
		Details: map[string]any{"scope": "source_repository", "repository": "https://github.com/" + doc.FullName, "mapping_source_url": ref.MappingURL, "mapping_provenance": ref.Provenance, "raw_payload_hash": contract.Digest(data.Body)}}, ds
}
