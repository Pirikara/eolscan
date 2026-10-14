package provider

import (
	"context"
	"testing"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/testutil"
	"github.com/Pirikara/eolscan/internal/transport"
)

func TestRepositoryURLParsingDoesNotFetchArbitraryURLs(t *testing.T) {
	for _, raw := range []string{"https://github.com.evil.invalid/owner/repo", "https://user:secret@github.com/owner/repo", "https://github.com/owner/repo?token=secret", "https://github.com/owner/..", "https://github.com:443/owner/repo", "https://example.org/owner/repo", "https://github.com/owner"} {
		if githubProject(raw) != "" {
			t.Fatalf("accepted ambiguous source URL %q", raw)
		}
	}
	for _, raw := range []string{"git+https://github.com/Owner/Repo.git", "git@github.com:Owner/Repo.git", "ssh://git@github.com/Owner/Repo.git", "http://github.com/Owner/Repo/tree/v1.0.0", "github.com/Owner/Repo"} {
		if githubProject(raw) != "github.com/owner/repo" {
			t.Fatalf("source identity was lost: %s", raw)
		}
	}
}

func TestRepositorySelectionUsesProvenanceAndRejectsAmbiguity(t *testing.T) {
	metadata := repositoryRef{ProjectID: "github.com/publisher/old", MappingURL: "https://registry.npmjs.org/leaf", Provenance: "UNVERIFIED_METADATA"}
	verified := repositoryRef{ProjectID: "github.com/publisher/current", MappingURL: "https://api.deps.dev/v3/example", Provenance: "SLSA_ATTESTATION"}
	other := repositoryRef{ProjectID: "github.com/publisher/other", MappingURL: "https://api.deps.dev/v3/example", Provenance: "GO_ORIGIN"}
	for _, tc := range []struct {
		name, project, reason string
		refs                  []repositoryRef
	}{
		{"one_metadata_mapping", "publisher/old", "", []repositoryRef{metadata}},
		{"verified_mapping_overrides_metadata", "publisher/current", "", []repositoryRef{metadata, verified}},
		{"order_does_not_change_trust", "publisher/current", "", []repositoryRef{verified, metadata}},
		{"duplicate_mapping_is_not_ambiguous", "publisher/old", "", []repositoryRef{metadata, metadata}},
		{"conflicting_unverified_mappings", "", "AMBIGUOUS_SOURCE_REPOSITORY", []repositoryRef{metadata, {ProjectID: "github.com/publisher/other"}}},
		{"conflicting_verified_mappings", "", "AMBIGUOUS_SOURCE_REPOSITORY", []repositoryRef{verified, other}},
		{"no_mapping", "", "NO_GITHUB_SOURCE_REPOSITORY", nil},
		{"unsupported_source", "", "NO_GITHUB_SOURCE_REPOSITORY", []repositoryRef{{ProjectID: "https://gitlab.com/publisher/old"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := config.Default()
			stub := testutil.NewStub()
			if tc.project != "" {
				testutil.PutJSON(t, stub, "api.github.com/repos/"+tc.project, map[string]any{"full_name": tc.project, "archived": true})
			}
			clock := testutil.NewClock(testutil.FixedNow)
			tr := transport.New(stub.Client(), p, testutil.FixedNow, false, transport.WithClock(clock.Now), transport.WithWait(clock.Wait))
			evaluation, evidence, _ := repositoryArchival(context.Background(), tr, tc.refs)
			if tc.reason != "" {
				if evaluation.Status != "UNKNOWN" || model.Text(evaluation.ReasonCode) != tc.reason || evidence != nil || len(stub.Calls) != 0 {
					t.Fatalf("ambiguous mapping triggered a lookup or finding: %+v", evaluation)
				}
			} else if evaluation.Status != "PRESENT" || evidence == nil || evidence.Details["repository"] != "https://github.com/"+tc.project || len(stub.Calls) != 1 {
				t.Fatalf("repository selection: evaluation=%+v evidence=%+v calls=%v", evaluation, evidence, stub.Calls)
			}
		})
	}
}
