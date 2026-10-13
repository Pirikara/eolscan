package provider

import "testing"

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
