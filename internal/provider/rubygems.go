package provider

import (
	"context"
	"net/url"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/identity"
)

func (r *registry) rubygems(ctx context.Context, id identity.Identity) (packageSnapshot, error) {
	s := packageSnapshot{Provider: "rubygems", URL: config.CleanBase(r.t.Policy().Sources.RubyGems.BaseURL) + "/api/v1/versions/" + url.PathEscape(id.Name) + ".json", Versions: map[string][]release{}, Complete: true}
	var versions []struct {
		Number    string `json:"number"`
		Platform  string `json:"platform"`
		CreatedAt string `json:"created_at"`
		Yanked    *bool  `json:"yanked"`
	}
	var err error
	s.Data, err = r.decode(ctx, s.URL, "application/json", &versions)
	if err != nil || s.Data.Status != 200 {
		return s, err
	}
	if versions == nil {
		return r.mismatch(s, "application/json")
	}
	for _, v := range versions {
		if v.Number == "" {
			return r.mismatch(s, "application/json")
		}
		s.Versions[v.Number] = append(s.Versions[v.Number], release{PublishedAt: v.CreatedAt, Platform: v.Platform, Yanked: v.Yanked})
	}
	return s, nil
}

// The version endpoint supplies explicit yank status for an available release.
// A platform-qualified PURL requires the list's exact platform match; the v2
// endpoint's unspecified default platform must not certify another artifact.
func (r *registry) gemVersion(ctx context.Context, id identity.Identity) (packageSnapshot, error) {
	s := packageSnapshot{Provider: "rubygems", URL: config.CleanBase(r.t.Policy().Sources.RubyGems.BaseURL) + "/api/v2/rubygems/" + url.PathEscape(id.Name) + "/versions/" + url.PathEscape(id.Version) + ".json", Versions: map[string][]release{}}
	var v struct {
		Name          string `json:"name"`
		Version       string `json:"version"`
		Platform      string `json:"platform"`
		PublishedAt   string `json:"version_created_at"`
		Yanked        *bool  `json:"yanked"`
		SourceCodeURI string `json:"source_code_uri"`
		Metadata      struct {
			SourceCodeURI string `json:"source_code_uri"`
		} `json:"metadata"`
	}
	var err error
	s.Data, err = r.decode(ctx, s.URL, "application/json", &v)
	if err != nil || s.Data.Status != 200 {
		return s, err
	}
	if v.Name != id.Name || v.Version != id.Version || id.Platform != "" && v.Platform != id.Platform {
		return r.mismatch(s, "application/json")
	}
	s.Versions[v.Version] = []release{{PublishedAt: v.PublishedAt, Platform: v.Platform, Yanked: v.Yanked}}
	s.Repositories = map[string][]repositoryRef{}
	for _, raw := range []string{v.SourceCodeURI, v.Metadata.SourceCodeURI} {
		if project := githubProject(raw); project != "" {
			s.Repositories[v.Version] = append(s.Repositories[v.Version], repositoryRef{ProjectID: project, MappingURL: s.URL, Provenance: "REGISTRY_METADATA"})
		}
	}
	return s, nil
}
