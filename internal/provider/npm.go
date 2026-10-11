package provider

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
)

func (r *registry) npm(ctx context.Context, id identity.Identity) (packageSnapshot, error) {
	s := packageSnapshot{Provider: "npm", URL: config.CleanBase(r.t.Policy().Sources.NPM.BaseURL) + "/" + url.PathEscape(id.Name), Versions: map[string][]release{}, Complete: true}
	var doc struct {
		Name     string `json:"name"`
		Versions map[string]struct {
			Name       string  `json:"name"`
			Version    string  `json:"version"`
			Deprecated *string `json:"deprecated"`
		} `json:"versions"`
		Time map[string]json.RawMessage `json:"time"`
	}
	var err error
	s.Data, err = r.decode(ctx, s.URL, "application/json", &doc)
	if err != nil || s.Data.Status != 200 {
		return s, err
	}
	if identity.NormalizeName("NPM", doc.Name) != id.Name || doc.Versions == nil {
		return r.mismatch(s, "application/json")
	}
	for version, v := range doc.Versions {
		if v.Version != version || identity.NormalizeName("NPM", v.Name) != id.Name {
			return r.mismatch(s, "application/json")
		}
		published := ""
		if raw := doc.Time[version]; len(raw) > 0 && json.Unmarshal(raw, &published) != nil {
			return r.mismatch(s, "application/json")
		}
		// npm specifies that irrelevant version fields are omitted. A valid
		// full version document without a deprecation message is negative
		// evidence; an unavailable or malformed document is never negative.
		reason := ""
		if v.Deprecated != nil {
			reason = *v.Deprecated
		}
		s.Versions[version] = []release{{PublishedAt: published, Deprecated: model.Ptr(strings.TrimSpace(reason) != ""), Reason: reason}}
	}
	// The package timestamp map may retain publication dates for removed
	// versions. Omitting them could falsely report prolonged inactivity.
	for version := range doc.Time {
		if version != "created" && version != "modified" && s.Versions[version] == nil {
			s.Complete = false
		}
	}
	return s, nil
}
