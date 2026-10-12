package provider

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
)

const pypiJSON = "application/vnd.pypi.simple.v1+json"

var eggPythonTag = regexp.MustCompile(`^py[0-9]+(?:\.[0-9]+)?$`)

func (r *registry) pypi(ctx context.Context, id identity.Identity) (packageSnapshot, error) {
	s := packageSnapshot{Provider: "pypi", URL: config.CleanBase(r.t.Policy().Sources.PyPI.BaseURL) + "/simple/" + url.PathEscape(id.Name) + "/", Versions: map[string][]release{}, Complete: true}
	var doc struct {
		Name string `json:"name"`
		Meta struct {
			Version string `json:"api-version"`
		} `json:"meta"`
		ProjectStatus *struct {
			Status string `json:"status"`
		} `json:"project-status"`
		Versions []string `json:"versions"`
		Files    *[]struct {
			Filename   string          `json:"filename"`
			UploadTime string          `json:"upload-time"`
			Yanked     json.RawMessage `json:"yanked"`
		} `json:"files"`
	}
	var err error
	s.Data, err = r.decode(ctx, s.URL, pypiJSON, &doc)
	if err != nil || s.Data.Status != 200 {
		return s, err
	}
	if identity.NormalizeName("PYPI", doc.Name) != id.Name || !strings.HasPrefix(doc.Meta.Version, "1.") || doc.Files == nil {
		return r.mismatch(s, pypiJSON)
	}
	if doc.ProjectStatus != nil && model.Contains([]string{"active", "archived", "deprecated", "quarantined"}, doc.ProjectStatus.Status) {
		s.ProjectStatus = doc.ProjectStatus.Status
	}
	seen := map[string]bool{}
	for _, file := range *doc.Files {
		if file.Filename == "" || seen[file.Filename] || strings.ContainsAny(file.Filename, "/\\\x00") {
			return r.mismatch(s, pypiJSON)
		}
		seen[file.Filename] = true
		version, ok := pypiFileVersion(file.Filename, id.Name)
		if !ok {
			s.Complete = false
			s.UnassignedArtifacts = true
			continue
		}
		var yanked *bool
		reason := ""
		if len(file.Yanked) > 0 && string(file.Yanked) != "null" {
			var b bool
			if json.Unmarshal(file.Yanked, &b) == nil {
				yanked = model.Ptr(b)
			} else if json.Unmarshal(file.Yanked, &reason) == nil {
				yanked = model.Ptr(true)
			} else {
				return r.mismatch(s, pypiJSON)
			}
		}
		s.Versions[version] = append(s.Versions[version], release{PublishedAt: file.UploadTime, Yanked: yanked, Reason: reason})
	}
	// Keep known version identifiers even if their artifacts cannot be parsed
	// or have been removed. They still cannot establish publication time.
	for _, v := range doc.Versions {
		if len(s.Versions[v]) == 0 {
			s.Versions[v] = []release{{}}
			s.Complete = false
		}
	}
	return s, nil
}

func pypiFileVersion(filename, name string) (string, bool) {
	if strings.HasSuffix(filename, ".whl") {
		parts := strings.Split(strings.TrimSuffix(filename, ".whl"), "-")
		if (len(parts) == 5 || len(parts) == 6) && identity.NormalizeName("PYPI", parts[0]) == name && parts[1] != "" {
			return parts[1], true
		}
		return "", false
	}
	// PyPI retains legacy eggs. Their normalized distribution/version prefix
	// and mandatory Python tag identify the release just as wheel names do.
	if strings.HasSuffix(filename, ".egg") {
		parts := strings.Split(strings.TrimSuffix(filename, ".egg"), "-")
		if len(parts) >= 3 && identity.NormalizeName("PYPI", parts[0]) == name && parts[1] != "" && eggPythonTag.MatchString(parts[2]) {
			return parts[1], true
		}
		return "", false
	}
	stem := ""
	for _, ext := range []string{".tar.gz", ".zip"} {
		if strings.HasSuffix(filename, ext) {
			stem = strings.TrimSuffix(filename, ext)
			break
		}
	}
	i := strings.LastIndex(stem, "-")
	if i <= 0 || i == len(stem)-1 || identity.NormalizeName("PYPI", stem[:i]) != name {
		return "", false
	}
	return stem[i+1:], true
}
