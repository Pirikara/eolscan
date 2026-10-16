// Package identity normalizes PURLs and matches exact identities and release series.
package identity

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/Pirikara/eolscan/internal/model"
	purl "github.com/package-url/packageurl-go"
)

type Identity struct {
	PURL     string
	BasePURL string
	Type     string
	System   string
	Name     string
	Version  string
	Platform string
}

var systems = map[string]string{"gem": "RUBYGEMS", "npm": "NPM", "pypi": "PYPI", "maven": "MAVEN", "golang": "GO", "cargo": "CARGO", "nuget": "NUGET"}

var numeric = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*$`)

var pypiSeparator = regexp.MustCompile(`[-_.]+`)

func NormalizeName(system, name string) string {
	switch system {
	case "PYPI":
		return pypiSeparator.ReplaceAllString(strings.ToLower(name), "-")
	case "NUGET", "NPM":
		return strings.ToLower(name)
	default:
		return name
	}
}

func NormalizeVersion(system, version string) string {
	if system != "NUGET" {
		return version
	}
	// NuGet ignores metadata, leading zeroes and a zero fourth component.
	version = strings.ToLower(strings.SplitN(version, "+", 2)[0])
	parts := strings.SplitN(version, "-", 2)
	digits := strings.Split(parts[0], ".")
	if len(digits) > 4 {
		return version
	}
	for i, s := range digits {
		if s == "" || !numeric.MatchString(s) {
			return version
		}
		s = strings.TrimLeft(s, "0")
		if s == "" {
			s = "0"
		}
		digits[i] = s
	}
	for len(digits) < 3 {
		digits = append(digits, "0")
	}
	if len(digits) == 4 && digits[3] == "0" {
		digits = digits[:3]
	}
	out := strings.Join(digits, ".")
	if len(parts) == 2 {
		out += "-" + parts[1]
	}
	return out
}

func parsePackage(raw string) (purl.PackageURL, error) {
	if strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, " \r\n\t") {
		return purl.PackageURL{}, fmt.Errorf("invalid PURL whitespace")
	}
	p, err := purl.FromString(raw)
	if err != nil {
		return p, err
	}
	if p.Type == "" || p.Name == "" {
		return p, fmt.Errorf("missing PURL type/name")
	}
	system := systems[p.Type]
	if system != "" {
		// Qualifiers may change registry identity. Only inert artifact qualifiers
		// are safe to query against a public package index.
		for _, q := range p.Qualifiers {
			switch q.Key {
			case "arch", "os", "platform", "classifier", "type":
			default:
				return p, fmt.Errorf("private or ambiguous package source")
			}
		}
		if p.Subpath != "" {
			return p, fmt.Errorf("package subpath is not an exact registry identity")
		}
		switch p.Type {
		case "npm":
			if p.Namespace != "" && !strings.HasPrefix(p.Namespace, "@") {
				return p, fmt.Errorf("invalid npm scope")
			}
		case "maven":
			if p.Namespace == "" {
				return p, fmt.Errorf("Maven group ID is required")
			}
		case "gem", "pypi", "cargo", "nuget":
			if p.Namespace != "" {
				return p, fmt.Errorf("unsupported registry namespace")
			}
		}
		switch p.Type {
		case "pypi":
			p.Name = NormalizeName(system, p.Name)
		case "nuget", "npm":
			p.Name = strings.ToLower(p.Name)
			p.Namespace = strings.ToLower(p.Namespace)
		}
		p.Version = NormalizeVersion(system, p.Version)
	}
	return p, nil
}

func IndexPackage(raw string) (purl.PackageURL, bool, error) {
	p, err := purl.FromString(raw)
	if err != nil {
		return p, SupportedIndexPrefix(raw), err
	}
	if systems[p.Type] == "" || p.Version != "" || len(p.Qualifiers) > 0 || p.Subpath != "" {
		return p, false, nil
	}
	p, err = parsePackage(raw)
	return p, true, err
}

func Resolve(c model.Component) (Identity, string) {
	var id Identity
	if c.PURLConflict {
		return id, "AMBIGUOUS_IDENTITY"
	}
	if c.PURL == "" {
		return id, "MISSING_PURL"
	}
	p, err := parsePackage(c.PURL)
	if err != nil {
		if strings.Contains(err.Error(), "private or ambiguous") || strings.Contains(err.Error(), "subpath") {
			return id, "PRIVATE_SOURCE_UNSUPPORTED"
		}
		return id, "INVALID_PURL"
	}
	id.Type = p.Type
	if p.Type == "gem" {
		for _, q := range p.Qualifiers {
			if q.Key == "platform" {
				id.Platform = q.Value
			}
		}
	}
	id.System = systems[p.Type]
	id.Version = p.Version
	id.Name = p.Name
	if p.Namespace != "" {
		if p.Type == "maven" {
			id.Name = p.Namespace + ":" + p.Name
		} else {
			id.Name = p.Namespace + "/" + p.Name
		}
	}
	id.Name = NormalizeName(id.System, id.Name)
	if id.System == "" {
		return id, "UNSUPPORTED_ECOSYSTEM"
	}
	// Version ranges and moving tags cannot certify an exact registry version.
	if p.Version == "" || strings.ContainsAny(p.Version, "*<>=~^|, \t") || strings.HasPrefix(p.Version, "[") || strings.HasPrefix(p.Version, "(") ||
		model.Contains([]string{"latest", "next", "stable", "release", "head", "master", "main"}, strings.ToLower(p.Version)) {
		return id, "VERSION_UNRESOLVED"
	}
	if c.Version != "" && NormalizeVersion(id.System, c.Version) != p.Version {
		return id, "VERSION_CONFLICT"
	}
	id.PURL = p.ToString()
	p.Version = ""
	p.Qualifiers = nil
	p.Subpath = ""
	id.BasePURL = p.ToString()
	return id, ""
}

func Base(raw string) (string, error) {
	p, err := parsePackage(raw)
	if err != nil {
		return "", err
	}
	if p.Version != "" || p.Subpath != "" || len(p.Qualifiers) > 0 || systems[p.Type] == "" {
		return "", fmt.Errorf("expected unqualified versionless PURL")
	}
	return p.ToString(), nil
}

func PackageURL(base string, id Identity) string {
	return strings.TrimRight(base, "/") + "/systems/" + strings.ToLower(id.System) + "/packages/" + url.PathEscape(id.Name)
}

func VersionURL(base string, id Identity) string {
	return PackageURL(base, id) + "/versions/" + url.PathEscape(id.Version)
}

func NumericSegmentsMatch(version, cycle string) bool {
	version = strings.TrimPrefix(version, "v")
	// Prereleases, pseudo-versions and date series require an explicit mapping.
	if !numeric.MatchString(version) || !numeric.MatchString(cycle) {
		return false
	}
	v, c := strings.Split(version, "."), strings.Split(cycle, ".")
	if len(v) < len(c) {
		return false
	}
	for i := range c {
		if v[i] != c[i] {
			return false
		}
	}
	return true
}

// Redact structured credentials in rejected/private PURLs without making them
// eligible for matching or changing the input byte hash.
func RedactPURL(raw string) string {
	p, err := purl.FromString(raw)
	if err != nil {
		return raw
	}
	changed := false
	for i, q := range p.Qualifiers {
		key := strings.ToLower(q.Key)
		if model.Contains([]string{"token", "access_token", "api_key", "apikey", "password", "secret", "authorization", "auth", "key"}, key) {
			p.Qualifiers[i].Value = "REDACTED"
			changed = true
			continue
		}
		u, err := url.Parse(q.Value)
		if err != nil || u.Scheme == "" {
			continue
		}
		query := u.Query()
		masked := false
		if u.User != nil {
			u.User = nil
			masked = true
		}
		for k := range query {
			if model.Contains([]string{"token", "access_token", "api_key", "apikey", "password", "secret", "authorization", "auth", "key"}, strings.ToLower(k)) {
				query.Set(k, "REDACTED")
				masked = true
			}
		}
		if masked {
			u.RawQuery = query.Encode()
			p.Qualifiers[i].Value = u.String()
			changed = true
		}
	}
	if changed {
		return p.ToString()
	}
	return raw
}

// Public API cycle matching excludes date-based schemes. A reviewed local
// numeric mapping may explicitly cover such a scheme.
func NumericCycleMatches(version, cycle string) bool {
	if !NumericSegmentsMatch(version, cycle) {
		return false
	}
	first := strings.Split(cycle, ".")[0]
	return !(len(first) == 4 && first >= "1900" && first <= "2999")
}

// SeriesVersion removes only Maven's stable release aliases when comparing
// release series. The original identity still verifies the exact published
// version; prereleases, service packs and arbitrary qualifiers stay intact.
func SeriesVersion(id Identity) string {
	if id.Type == "maven" {
		for _, separator := range []string{".", "-", "_"} {
			for _, alias := range []string{"release", "final", "ga"} {
				suffix := separator + alias
				if strings.HasSuffix(strings.ToLower(id.Version), suffix) {
					base := id.Version[:len(id.Version)-len(suffix)]
					if numeric.MatchString(base) {
						return base
					}
				}
			}
		}
	}
	return id.Version
}

func SupportedIndexPrefix(raw string) bool {
	for kind := range systems {
		if strings.HasPrefix(strings.ToLower(raw), "pkg:"+kind+"/") {
			return true
		}
	}
	return false
}
