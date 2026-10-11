package identity_test

import (
	"testing"

	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
)

func TestIdentityAndCycleBoundaries(t *testing.T) {
	t.Run("UT12_numeric_segment_boundary", func(t *testing.T) {
		for _, v := range []string{"7.20.1", "7.2.4-rc1", "2024.2", "7.2.4+meta"} {
			if identity.NumericCycleMatches(v, "7.2") {
				t.Fatalf("matched %s", v)
			}
		}
		if !identity.NumericCycleMatches("7.2.4", "7.2") || identity.NumericCycleMatches("7.2", "7.2.1") {
			t.Fatal("incorrect segment comparison")
		}
	})
	cases := []struct{ purl, system, name, version string }{
		{"pkg:npm/%40scope/name@1.2.3", "NPM", "@scope/name", "1.2.3"},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.24.0", "MAVEN", "org.apache.logging.log4j:log4j-core", "2.24.0"},
		{"pkg:golang/github.com/user/module@v1.2.3", "GO", "github.com/user/module", "v1.2.3"},
		{"pkg:pypi/Foo_Bar@1.0", "PYPI", "foo-bar", "1.0"},
		{"pkg:nuget/Example@01.02.0.0+build", "NUGET", "example", "1.2.0"},
	}
	for _, tt := range cases {
		id, reason := identity.Resolve(model.Component{PURL: tt.purl})
		if reason != "" || id.System != tt.system || id.Name != tt.name || id.Version != tt.version {
			t.Fatalf("%s => %+v %s", tt.purl, id, reason)
		}
	}
	invalid := []struct{ purl, version, reason string }{
		{"", "", "MISSING_PURL"}, {"not-a-purl", "", "INVALID_PURL"}, {"pkg:gem/a", "", "VERSION_UNRESOLVED"},
		{"pkg:gem/a@latest", "", "VERSION_UNRESOLVED"}, {"pkg:npm/a@%5E1.2", "", "VERSION_UNRESOLVED"},
		{"pkg:gem/a@1.0", "2.0", "VERSION_CONFLICT"}, {"pkg:oci/a@1", "", "UNSUPPORTED_ECOSYSTEM"},
		{"pkg:gem/a@1?repository_url=https%3A%2F%2Fprivate.example", "", "PRIVATE_SOURCE_UNSUPPORTED"},
		{"pkg:golang/example.org/a@1#subdir", "", "PRIVATE_SOURCE_UNSUPPORTED"},
	}
	for _, tt := range invalid {
		if _, reason := identity.Resolve(model.Component{PURL: tt.purl, Version: tt.version}); reason != tt.reason {
			t.Fatalf("%s: %s wanted %s", tt.purl, reason, tt.reason)
		}
	}
}
