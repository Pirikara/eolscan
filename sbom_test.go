package main

import (
	"strings"
	"testing"
)

func TestSBOMExtraction(t *testing.T) {
	p := defaultPolicy().Input
	cdx := `{"bomFormat":"CycloneDX","specVersion":"1.7","metadata":{"component":{"type":"application","name":"root","version":"1"}},"components":[{"type":"application","name":"app","components":[{"type":"library","bom-ref":"dep","name":"dep","purl":"pkg:gem/dep@1.0"}]},{"type":"file","name":"binary"}]}`
	sbom, err := parseSBOM(strings.NewReader(cdx), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(sbom.Components) != 2 || sbom.Excluded != 2 || sbom.Components[1].SourceRef != "dep" {
		t.Fatalf("SBOM: %+v", sbom)
	}
	if sbom.Components[0].SourceRef != "/components/0" {
		t.Fatal("unstable fallback reference")
	}
	if sbom.Components[0].Version != "" {
		t.Fatal("missing version was discarded or synthesized")
	}
	p.IncludeMetadataComponent = true
	sbom, err = parseSBOM(strings.NewReader(cdx), p)
	if err != nil || len(sbom.Components) != 3 {
		t.Fatalf("metadata: %+v %v", sbom, err)
	}
	spdx := `{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-dep","name":"dep","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:gem/dep@1.0"}]},{"name":"multi","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:gem/one@1"},{"referenceType":"purl","referenceLocator":"pkg:gem/two@1"}]}]}`
	sbom, err = parseSBOM(strings.NewReader(spdx), p)
	if err != nil || len(sbom.Components) != 2 || sbom.Components[0].SourceRef != "SPDXRef-dep" || !sbom.Components[1].PURLConflict {
		t.Fatalf("SPDX: %+v %v", sbom, err)
	}
}

func TestSBOMInputLimitsAndFormats(t *testing.T) {
	valid := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"dep"}]}`
	for _, input := range []string{
		`{"artifacts":[]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.3","components":[]}`,
		`{"spdxVersion":"SPDX-3.0","packages":[]}`,
		valid + " {}",
		`{"bomFormat":"CycloneDX","bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`,
		"null",
		valid + " junk",
	} {
		if _, err := parseSBOM(strings.NewReader(input), defaultPolicy().Input); err == nil {
			t.Fatalf("accepted invalid SBOM: %s", input)
		}
	}
	p := defaultPolicy().Input
	p.MaxInputBytes = 10
	if _, err := parseSBOM(strings.NewReader(valid), p); err == nil {
		t.Fatal("size limit ignored")
	}
	p = defaultPolicy().Input
	p.MaxJSONDepth = 2
	if _, err := parseSBOM(strings.NewReader(valid), p); err == nil {
		t.Fatal("depth limit ignored")
	}
	p = defaultPolicy().Input
	p.MaxComponents = 1
	two := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"one"},{"type":"file","name":"excluded"}]}`
	if _, err := parseSBOM(strings.NewReader(two), p); err == nil {
		t.Fatal("excluded components bypassed count limit")
	}
}
func TestIdentityAndCycleBoundaries(t *testing.T) {
	t.Run("UT12_numeric_segment_boundary", func(t *testing.T) {
		for _, v := range []string{"7.20.1", "7.2.4-rc1", "2024.2", "7.2.4+meta"} {
			if numericCycleMatches(v, "7.2") {
				t.Fatalf("matched %s", v)
			}
		}
		if !numericCycleMatches("7.2.4", "7.2") || numericCycleMatches("7.2", "7.2.1") {
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
		id, reason := resolveIdentity(Component{PURL: tt.purl})
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
		if _, reason := resolveIdentity(Component{PURL: tt.purl, Version: tt.version}); reason != tt.reason {
			t.Fatalf("%s: %s wanted %s", tt.purl, reason, tt.reason)
		}
	}
}
