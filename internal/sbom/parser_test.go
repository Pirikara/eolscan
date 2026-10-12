package sbom_test

import (
	"strings"
	"testing"

	"github.com/Pirikara/eolscan/internal/config"
	sbomparser "github.com/Pirikara/eolscan/internal/sbom"
)

func TestSBOMExtraction(t *testing.T) {
	p := config.Default().Input
	cdx := `{"bomFormat":"CycloneDX","specVersion":"1.7","metadata":{"component":{"type":"application","name":"root","version":"1"}},"components":[{"type":"application","name":"app","components":[{"type":"library","bom-ref":"dep","name":"dep","purl":"pkg:gem/dep@1.0"}]},{"type":"file","name":"binary"}]}`
	sbom, err := sbomparser.Parse(strings.NewReader(cdx), p)
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
	sbom, err = sbomparser.Parse(strings.NewReader(cdx), p)
	if err != nil || len(sbom.Components) != 3 {
		t.Fatalf("metadata: %+v %v", sbom, err)
	}
	spdx := `{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-dep","name":"dep","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:gem/dep@1.0"}]},{"name":"multi","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:gem/one@1"},{"referenceType":"purl","referenceLocator":"pkg:gem/two@1"}]}]}`
	sbom, err = sbomparser.Parse(strings.NewReader(spdx), p)
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
		if _, err := sbomparser.Parse(strings.NewReader(input), config.Default().Input); err == nil {
			t.Fatalf("accepted invalid SBOM: %s", input)
		}
	}
	p := config.Default().Input
	p.MaxInputBytes = 10
	if _, err := sbomparser.Parse(strings.NewReader(valid), p); err == nil {
		t.Fatal("size limit ignored")
	}
	p = config.Default().Input
	p.MaxJSONDepth = 2
	if _, err := sbomparser.Parse(strings.NewReader(valid), p); err == nil {
		t.Fatal("depth limit ignored")
	}
	p = config.Default().Input
	p.MaxComponents = 1
	two := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"one"},{"type":"file","name":"excluded"}]}`
	if _, err := sbomparser.Parse(strings.NewReader(two), p); err == nil {
		t.Fatal("excluded components bypassed count limit")
	}
}

func TestMetadataExclusionPreservesNestedComponents(t *testing.T) {
	input := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"subject","components":[{"type":"file","name":"assembly","components":[{"type":"library","bom-ref":"dep","name":"requests","purl":"pkg:pypi/requests@2.31.0"}]}]}}}`
	for _, includeSubject := range []bool{false, true} {
		p := config.Default().Input
		p.IncludeMetadataComponent = includeSubject
		result, err := sbomparser.Parse(strings.NewReader(input), p)
		if err != nil {
			t.Fatal(err)
		}
		wantCount, wantExcluded := 1, 2
		if includeSubject {
			wantCount, wantExcluded = 2, 1
		}
		if len(result.Components) != wantCount || result.Excluded != wantExcluded || result.Components[wantCount-1].SourceRef != "dep" {
			t.Fatalf("include subject=%t: %+v", includeSubject, result)
		}
	}
}
