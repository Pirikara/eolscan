package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/eolscan/internal/cli"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/testutil"
)

func TestTableShowsSupportProofAndPreservesTotalsWhenHidingRows(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		includeUnknown, evidence bool
	}{
		{"all_rows_with_evidence", true, true},
		{"all_rows_without_evidence", true, false},
		{"hide_unknown_preserves_totals", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			catalog, err := json.Marshal(testCatalog())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "catalog.yaml"), catalog, 0600); err != nil {
				t.Fatal(err)
			}
			p := offlinePolicy()
			p.Sources.OfficialCatalog.Enabled, p.Sources.OfficialCatalog.Path = true, model.Ptr("catalog.yaml")
			p.Output.IncludeUnknown, p.Output.IncludeEvidence = tc.includeUnknown, tc.evidence
			policy, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "policy.yaml")
			if err := os.WriteFile(path, policy, 0600); err != nil {
				t.Fatal(err)
			}
			input := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"known-gem","purl":"pkg:gem/example@2.4.7"},{"type":"library","name":"unverified-gem","purl":"pkg:gem/unversioned"}]}`
			stub := testutil.NewStub()
			var out, errs bytes.Buffer
			code := cli.Run(context.Background(), []string{"scan", "-i", "-", "-c", path, "--offline"}, strings.NewReader(input), &out, &errs, stub.Client(), testutil.FixedNow)
			if code != 0 || len(stub.Calls) != 0 {
				t.Fatalf("offline table exit=%d stderr=%s", code, errs.String())
			}
			for _, fragment := range []string{"SUPPORTED", "HIGH", "2026-12-01", "EOL_SOON(51d)", "Scanned 2", "supported 1", "unknown 1", "policy coverage 50.0%"} {
				if !strings.Contains(out.String(), fragment) {
					t.Fatalf("table lost %q: %s", fragment, out.String())
				}
			}
			if strings.Contains(out.String(), "unverified-gem") != tc.includeUnknown || strings.Contains(out.String(), "https://example.org/support/2.4") != tc.evidence {
				t.Fatalf("table visibility settings changed totals or ignored flags: %s", out.String())
			}
		})
	}
}
