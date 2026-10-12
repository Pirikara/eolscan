package acceptance

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/scanner"
	"github.com/Pirikara/eolscan/internal/testutil"
)

func TestDefaultCatalogProducesLifecycleResultsWithVerifiedVersions(t *testing.T) {
	for _, tc := range []struct {
		name, purl, published, asOf, status, reason string
		runAt                                       time.Time
	}{
		{"angular_18_eol", "pkg:npm/%40angular/core@18.0.0", "2024-05-22T00:00:00Z", "2026-10-12", "EOL", "", testutil.FixedNow.AddDate(0, 0, 1)},
		{"angular_19_eol", "pkg:npm/%40angular/core@19.0.0", "2024-11-19T00:00:00Z", "2026-10-12", "EOL", "", testutil.FixedNow.AddDate(0, 0, 1)},
		{"angular_20_supported", "pkg:npm/%40angular/core@20.0.0", "2025-05-28T00:00:00Z", "2026-10-12", "SUPPORTED", "", testutil.FixedNow.AddDate(0, 0, 1)},
		{"rails_7.2_eol", "pkg:gem/rails@7.2.0", "2024-08-09T00:00:00Z", "2026-10-12", "EOL", "", testutil.FixedNow.AddDate(0, 0, 1)},
		{"rails_8.0_supported", "pkg:gem/rails@8.0.0", "2024-11-07T00:00:00Z", "2026-10-12", "SUPPORTED", "", testutil.FixedNow.AddDate(0, 0, 1)},
		{"unreviewed_series", "pkg:npm/%40angular/core@21.0.0", "2025-11-19T00:00:00Z", "2026-10-12", "UNKNOWN", "NO_LIFECYCLE_EVIDENCE", testutil.FixedNow.AddDate(0, 0, 1)},
		{"expiry_uses_execution_date", "pkg:npm/%40angular/core@20.0.0", "2025-05-28T00:00:00Z", "2026-10-12", "UNKNOWN", "STALE_EVIDENCE", time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)},
		{"day_before_cutoff", "pkg:npm/%40angular/core@20.0.0", "2025-05-28T00:00:00Z", "2026-11-27", "SUPPORTED", "", testutil.FixedNow.AddDate(0, 0, 1)},
		{"cutoff_day", "pkg:npm/%40angular/core@20.0.0", "2025-05-28T00:00:00Z", "2026-11-28", "EOL", "", testutil.FixedNow.AddDate(0, 0, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := config.Default()
			p.Sources.EndoflifeDate.Enabled = false
			p.Sources.DepsDev.Enabled = false
			p.Signals.Deprecated, p.Signals.StaleReleaseDays = false, nil
			bundle, err := config.LoadBundle(p, "")
			if err != nil {
				t.Fatal(err)
			}
			id, reason := identity.Resolve(model.Component{PURL: tc.purl})
			if reason != "" {
				t.Fatal(reason)
			}
			stub := testutil.NewStub()
			if id.Type == "npm" {
				testutil.PutJSON(t, stub, "registry.npmjs.org/"+url.PathEscape(id.Name), map[string]any{
					"name":     id.Name,
					"versions": map[string]any{id.Version: map[string]any{"name": id.Name, "version": id.Version}},
					"time":     map[string]string{id.Version: tc.published},
				})
			} else {
				testutil.PutJSON(t, stub, "rubygems.org/api/v1/versions/rails.json", []map[string]any{
					{"number": id.Version, "platform": "ruby", "created_at": tc.published},
				})
			}
			s := scanner.New(bundle, stub.Client(), tc.runAt, tc.asOf, false)
			report, err := s.Scan(context.Background(), componentSBOM(tc.purl))
			if err != nil {
				t.Fatal(err)
			}
			confidence := "HIGH"
			if tc.status == "UNKNOWN" {
				confidence = ""
			}
			row := expectLifecycle(t, report, tc.status, confidence, tc.reason)
			if row.VersionVerification.Status != "VERIFIED" || report.CIGate.Passed != (tc.status != "EOL") {
				t.Fatalf("publication or CI gate=%+v row=%+v", report.CIGate, row)
			}
		})
	}
}
