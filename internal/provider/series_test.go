package provider

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/testutil"
	"github.com/Pirikara/eolscan/internal/transport"
)

func TestReleaseSeriesEOLFacts(t *testing.T) {
	for _, tc := range []struct {
		name, asOf, status, reason string
		end                        *string
		flag                       bool
		conflict                   bool
	}{
		{"general_past", "2026-10-11", "PRESENT", "", model.Ptr("2026-10-01"), true, false},
		{"end_day", "2026-10-11", "PRESENT", "", model.Ptr("2026-10-11"), false, false},
		{"future_end", "2026-10-11", "ABSENT", "", model.Ptr("2026-12-01"), false, false},
		{"historical_date", "2026-10-01", "PRESENT", "", model.Ptr("2026-10-01"), true, false},
		{"projected_date", "2026-12-01", "PRESENT", "", model.Ptr("2026-12-01"), false, false},
		{"undated_live_flag", "2026-10-11", "PRESENT", "", nil, true, false},
		{"undated_negative", "2026-10-11", "ABSENT", "", nil, false, false},
		{"undated_historical", "2026-10-01", "UNKNOWN", "STATUS_TIME_UNAVAILABLE", nil, true, false},
		{"undated_future", "2026-12-01", "UNKNOWN", "STATUS_TIME_UNAVAILABLE", nil, true, false},
		{"future_conflict", "2026-10-11", "UNKNOWN", "AMBIGUOUS_CYCLE", model.Ptr("2026-10-01"), true, true},
		{"invalid_date", "2026-10-11", "UNKNOWN", "SOURCE_ERROR", model.Ptr("not-a-date"), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := config.Default()
			stub := testutil.NewStub()
			stub.Bodies["endoflife.date/api/v1/identifiers/purl/"] = testutil.IndexBody("example")
			var product map[string]any
			json.Unmarshal([]byte(testutil.ProductBody("example", "2.4", tc.end, false)), &product)
			result := product["result"].(map[string]any)
			result["labels"] = map[string]any{"eol": "Support"}
			releases := result["releases"].([]any)
			releases[0].(map[string]any)["isEol"] = tc.flag
			if tc.conflict {
				result["releases"] = append(releases, map[string]any{"name": "2.4", "eolFrom": "2026-12-01", "isEol": false, "isMaintained": false})
			}
			testutil.PutJSON(t, stub, "endoflife.date/api/v1/products/example/", product)
			clock := testutil.NewClock(testutil.FixedNow)
			tr := transport.New(stub.Client(), p, testutil.FixedNow, false, transport.WithClock(clock.Now), transport.WithWait(clock.Wait))
			provider := NewEOL(tr, model.PolicyBundle{Policy: p})
			id, _ := identity.Resolve(model.Component{PURL: "pkg:gem/example@2.4.7"})
			out := provider.Collect(context.Background(), id, tc.asOf, true)
			e := out.SeriesEvaluation
			if e == nil || e.Status != tc.status || model.Text(e.ReasonCode) != tc.reason || (out.SeriesEvidence != nil) != (tc.status == "PRESENT") {
				t.Fatalf("%+v", out)
			}
			if tc.status == "PRESENT" && tc.end != nil && out.SeriesEvidence.Details["eol_effective_date"] != *tc.end {
				t.Fatal("actual end date was lost")
			}
			if tc.status == "PRESENT" && tc.end == nil {
				if _, exists := out.SeriesEvidence.Details["eol_effective_date"]; exists {
					t.Fatal("invented a date for a live flag")
				}
			}
			provider.Collect(context.Background(), id, tc.asOf, true)
			for path, calls := range stub.Calls {
				if calls != 1 {
					t.Fatalf("duplicate lookup %s: %d", path, calls)
				}
			}
		})
	}
}

func TestSeriesLookupAbsenceAndFailures(t *testing.T) {
	for _, tc := range []struct {
		name, index, status, reason string
		http                        int
	}{
		{"no_claim_in_valid_index", `{"schema_version":"1.2.1","generated_at":"2026-10-11T00:00:00Z","result":[]}`, "ABSENT", "", 200},
		{"unavailable_index", "", "UNKNOWN", "SOURCE_ERROR", 503},
		{"malformed_index", `{}`, "UNKNOWN", "SOURCE_ERROR", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := config.Default()
			p.Network.Retries = 0
			stub := testutil.NewStub()
			key := "endoflife.date/api/v1/identifiers/purl/"
			stub.Bodies[key], stub.Status[key] = tc.index, tc.http
			tr := transport.New(stub.Client(), p, testutil.FixedNow, false)
			id, _ := identity.Resolve(model.Component{PURL: "pkg:gem/example@2.4.7"})
			out := NewEOL(tr, model.PolicyBundle{Policy: p}).Collect(context.Background(), id, "2026-10-11", true)
			if out.SeriesEvaluation.Status != tc.status || model.Text(out.SeriesEvaluation.ReasonCode) != tc.reason {
				t.Fatalf("%+v", out.SeriesEvaluation)
			}
		})
	}
}
