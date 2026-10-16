package provider

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/testutil"
	"github.com/Pirikara/eolscan/internal/transport"
)

func TestRepositoryPushInactivity(t *testing.T) {
	for _, tc := range []struct{ name, pushed, asOf, status, reason string }{
		{"recent_push", "2026-10-10T00:00:00Z", "2026-10-11", "ABSENT", ""},
		{"at_threshold", "2026-10-01T23:59:59Z", "2026-10-11", "ABSENT", ""},
		{"beyond_threshold", "2026-09-30T23:59:59Z", "2026-10-11", "PRESENT", ""},
		{"missing_push", "", "2026-10-11", "UNKNOWN", "MISSING_REPOSITORY_ACTIVITY"},
		{"invalid_push", "not-a-date", "2026-10-11", "UNKNOWN", "INVALID_REPOSITORY_ACTIVITY"},
		{"future_push", "2027-01-01T00:00:00Z", "2026-10-11", "UNKNOWN", "INVALID_REPOSITORY_ACTIVITY"},
		{"historical_push", "2024-01-01T00:00:00Z", "2026-10-01", "UNKNOWN", "STATUS_TIME_UNAVAILABLE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := config.Default()
			p.Signals.StaleRepositoryDays = model.Ptr(10)
			stub := testutil.NewStub()
			doc := map[string]any{"full_name": "owner/leaf", "archived": false, "updated_at": "2026-10-11T00:00:00Z"}
			if tc.pushed != "" {
				doc["pushed_at"] = tc.pushed
			}
			testutil.PutJSON(t, stub, "api.github.com/repos/owner/leaf", doc)
			tr := transport.New(stub.Client(), p, testutil.FixedNow, false)
			refs := []repositoryRef{{ProjectID: "github.com/owner/leaf", Provenance: "REGISTRY_METADATA"}}
			e, evidence, _ := repositoryInactivity(context.Background(), tr, refs, tc.asOf)
			if e.Status != tc.status || model.Text(e.ReasonCode) != tc.reason || (evidence != nil) != (tc.status == "PRESENT") {
				t.Fatalf("%+v", e)
			}
			if evidence != nil && evidence.Details["source_field"] != "pushed_at" {
				t.Fatal("metadata updates reset repository activity")
			}
			if stub.Calls["api.github.com/repos/owner/leaf"] != 1 {
				t.Fatal("repository lookup was repeated")
			}
		})
	}
}

func TestRepositoryReadmeDeclarations(t *testing.T) {
	for _, tc := range []struct {
		name, text, status, reason string
		malformed                  bool
		http                       int
	}{
		{"explicit_retirement", "This project is no longer maintained.", "PRESENT", "", false, 200},
		{"no_declaration", "Use this library with a deprecated API if needed.", "ABSENT", "", false, 200},
		{"missing_readme", "", "UNKNOWN", "README_NOT_FOUND", false, 404},
		{"malformed_encoding", "This project is unmaintained.", "UNKNOWN", "PROVIDER_SCHEMA_MISMATCH", true, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := config.Default()
			stub := testutil.NewStub()
			testutil.PutJSON(t, stub, "api.github.com/repos/owner/leaf", map[string]any{"full_name": "owner/leaf", "archived": false})
			doc := map[string]any{"type": "file", "path": "README.md", "encoding": "base64", "size": len(tc.text), "content": base64.StdEncoding.EncodeToString([]byte(tc.text)), "download_url": "https://untrusted.invalid/never-fetch"}
			if tc.malformed {
				doc["content"] = "not base64"
			}
			testutil.PutJSON(t, stub, "api.github.com/repos/owner/leaf/readme", doc)
			stub.Status["api.github.com/repos/owner/leaf/readme"] = tc.http
			clock := testutil.NewClock(testutil.FixedNow)
			tr := transport.New(stub.Client(), p, testutil.FixedNow, false, transport.WithClock(clock.Now), transport.WithWait(clock.Wait))
			e, evidence, _ := repositoryDeclaration(context.Background(), tr, []repositoryRef{{ProjectID: "github.com/owner/leaf"}}, identity.Identity{Name: "leaf"})
			if e.Status != tc.status || model.Text(e.ReasonCode) != tc.reason || (evidence != nil) != (tc.status == "PRESENT") {
				t.Fatalf("%+v", e)
			}
			if len(stub.Calls) != 2 {
				t.Fatalf("fetched something other than the configured API: %v", stub.Calls)
			}
		})
	}
}
