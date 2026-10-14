package acceptance

import (
	"context"
	"testing"

	"github.com/Pirikara/eolscan/internal/model"
	reporting "github.com/Pirikara/eolscan/internal/report"
	"github.com/Pirikara/eolscan/internal/testutil"
)

func assertArchivalOutcome(t *testing.T, report model.Report, want, reason string) model.ComponentResult {
	t.Helper()
	confidence, signal, exit := "", "UNKNOWN", 3
	if want == "EOL" {
		confidence, signal, exit = "MEDIUM", "PRESENT", 1
	} else if want == "NO_EOL_DETECTED" {
		signal, exit = "ABSENT", 0
	}
	row := expectLifecycle(t, report, want, confidence, "")
	signalStatus(t, row, "ARCHIVED", signal)
	if row.Incomplete != (want == "UNKNOWN") || reporting.ExitCode(report) != exit {
		t.Fatalf("archival completeness or CI: row=%+v gate=%+v", row, report.CIGate)
	}
	for _, evaluation := range row.SignalEvaluations {
		if evaluation.Type == "ARCHIVED" && reason != "" && model.Text(evaluation.ReasonCode) != reason {
			t.Fatalf("archival failure lost its reason: %+v", evaluation)
		}
	}
	if want == "EOL" && (row.EOLEffectiveDate != nil || model.Text(row.EOLBasis) != "POLICY_RULE") {
		t.Fatal("repository archival fabricated a support end date")
	}
	if want != "EOL" && len(row.Signals) != 0 {
		t.Fatal("unverified repository response produced positive evidence")
	}
	return row
}

func TestGitHubResponseFailuresCannotEstablishEOLOrNonmatch(t *testing.T) {
	for _, tc := range []struct {
		name, body, reason string
		status             int
		timeout            bool
	}{
		{"not_found", "", "REPOSITORY_NOT_FOUND", 404, false},
		{"rate_limited", `{}`, "SOURCE_ERROR", 429, false},
		{"forbidden", `{}`, "SOURCE_ERROR", 403, false},
		{"service_failure", `{}`, "SOURCE_ERROR", 503, false},
		{"timeout", "", "SOURCE_ERROR", 0, true},
		{"malformed_json", `{"full_name":`, "PROVIDER_SCHEMA_MISMATCH", 200, false},
		{"wrong_repository", `{"full_name":"other/repo","archived":true}`, "PROVIDER_SCHEMA_MISMATCH", 200, false},
		{"missing_identity", `{"archived":true}`, "PROVIDER_SCHEMA_MISMATCH", 200, false},
		{"missing_archived", `{"full_name":"publisher/leaf"}`, "PROVIDER_SCHEMA_MISMATCH", 200, false},
		{"null_archived", `{"full_name":"publisher/leaf","archived":null}`, "PROVIDER_SCHEMA_MISMATCH", 200, false},
		{"string_archived", `{"full_name":"publisher/leaf","archived":"true"}`, "PROVIDER_SCHEMA_MISMATCH", 200, false},
		{"duplicate_archived", `{"full_name":"publisher/leaf","archived":false,"archived":true}`, "PROVIDER_SCHEMA_MISMATCH", 200, false},
		{"array_response", `[{"full_name":"publisher/leaf","archived":true}]`, "PROVIDER_SCHEMA_MISMATCH", 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := rulePolicy(model.EOLRule{ID: "archived", AnyOf: []string{"ARCHIVED"}})
			p.Network.Retries = 0
			stub := testutil.NewStub()
			npmSource(t, stub, "https://github.com/publisher/leaf", "", "2020-01-01T00:00:00Z")
			const key = "api.github.com/repos/publisher/leaf"
			stub.Bodies[key], stub.Status[key] = tc.body, tc.status
			if tc.timeout {
				stub.Errors[key] = context.DeadlineExceeded
			}
			assertArchivalOutcome(t, runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:npm/transitive-leaf@1.0.0"), false), "UNKNOWN", tc.reason)
			if stub.Count(key) != 1 {
				t.Fatal("a non-retry scan repeated an unavailable repository lookup")
			}
		})
	}
}

func TestPyPIPublisherRepositoryAndRegistryArchiveScopes(t *testing.T) {
	for _, tc := range []struct {
		name, projectStatus, label, source, infoName, infoVersion, body, want string
		archived, repositoryMissing                                           bool
		repositoryQueries                                                     int
	}{
		{"active_project_archived_repo", "active", "Source Code", "https://github.com/publisher/leaf", "leaf", "1.0.0", "", "EOL", true, false, 1},
		{"active_project_active_repo", "active", "Repository", "https://github.com/publisher/leaf", "leaf", "1.0.0", "", "NO_EOL_DETECTED", false, false, 1},
		{"archived_project_skips_repo", "archived", "Source", "https://github.com/publisher/leaf", "leaf", "1.0.0", "", "EOL", false, false, 0},
		{"unknown_project_archived_repo", "future-status", "Source_Code", "https://github.com/publisher/leaf", "leaf", "1.0.0", "", "EOL", true, false, 1},
		{"unknown_project_active_repo", "future-status", "Code", "https://github.com/publisher/leaf", "leaf", "1.0.0", "", "UNKNOWN", false, false, 1},
		{"repo_404_does_not_mean_active", "active", "GitHub", "https://github.com/publisher/leaf", "leaf", "1.0.0", "", "UNKNOWN", false, true, 1},
		{"homepage_is_not_source", "active", "Homepage", "https://github.com/publisher/leaf", "leaf", "1.0.0", "", "UNKNOWN", true, false, 0},
		{"issues_are_not_source", "active", "Issues", "https://github.com/publisher/leaf/issues", "leaf", "1.0.0", "", "UNKNOWN", true, false, 0},
		{"unsupported_host", "active", "Repository", "https://gitlab.com/publisher/leaf", "leaf", "1.0.0", "", "UNKNOWN", true, false, 0},
		{"wrong_project_identity", "active", "Source", "https://github.com/publisher/leaf", "other", "1.0.0", "", "UNKNOWN", true, false, 0},
		{"wrong_version_identity", "active", "Source", "https://github.com/publisher/leaf", "leaf", "9.0.0", "", "UNKNOWN", true, false, 0},
		{"malformed_version_details", "active", "Source", "https://github.com/publisher/leaf", "leaf", "1.0.0", `{"info":`, "UNKNOWN", true, false, 0},
		{"missing_source_link", "active", "Source", "", "leaf", "1.0.0", "", "UNKNOWN", true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := rulePolicy(model.EOLRule{ID: "archived", AnyOf: []string{"ARCHIVED"}})
			p.Sources.NPM.Enabled, p.Sources.PyPI.Enabled = false, true
			stub := testutil.NewStub()
			pypiPackage(t, stub, "leaf", tc.projectStatus, []map[string]any{{"filename": "leaf-1.0.0.tar.gz", "upload-time": "2020-01-01T00:00:00Z", "yanked": false}})
			const details = "pypi.org/pypi/leaf/1.0.0/json"
			testutil.PutJSON(t, stub, details, map[string]any{"info": map[string]any{
				"name": tc.infoName, "version": tc.infoVersion, "project_urls": map[string]string{tc.label: tc.source},
			}})
			if tc.body != "" {
				stub.Bodies[details] = tc.body
			}
			const repository = "api.github.com/repos/publisher/leaf"
			testutil.PutJSON(t, stub, repository, map[string]any{"full_name": "publisher/leaf", "archived": tc.archived})
			if tc.repositoryMissing {
				stub.Status[repository] = 404
			}
			row := assertArchivalOutcome(t, runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:pypi/leaf@1.0.0"), false), tc.want, "")
			if row.VersionVerification.Status != "VERIFIED" || model.Text(row.VersionVerification.ProviderID) != "pypi" || stub.Count(repository) != tc.repositoryQueries {
				t.Fatalf("publisher repository mapping: row=%+v calls=%v", row, stub.Calls)
			}
			if tc.projectStatus == "archived" && stub.Count(details) != 0 {
				t.Fatal("a confirmed registry archive triggered unnecessary metadata requests")
			}
		})
	}
}

func TestRubyGemsSourceDetailsFallbacksAndFailures(t *testing.T) {
	for _, tc := range []struct {
		name, listing, detailName, detailVersion, source, want string
		nested, archive, missingDetails                        bool
		queries                                                int
	}{
		{"top_level_source", "present", "leaf", "1.0.0", "https://github.com/publisher/leaf", "EOL", false, true, false, 1},
		{"metadata_source", "present", "leaf", "1.0.0", "https://github.com/publisher/leaf", "EOL", true, true, false, 1},
		{"active_repository", "present", "leaf", "1.0.0", "https://github.com/publisher/leaf", "NO_EOL_DETECTED", false, false, false, 1},
		{"version_missing_from_list", "missing", "leaf", "1.0.0", "https://github.com/publisher/leaf", "EOL", false, true, false, 1},
		{"list_404_detail_available", "404", "leaf", "1.0.0", "https://github.com/publisher/leaf", "EOL", false, true, false, 1},
		{"wrong_detail_name", "present", "other", "1.0.0", "https://github.com/publisher/leaf", "UNKNOWN", false, true, false, 0},
		{"wrong_detail_version", "present", "leaf", "9.0.0", "https://github.com/publisher/leaf", "UNKNOWN", false, true, false, 0},
		{"unsupported_repository", "present", "leaf", "1.0.0", "https://gitlab.com/publisher/leaf", "UNKNOWN", false, true, false, 0},
		{"no_source_link", "present", "leaf", "1.0.0", "", "UNKNOWN", false, true, false, 0},
		{"detail_404", "present", "leaf", "1.0.0", "https://github.com/publisher/leaf", "UNKNOWN", false, true, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := rulePolicy(model.EOLRule{ID: "archived", AnyOf: []string{"ARCHIVED"}})
			p.Sources.NPM.Enabled, p.Sources.RubyGems.Enabled = false, true
			stub := testutil.NewStub()
			const listing = "rubygems.org/api/v1/versions/leaf.json"
			stub.Bodies[listing] = `[{"number":"1.0.0","platform":"ruby","created_at":"2020-01-01T00:00:00Z"}]`
			if tc.listing == "missing" {
				stub.Bodies[listing] = `[]`
			} else if tc.listing == "404" {
				stub.Status[listing] = 404
			}
			const details = "rubygems.org/api/v2/rubygems/leaf/versions/1.0.0.json"
			doc := map[string]any{"name": tc.detailName, "version": tc.detailVersion, "platform": "ruby", "version_created_at": "2020-01-01T00:00:00Z"}
			if tc.nested {
				doc["metadata"] = map[string]string{"source_code_uri": tc.source}
			} else {
				doc["source_code_uri"] = tc.source
			}
			testutil.PutJSON(t, stub, details, doc)
			if tc.missingDetails {
				stub.Status[details] = 404
			}
			const repository = "api.github.com/repos/publisher/leaf"
			testutil.PutJSON(t, stub, repository, map[string]any{"full_name": "publisher/leaf", "archived": tc.archive})
			row := assertArchivalOutcome(t, runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:gem/leaf@1.0.0"), false), tc.want, "")
			if row.VersionVerification.Status != "VERIFIED" || model.Text(row.VersionVerification.ProviderID) != "rubygems" || stub.Count(repository) != tc.queries {
				t.Fatalf("native gem source mapping: row=%+v calls=%v", row, stub.Calls)
			}
			if tc.want == "EOL" && row.Signals[0].Details["mapping_source_url"] != "https://"+details {
				t.Fatal("native repository provenance was lost")
			}
		})
	}
}
