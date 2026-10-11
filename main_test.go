package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLICommandsAndReportOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	stub := newStub()
	code := runCLI(context.Background(), []string{"scan", "-i", "examples/fixtures/supported.cdx.json", "-c", "examples/eol-policy.catalog.example.yaml", "--offline", "-f", "json"}, nil, &stdout, &stderr, stub.client(), fixedNow)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	var report Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Results[0].Lifecycle != "SUPPORTED" || len(stub.calls) != 0 {
		t.Fatalf("report=%+v", report)
	}
	for _, args := range [][]string{{"version"}, {"providers", "list"}, {"policy", "validate", "-c", "examples/eol-policy.partial.example.yaml"}, {"--help"}} {
		stdout.Reset()
		stderr.Reset()
		if code := runCLI(context.Background(), args, nil, &stdout, &stderr, stub.client(), fixedNow); code != 0 || stdout.Len() == 0 {
			t.Fatalf("%v: %d %s", args, code, stderr.String())
		}
	}
	dir := t.TempDir()
	output := filepath.Join(dir, "report.json")
	stdout.Reset()
	stderr.Reset()
	code = runCLI(context.Background(), []string{"scan", "-i", "examples/fixtures/supported.cdx.json", "-c", "examples/eol-policy.catalog.example.yaml", "--offline", "-f", "json", "-o", output}, nil, &stdout, &stderr, stub.client(), fixedNow)
	b, err := os.ReadFile(output)
	if err != nil || code != 0 || stdout.Len() != 0 || !json.Valid(b) {
		t.Fatalf("atomic output code=%d err=%v stderr=%s", code, err, stderr.String())
	}
	if info, _ := os.Stat(output); info.Mode().Perm() != 0600 {
		t.Fatalf("report permissions: %v", info.Mode())
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 1 {
		t.Fatal("temporary file leaked")
	}
}
func TestCLIErrorExitAndNoPartialOutput(t *testing.T) {
	for _, args := range [][]string{
		{"scan"}, {"scan", "-i", "-", "--offline", "--no-cache"}, {"scan", "-i", "-", "--as-of", "bad"},
		{"scan", "-i", "-", "--format", "sarif"}, {"scan", "-i", "-", "--old-flag"}, {"--output", "json", "-"},
		{"providers", "unknown"}, {"policy", "validate"}, {"version", "unexpected"},
	} {
		var out, errs bytes.Buffer
		code := runCLI(context.Background(), args, strings.NewReader("{}"), &out, &errs, newStub().client(), fixedNow)
		if code != 2 || out.Len() != 0 {
			t.Fatalf("%v code=%d stdout=%s stderr=%s", args, code, out.String(), errs.String())
		}
	}
}
func TestPolicyValidationRejectionAndMerge(t *testing.T) {
	for _, data := range []string{
		"schema_version: 1\n",
		"schema_version: 2\nschema_version: 2\n",
		"schema_version: 2\nsources:\n  github:\n    enabled: true\n",
		"schema_version: 2\nversion_verification:\n  mode: optional\n",
		"schema_version: 2\nsignals:\n  stale_release_days: null\nci:\n  fail_on_signals: [STALE_RELEASE]\n",
		"schema_version: 2\nsources:\n  deps_dev:\n    base_url: http://api.deps.dev/v3\n",
		"schema_version: 2\nsources:\n  deps_dev:\n    base_url: https://api.deps.dev/v3?token=secret\n",
		"schema_version: 2\nsources:\n  deps_dev:\n    base_url: https://user:secret@api.deps.dev/v3\n",
		"schema_version: 2\nnetwork:\n  allowed_hosts: [example.org]\n",
		"schema_version: 2\nci:\n  fail_on_signals: [STALE_RELEASE, STALE_RELEASE]\n",
	} {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		os.WriteFile(path, []byte(data), 0600)
		if _, err := loadPolicy(path); err == nil {
			t.Fatalf("accepted policy %s", data)
		}
	}
	p, err := loadPolicy("examples/eol-policy.partial.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.Network.TimeoutSeconds != 8 || p.CI.MinConfidence != "MEDIUM" || !p.CI.FailOnIncompleteScan || p.CI.MaxUnknownRatio == nil {
		t.Fatalf("merge: %+v", p)
	}
}
