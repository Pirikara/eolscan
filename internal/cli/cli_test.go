package cli_test

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

func TestCLICommandsAndReportOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	stub := testutil.NewStub()
	code := cli.Run(context.Background(), []string{"scan", "-i", testutil.Path(t, "testdata/fixtures/supported.cdx.json"), "-c", testutil.Path(t, "examples/eol-policy.catalog.example.yaml"), "--offline", "-f", "json"}, nil, &stdout, &stderr, stub.Client(), testutil.FixedNow)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	var report model.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Results[0].Lifecycle != "SUPPORTED" || len(stub.Calls) != 0 {
		t.Fatalf("report=%+v", report)
	}
	for _, args := range [][]string{{"version"}, {"providers", "list"}, {"policy", "validate", "-c", testutil.Path(t, "examples/eol-policy.partial.example.yaml")}, {"--help"}} {
		stdout.Reset()
		stderr.Reset()
		if code := cli.Run(context.Background(), args, nil, &stdout, &stderr, stub.Client(), testutil.FixedNow); code != 0 || stdout.Len() == 0 {
			t.Fatalf("%v: %d %s", args, code, stderr.String())
		}
	}
	dir := t.TempDir()
	output := filepath.Join(dir, "report.json")
	stdout.Reset()
	stderr.Reset()
	code = cli.Run(context.Background(), []string{"scan", "-i", testutil.Path(t, "testdata/fixtures/supported.cdx.json"), "-c", testutil.Path(t, "examples/eol-policy.catalog.example.yaml"), "--offline", "-f", "json", "-o", output}, nil, &stdout, &stderr, stub.Client(), testutil.FixedNow)
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
		code := cli.Run(context.Background(), args, strings.NewReader("{}"), &out, &errs, testutil.NewStub().Client(), testutil.FixedNow)
		if code != 2 || out.Len() != 0 {
			t.Fatalf("%v code=%d stdout=%s stderr=%s", args, code, out.String(), errs.String())
		}
	}
}
