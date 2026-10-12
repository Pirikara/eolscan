package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestEmptyScanAlwaysFailsAndReportsReason(t *testing.T) {
	for _, input := range []string{
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`,
		`{"spdxVersion":"SPDX-2.3","packages":[]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"file","name":"binary"}]}`,
	} {
		var out, errs bytes.Buffer
		code := cli.Run(context.Background(), []string{"scan", "-i", "-", "--offline", "-f", "json"}, strings.NewReader(input), &out, &errs, testutil.NewStub().Client(), testutil.FixedNow)
		var report model.Report
		if code != 3 || json.Unmarshal(out.Bytes(), &report) != nil || report.Summary.InScope != 0 || report.CIGate.Passed || !report.CIGate.Incomplete || !model.Contains(report.CIGate.ViolationCodes, "NO_COMPONENTS") {
			t.Fatalf("exit=%d report=%s stderr=%s", code, out.String(), errs.String())
		}
	}
}

type observedInput struct {
	io.ReadCloser
	started chan struct{}
	once    sync.Once
}

func (r *observedInput) Read(b []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	return r.ReadCloser.Read(b)
}

func TestCancellationWhileWaitingForStdin(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	input := &observedInput{ReadCloser: reader, started: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(output, []byte("previous report"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- cli.Run(ctx, []string{"scan", "-i", "-", "--offline", "-f", "json", "-o", output}, input, &out, &errs, testutil.NewStub().Client(), testutil.FixedNow)
	}()
	select {
	case <-input.started:
	case <-time.After(2 * time.Second):
		t.Fatal("stdin was not read")
	}
	cancel()
	select {
	case code := <-done:
		data, err := os.ReadFile(output)
		if code != 130 || err != nil || string(data) != "previous report" || out.Len() != 0 || !strings.Contains(errs.String(), "interrupted") {
			t.Fatalf("exit=%d output=%q stderr=%s error=%v", code, data, errs.String(), err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled stdin scan did not exit")
	}
}

func TestCancelledOrExpiredContextDoesNotPublishReport(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		want := 130
		if deadline {
			cancel()
			ctx, cancel = context.WithDeadline(context.Background(), time.Time{})
			want = 3
		}
		cancel()
		var out, errs bytes.Buffer
		code := cli.Run(ctx, []string{"scan", "-i", "-", "--offline", "-f", "json"}, strings.NewReader(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`), &out, &errs, testutil.NewStub().Client(), testutil.FixedNow)
		if code != want || out.Len() != 0 || !strings.Contains(errs.String(), "interrupted") {
			t.Fatalf("deadline=%t exit=%d output=%s stderr=%s", deadline, code, out.String(), errs.String())
		}
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
