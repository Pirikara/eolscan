package acceptance

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/testutil"
)

func TestBuiltCLIWithNestedDependencyAndHTTPS(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Go uses the macOS native trust store and ignores SSL_CERT_FILE; production-binary HTTPS cases run in Linux CI")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "eolscan")
	build := exec.Command("go", "build", "-o", binary, "./cmd/eolscan")
	build.Dir = filepath.Dir(testutil.Path(t, "go.mod"))
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build executable: %v\n%s", err, output)
	}
	for _, tc := range []struct {
		name, repositoryBody, want string
		status, exit               int
	}{
		{"archived", `{"full_name":"publisher/leaf","archived":true}`, "EOL", 200, 1},
		{"active", `{"full_name":"publisher/leaf","archived":false}`, "NO_EOL_DETECTED", 200, 0},
		{"not_found", `{}`, "UNKNOWN", 404, 3},
		{"invalid_response", `{"full_name":"publisher/leaf","archived":null}`, "UNKNOWN", 200, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/npm/leaf":
					io.WriteString(w, `{"name":"leaf","versions":{"1.0.0":{"name":"leaf","version":"1.0.0","repository":"https://github.com/publisher/leaf"}},"time":{"1.0.0":"2020-01-01T00:00:00Z"}}`)
				case "/github/repos/publisher/leaf":
					w.WriteHeader(tc.status)
					io.WriteString(w, tc.repositoryBody)
				default:
					t.Errorf("unexpected binary request: %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			u, _ := url.Parse(server.URL)
			p := rulePolicy(model.EOLRule{ID: "archived", AnyOf: []string{"ARCHIVED"}})
			p.Sources.NPM.BaseURL, p.Sources.GitHub.BaseURL = server.URL+"/npm", server.URL+"/github"
			p.Network.AllowedHosts = []string{u.Hostname()}
			p.Network.RequestsPerSecond, p.Network.Retries = 100, 0
			path := filepath.Join(t.TempDir(), "policy.json")
			data, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			// Trust only this local test certificate in the child process. No
			// system trust store or application TLS verification is changed.
			ca := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			input := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"root","components":[{"type":"library","name":"leaf","bom-ref":"transitive-leaf","purl":"pkg:npm/leaf@1.0.0"}]}}}`
			cmd := exec.Command(binary, "scan", "-i", "-", "-c", path, "-f", "json")
			cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+ca, "SSL_CERT_DIR="+t.TempDir(), "EOLSCAN_GITHUB_TOKEN=")
			cmd.Stdin = strings.NewReader(input)
			var out, errs bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &errs
			err = cmd.Run()
			code := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatal(err)
				}
				code = exit.ExitCode()
			}
			var report model.Report
			if code != tc.exit || json.Unmarshal(out.Bytes(), &report) != nil || len(report.Results) != 1 {
				t.Fatalf("executable exit=%d want=%d stderr=%s stdout=%s", code, tc.exit, errs.String(), out.String())
			}
			row := report.Results[0]
			if row.SourceRef != "transitive-leaf" || row.Lifecycle != tc.want || report.Summary.Excluded != 1 || strings.Contains(errs.String(), "WARNING:") != (tc.want == "EOL") {
				t.Fatalf("executable dropped a nested dependency or emitted a false warning: %+v stderr=%s", report, errs.String())
			}
		})
	}
}
