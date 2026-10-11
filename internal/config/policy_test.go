package config_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/testutil"
)

func TestDefaultPolicyMatchesExample(t *testing.T) {
	fromExample, err := config.Load(testutil.Path(t, "examples/eol-policy.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(config.Default(), fromExample) {
		t.Fatal("embedded defaults differ from the documented default policy")
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
		if _, err := config.Load(path); err == nil {
			t.Fatalf("accepted policy %s", data)
		}
	}
	p, err := config.Load(testutil.Path(t, "examples/eol-policy.partial.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Network.TimeoutSeconds != 8 || p.CI.MinConfidence != "MEDIUM" || !p.CI.FailOnIncompleteScan || p.CI.MaxUnknownRatio == nil {
		t.Fatalf("merge: %+v", p)
	}
}
