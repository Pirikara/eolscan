package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/testutil"
	"github.com/Pirikara/eolscan/internal/transport"
)

func TestPublisherDeclarationPatterns(t *testing.T) {
	id := identity.Identity{Name: "leaf"}
	for _, tc := range []struct {
		name, text string
		present    bool
	}{
		{"project_statement", "This project is no longer maintained. Use its successor.", true},
		{"package_statement", "The leaf PyPI package is deprecated.", true},
		{"named_statement", "leaf is deprecated in favor of next-leaf.", true},
		{"warning_decoration", "⚠️⚠️⚠️ The `leaf` PyPI package is deprecated use `next-leaf` instead ⚠️", true},
		{"actively_unmaintained", "NOTE: This project is no longer actively maintained!", true},
		{"backport_retirement", "**Attention:** this backport module isn't maintained anymore. Use pathlib2.", true},
		{"retired_predecessor", "The old pathlib module on bitbucket is no longer maintained. The goal of pathlib2 is to provide a backport with newest features.", false},
		{"named_deprecated_heading", "# leaf (DEPRECATED)\n\nSee the successor.", true},
		{"html_deprecated_heading", `<h1 align="center">leaf (DEPRECATED)</h1>`, true},
		{"html_example", "<pre>\n<h1>leaf (DEPRECATED)</h1>\n</pre>", false},
		{"html_comment", "<!-- Historical notice:\n<h1>leaf (DEPRECATED)</h1>\n-->", false},
		{"quoted_warning", "> ⚠️ Warning: This project is no longer maintained.", true},
		{"bold_quoted_warning", "> ⚠️ **Warning: This project is no longer maintained. Use at your own risk.**", true},
		{"formatted_statement", "# Leaf\n**This package is unmaintained.**\nUse another one.", true},
		{"status_heading", "# Status: UNMAINTAINED\nOld project", true},
		{"plain_unmaintained_heading", "# UNMAINTAINED\nOld project", true},
		{"renamed_distribution", "The tool is no longer released as\nleaf and will only be fixed in the new_leaf package", true},
		{"explicit_eol", "This library has reached end-of-life.", true},
		{"negated_status", "This project is not unmaintained.", false},
		{"negated_deprecation", "leaf is not deprecated.", false},
		{"supported_platform_scope", "This package is no longer supported on Python 2.", false},
		{"dependency_statement", "Another dependency is deprecated.\n\nWe still maintain this project.", false},
		{"api_deprecation", "This method is deprecated. Use the replacement API.", false},
		{"quoted_notice", "> This project is unmaintained.\n\nThat was the old message.", false},
		{"fenced_example", "```text\nThis project is unmaintained.\n```", false},
		{"indented_example", "Example::\n\n    This project is unmaintained.\n\nStill active.", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, evidence := declaration("pypi", "https://pypi.org/pypi/leaf/1/json", "info.description", tc.text, nil, id,
				transport.HTTPData{ObservedAt: model.Timestamp(testutil.FixedNow), Body: []byte(tc.text)}, config.Default())
			if (e.Status == "PRESENT") != tc.present || (evidence != nil) != tc.present {
				t.Fatalf("%+v", e)
			}
		})
	}
	patterns := []string{`(?i)^leaf maintenance ended$`}
	p := config.Default()
	p.Signals.UnmaintainedPatterns = &patterns
	e, _ := declaration("pypi", "https://pypi.org/", "info.description", "leaf maintenance ended", nil, id, transport.HTTPData{}, p)
	if e.Status != "PRESENT" {
		t.Fatal("custom expression was not applied")
	}
	patterns = []string{}
	e, _ = declaration("pypi", "https://pypi.org/", "info.description", "This project is unmaintained.", nil, id, transport.HTTPData{}, p)
	if e.Status != "ABSENT" {
		t.Fatal("explicit empty pattern list did not disable text matching")
	}
	e, evidence := declaration("pypi", "https://pypi.org/", "info.description", "", []string{"Development Status :: 7 - Inactive"}, id, transport.HTTPData{}, p)
	if e.Status != "PRESENT" || evidence.Details["source_field"] != "info.classifiers" {
		t.Fatal("inactive classifier was not an independent declaration")
	}
}

func TestRegistryDeclarationRequiresExactMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, body, status, reason string
		http                       int
	}{
		{"inactive_classifier", `{"info":{"name":"leaf","version":"1.0.0","classifiers":["Development Status :: 7 - Inactive"]}}`, "PRESENT", "", 200},
		{"retired_description", `{"info":{"name":"leaf","version":"1.0.0","description":"This package is unmaintained."}}`, "PRESENT", "", 200},
		{"ordinary_description", `{"info":{"name":"leaf","version":"1.0.0","description":"A library. A dependency is deprecated.","classifiers":[]}}`, "ABSENT", "", 200},
		{"missing_classifiers", `{"info":{"name":"leaf","version":"1.0.0","description":"A library."}}`, "UNKNOWN", "MISSING_DECLARATION_METADATA", 200},
		{"wrong_name", `{"info":{"name":"other","version":"1.0.0","description":"This package is unmaintained."}}`, "UNKNOWN", "PROVIDER_SCHEMA_MISMATCH", 200},
		{"wrong_version", `{"info":{"name":"leaf","version":"2.0.0","description":"This package is unmaintained."}}`, "UNKNOWN", "PROVIDER_SCHEMA_MISMATCH", 200},
		{"missing_description", `{"info":{"name":"leaf","version":"1.0.0","classifiers":[]}}`, "UNKNOWN", "MISSING_DECLARATION_METADATA", 200},
		{"malformed_classifiers", `{"info":{"name":"leaf","version":"1.0.0","classifiers":"Inactive","description":"This package is unmaintained."}}`, "UNKNOWN", "PROVIDER_SCHEMA_MISMATCH", 200},
		{"duplicate_key", `{"info":{"name":"leaf","name":"other","version":"1.0.0"}}`, "UNKNOWN", "PROVIDER_SCHEMA_MISMATCH", 200},
		{"missing_version", `{}`, "UNKNOWN", "VERSION_NOT_FOUND_IN_INDEX", 404},
		{"unavailable_api", `{}`, "UNKNOWN", "SOURCE_ERROR", 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := config.Default()
			p.Network.Retries = 0
			stub := testutil.NewStub()
			key := "pypi.org/pypi/leaf/1.0.0/json"
			stub.Bodies[key], stub.Status[key] = tc.body, tc.http
			id, _ := identity.Resolve(model.Component{PURL: "pkg:pypi/leaf@1.0.0"})
			tr := transport.New(stub.Client(), p, testutil.FixedNow, false)
			e, proof, _ := newRegistry(tr).declaredUnmaintained(context.Background(), id)
			if e.Status != tc.status || model.Text(e.ReasonCode) != tc.reason || (proof != nil) != (tc.status == "PRESENT") {
				t.Fatalf("%+v", e)
			}
		})
	}
	e, proof := declaration("pypi", "https://pypi.org/", "info.description", strings.Repeat("x", maxDeclarationBytes+1), nil, identity.Identity{Name: "leaf"}, transport.HTTPData{}, config.Default())
	if e.Status != "UNKNOWN" || model.Text(e.ReasonCode) != "DECLARATION_TOO_LARGE" || proof != nil {
		t.Fatal(e)
	}
}
