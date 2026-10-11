// Package cli parses commands and coordinates input, scanning, and output.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	configpkg "github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/fileio"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/provider"
	reporting "github.com/Pirikara/eolscan/internal/report"
	sbomparser "github.com/Pirikara/eolscan/internal/sbom"
	scannerpkg "github.com/Pirikara/eolscan/internal/scanner"
	"github.com/Pirikara/eolscan/internal/version"
)

func usage(w io.Writer) {
	fmt.Fprintln(w, `eolscan scan -i SBOM.json|- [-c policy.yaml] [-f table|json] [-o report.json]
eolscan scan --offline --input SBOM.json --as-of YYYY-MM-DD
eolscan policy validate --config policy.yaml
eolscan providers list
eolscan version

CycloneDX JSON 1.4–1.7 / SPDX 2.3; config 2 / report 2.1.
Online scans send public package identities to configured registries,
endoflife.date, and deps.dev.
--offline makes no HTTP requests. Disk cache is disabled by default.
Default CI fails on EOL/HIGH; UNKNOWN and incomplete remain visible.
The default catalog is empty: generic EOL dates alone do not confirm EOL.`)
}

// Run executes a command using injected I/O, HTTP client, and execution time.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, client *http.Client, now time.Time) (code int) {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(stderr, "internal error")
			code = 4
		}
	}()
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		usage(stdout)
		return 0
	}
	switch args[0] {
	case "version":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "version takes no arguments")
			return 2
		}
		_, err := fmt.Fprintln(stdout, "eolscan "+version.Current)
		if err != nil {
			return 2
		}
		return 0
	case "providers":
		if len(args) != 2 || args[1] != "list" {
			fmt.Fprintln(stderr, "usage: eolscan providers list")
			return 2
		}
		_, err := io.WriteString(stdout, provider.DescribeProviders())
		if err != nil {
			return 2
		}
		return 0
	case "policy":
		if len(args) < 2 || args[1] != "validate" {
			fmt.Fprintln(stderr, "usage: eolscan policy validate -c policy.yaml")
			return 2
		}
		flags := flag.NewFlagSet("policy validate", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var config string
		flags.StringVar(&config, "config", "", "policy YAML")
		flags.StringVar(&config, "c", "", "policy YAML")
		if err := flags.Parse(args[2:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			return 2
		}
		if flags.NArg() != 0 || config == "" {
			fmt.Fprintln(stderr, "policy validate requires --config")
			return 2
		}
		p, err := configpkg.Load(config)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		b, err := configpkg.LoadBundle(p, config)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		_, err = fmt.Fprintln(stdout, "Policy valid | schema 2 | hash "+b.Hash)
		if err != nil {
			return 2
		}
		return 0
	case "scan":
	default:
		fmt.Fprintln(stderr, "expected scan, policy validate, providers list, or version")
		return 2
	}
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { usage(stderr); flags.PrintDefaults() }
	var input, config, format, output, asOf string
	var offline, noCache, verbose bool
	flags.StringVar(&input, "input", "", "SBOM file or - for stdin")
	flags.StringVar(&input, "i", "", "SBOM file or - for stdin")
	flags.StringVar(&config, "config", "", "policy YAML")
	flags.StringVar(&config, "c", "", "policy YAML")
	flags.StringVar(&format, "format", "table", "table or json")
	flags.StringVar(&format, "f", "table", "table or json")
	flags.StringVar(&output, "output", "", "report file; omitted for stdout")
	flags.StringVar(&output, "o", "", "report file; omitted for stdout")
	flags.StringVar(&asOf, "as-of", "", "evaluation date (UTC YYYY-MM-DD)")
	flags.BoolVar(&offline, "offline", false, "disable all HTTP")
	flags.BoolVar(&noCache, "no-cache", false, "disable persistent cache; incompatible with offline")
	flags.BoolVar(&verbose, "verbose", false, "print redacted diagnostics to stderr")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || input == "" || (format != "json" && format != "table") || offline && noCache {
		fmt.Fprintln(stderr, "scan requires --input, format table|json, and no --offline/--no-cache combination")
		return 2
	}
	if asOf == "" {
		asOf = model.UTCDate(now)
	}
	if _, err := time.Parse("2006-01-02", asOf); err != nil {
		fmt.Fprintln(stderr, "invalid --as-of date; expected YYYY-MM-DD")
		return 2
	}
	p, err := configpkg.Load(config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if noCache {
		p.Cache.Enabled = false
	}
	bundle, err := configpkg.LoadBundle(p, config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	reader := stdin
	if input != "-" {
		f, err := os.Open(input)
		if err != nil {
			fmt.Fprintln(stderr, "open SBOM:", err)
			return 2
		}
		defer f.Close()
		reader = f
	}
	sbom, err := sbomparser.Parse(reader, p.Input)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	scanner := scannerpkg.New(bundle, client, now, asOf, offline)
	report, err := scanner.Scan(ctx, sbom)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 4
	}
	if verbose {
		for _, row := range report.Results {
			for _, d := range row.Diagnostics {
				fmt.Fprintf(stderr, "%s [%s] %s: %s\n", row.SourceRef, model.Text(d.ProviderID), d.Code, d.Message)
			}
		}
		incomplete, unverified, notFound := 0, 0, 0
		for _, row := range report.Results {
			if row.Incomplete {
				incomplete++
			}
			if row.VersionVerification.Status == "UNVERIFIED" {
				unverified++
			}
			if row.VersionVerification.Status == "NOT_FOUND_IN_INDEX" {
				notFound++
			}
		}
		fmt.Fprintf(stderr, "metrics in_scope=%d eol=%d supported=%d unknown=%d assessment_coverage=%.4f provider_error_count=%d incomplete_component_count=%d version_unverified_count=%d version_not_found_count=%d cache_hit_count=%d ci_failure_count=%d\n",
			report.Summary.InScope, report.Summary.EOL, report.Summary.Supported, report.Summary.Unknown,
			report.Summary.AssessmentCoverage, report.Summary.ProviderErrorCount, incomplete, unverified,
			notFound, scanner.CacheHits(), report.Summary.CIFailureCount)
	}
	var buf bytes.Buffer
	if format == "json" {
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		err = enc.Encode(report)
	} else {
		err = reporting.Table(&buf, report, p)
	}
	if err != nil {
		fmt.Fprintln(stderr, "write report:", err)
		return 2
	}
	if output != "" {
		err = fileio.AtomicWrite(output, buf.Bytes())
	} else {
		_, err = stdout.Write(buf.Bytes())
	}
	if err != nil {
		fmt.Fprintln(stderr, "write report:", err)
		return 2
	}
	return reporting.ExitCode(report)
}
