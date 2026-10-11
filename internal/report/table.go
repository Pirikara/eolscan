// Package report renders reports and validates their semantic invariants.
package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/Pirikara/eolscan/internal/model"
)

func Table(w io.Writer, r model.Report, p model.Policy) error {
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "LIFECYCLE\tCONFIDENCE\tPACKAGE\tVERSION\tEOL DATE\tNOTICE\tSIGNALS\tINCOMPLETE\tCI FAILURE\tREASON"); err != nil {
		return err
	}
	for _, row := range r.Results {
		if row.Lifecycle == "UNKNOWN" && !p.Output.IncludeUnknown {
			continue
		}
		sig := ""
		for i, e := range row.SignalEvaluations {
			if i > 0 {
				sig += ","
			}
			sig += e.Type + "=" + e.Status
		}
		reason := ""
		for i, v := range row.UnknownReasons {
			if i > 0 {
				reason += ","
			}
			reason += v
		}
		notice := ""
		for _, n := range row.Notices {
			notice = fmt.Sprintf("%s(%dd)", n.Type, n.DaysRemaining)
		}
		if _, err := fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%t\t%t\t%s\n", row.Lifecycle, model.Text(row.Confidence), row.Name, model.Text(row.Version), model.Text(row.EOLEffectiveDate), notice, sig, row.Incomplete, row.CIFailure, reason); err != nil {
			return err
		}
		if p.Output.IncludeEvidence {
			for _, e := range row.Evidence {
				if _, err := fmt.Fprintf(table, "  evidence\t%s\t%s\t%s\t%s\t%s\t\t\t\t\n", e.Confidence, e.ID, e.MatchedCycle, e.EOLEffectiveDate, e.SourceURL); err != nil {
					return err
				}
			}
		}
	}
	if err := table.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "Scanned %d | excluded %d | EOL %d | supported %d | unknown %d | coverage %.1f%% | incomplete %t | CI passed %t\n",
		r.Summary.InScope, r.Summary.Excluded, r.Summary.EOL, r.Summary.Supported, r.Summary.Unknown, r.Summary.AssessmentCoverage*100, r.CIGate.Incomplete, r.CIGate.Passed)
	if err == nil && !r.CIGate.Passed {
		_, err = fmt.Fprintln(w, "CI violations: "+strings.Join(r.CIGate.ViolationCodes, ","))
	}
	return err
}
