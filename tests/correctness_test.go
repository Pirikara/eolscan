package acceptance

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Pirikara/eolscan/internal/lifecycle"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/scanner"
	"github.com/Pirikara/eolscan/internal/testutil"
)

type cancelTransport struct {
	started chan struct{}
	once    sync.Once
	calls   atomic.Int32
}

func (r *cancelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.calls.Add(1)
	r.once.Do(func() { close(r.started) })
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func TestScanCancellationStopsWorkersAndDiscardsResult(t *testing.T) {
	p := offlinePolicy()
	p.Sources.NPM.Enabled = true
	p.Network.Burst = 6
	client := &cancelTransport{started: make(chan struct{})}
	sbom := componentSBOM("pkg:npm/example-0@1.0.0")
	for i := 1; i < 1000; i++ {
		sbom.Components = append(sbom.Components, model.Component{SourceRef: fmt.Sprint(i), Name: "example", PURL: fmt.Sprintf("pkg:npm/example-%d@1.0.0", i)})
	}
	s := scanner.New(testBundle(t, p, nil), &http.Client{Transport: client}, testutil.FixedNow, "2026-10-11", false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		report, err := s.Scan(ctx, sbom)
		if len(report.Results) != 0 || report.CIGate.Passed {
			done <- errors.New("cancelled scan returned a report")
			return
		}
		done <- err
	}()
	select {
	case <-client.started:
	case <-time.After(2 * time.Second):
		t.Fatal("metadata request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || client.calls.Load() > int32(p.Network.MaxConcurrency) {
			t.Fatalf("error=%v calls=%d", err, client.calls.Load())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("workers did not stop after cancellation")
	}
}

func TestUnavailableSignalKeepsItsActualProviderReason(t *testing.T) {
	evaluations := []model.SignalEvaluation{
		{Type: "STALE_RELEASE", Status: "UNKNOWN", ReasonCode: model.Ptr("NO_CAPABILITY")},
		{Type: "STALE_RELEASE", Status: "UNKNOWN", ReasonCode: model.Ptr("MISSING_PUBLICATION_DATE"), ProviderID: model.Ptr("deps_dev")},
	}
	got, _, _ := lifecycle.AggregateSignals([]string{"STALE_RELEASE"}, evaluations, nil)
	if len(got) != 1 || model.Text(got[0].ReasonCode) != "MISSING_PUBLICATION_DATE" || model.Text(got[0].ProviderID) != "deps_dev" {
		t.Fatalf("lost provider failure: %+v", got)
	}
}
