package cli

import (
	"context"
	"io"

	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/sbom"
)

// parseSBOM lets interruption terminate a scan even while stdin is waiting
// for data. A buffered result lets the parser finish after cancellation.
func parseSBOM(ctx context.Context, reader io.Reader, policy model.InputPolicy) (model.SBOM, error) {
	if err := ctx.Err(); err != nil {
		return model.SBOM{}, err
	}
	type parsed struct {
		sbom model.SBOM
		err  error
	}
	done := make(chan parsed, 1)
	go func() {
		result, err := sbom.Parse(reader, policy)
		done <- parsed{result, err}
	}()
	select {
	case <-ctx.Done():
		if closer, ok := reader.(io.Closer); ok {
			_ = closer.Close()
		}
		return model.SBOM{}, ctx.Err()
	case result := <-done:
		if err := ctx.Err(); err != nil {
			return model.SBOM{}, err
		}
		return result.sbom, result.err
	}
}
