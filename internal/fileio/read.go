package fileio

import (
	"fmt"
	"io"
	"os"
)

// ReadLimited reads a file with an enforced size limit.
func ReadLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("file exceeds %d bytes", max)
	}
	return b, nil
}
