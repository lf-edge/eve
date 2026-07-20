// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestReadWithMaxSize covers both the small-file path (content shorter than
// maxReadSize, returned whole) and the too-large path (content longer than
// maxReadSize, truncated with an error). The buffer is sized to the file for
// the small case, but the returned content and truncation semantics must be
// identical to allocating maxReadSize+1 in both cases.
func TestReadWithMaxSize(t *testing.T) {
	const maxReadSize = 100

	tests := []struct {
		name        string
		fileSize    int
		wantErr     bool
		wantLen     int
		wantContent bool // compare returned bytes against the written prefix
	}{
		{
			name:        "smaller than maxReadSize",
			fileSize:    50,
			wantErr:     false,
			wantLen:     50,
			wantContent: true,
		},
		{
			name:        "one below maxReadSize",
			fileSize:    maxReadSize - 1,
			wantErr:     false,
			wantLen:     maxReadSize - 1,
			wantContent: true,
		},
		{
			name:        "larger than maxReadSize",
			fileSize:    maxReadSize + 100,
			wantErr:     true,
			wantLen:     maxReadSize,
			wantContent: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.fileSize)
			for i := range data {
				data[i] = byte('a' + i%26)
			}
			filename := filepath.Join(t.TempDir(), "data")
			if err := os.WriteFile(filename, data, 0644); err != nil {
				t.Fatalf("WriteFile failed: %v", err)
			}

			content, err := ReadWithMaxSize(nil, filename, maxReadSize)
			if tt.wantErr && err == nil {
				t.Fatalf("expected truncation error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(content) != tt.wantLen {
				t.Fatalf("got %d bytes, want %d", len(content), tt.wantLen)
			}
			if tt.wantContent && !bytes.Equal(content, data[:tt.wantLen]) {
				t.Fatalf("returned content does not match file prefix")
			}
		})
	}
}
