// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware

import (
	"os"
	"testing"
)

func TestGetStatusLedPresent(t *testing.T) {
	// Backup original LedModels and restore after test
	originalLedModels := LedModels
	defer func() { LedModels = originalLedModels }()

	// Create a temporary file for testing existence
	tmpFile, err := os.CreateTemp("", "testled")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name()) // clean up
	tmpFilename := tmpFile.Name()
	tmpFile.Close()

	nonExistentFile := tmpFilename + "_missing"

	testCases := []struct {
		name           string
		models         []LedModel
		queryModel     string
		expectedResult bool
	}{
		{
			name:           "Unknown model",
			models:         []LedModel{},
			queryModel:     "UnknownModel",
			expectedResult: false,
		},
		{
			name: "Known model with no Arg (ForceDisk strategy)",
			models: []LedModel{
				{
					Model: "DiskModel",
					Arg:   "",
				},
			},
			queryModel:     "DiskModel",
			expectedResult: true,
		},
		{
			name: "Known model with existing file (absolute path)",
			models: []LedModel{
				{
					Model: "FileModel",
					Arg:   tmpFilename,
				},
			},
			queryModel:     "FileModel",
			expectedResult: true,
		},
		{
			name: "Known model with missing file (absolute path)",
			models: []LedModel{
				{
					Model: "MissingFileModel",
					Arg:   nonExistentFile,
				},
			},
			queryModel:     "MissingFileModel",
			expectedResult: false,
		},
		{
			name: "Regex model match with existing file",
			models: []LedModel{
				{
					Model:  "Regex.*",
					Regexp: true,
					Arg:    tmpFilename,
				},
			},
			queryModel:     "RegexModel123",
			expectedResult: true,
		},
		{
			name: "Regex model mismatch",
			models: []LedModel{
				{
					Model:  "Regex.*",
					Regexp: true,
					Arg:    tmpFilename,
				},
			},
			queryModel:     "Nomatch",
			expectedResult: false,
		},
		{
			name: "Comma separated list, first exists",
			models: []LedModel{
				{
					Model: "MultiModel",
					Arg:   tmpFilename + "," + nonExistentFile,
				},
			},
			queryModel:     "MultiModel",
			expectedResult: true,
		},
		{
			name: "Comma separated list, second exists",
			models: []LedModel{
				{
					Model: "MultiModel2",
					Arg:   nonExistentFile + "," + tmpFilename,
				},
			},
			queryModel:     "MultiModel2",
			expectedResult: true,
		},
		{
			name: "Comma separated list, none exists",
			models: []LedModel{
				{
					Model: "MultiModelNone",
					Arg:   nonExistentFile + "," + nonExistentFile + "_2",
				},
			},
			queryModel:     "MultiModelNone",
			expectedResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			LedModels = tc.models
			result := GetStatusLedPresent(tc.queryModel)
			if result != tc.expectedResult {
				t.Errorf("Expected %v, got %v for model %s", tc.expectedResult, result, tc.queryModel)
			}
		})
	}
}
