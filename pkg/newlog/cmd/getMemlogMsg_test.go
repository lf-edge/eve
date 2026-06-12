// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/sirupsen/logrus"
)

func TestParseMemlogEntryWithData(t *testing.T) {
	g := gomega.NewWithT(t)

	// Open the memlog test data file
	testDataFile := "../testdata/memlog"
	file, err := os.Open(testDataFile)
	g.Expect(err).To(gomega.BeNil(), "Should be able to open memlog test file")
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0
	var failedLines []string

	// Process each line from the file
	for scanner.Scan() {
		lineCount++
		line := scanner.Text()

		if line == "" {
			continue // Skip empty lines
		}

		// Parse the memlog entry
		entry, err := parseMemlogEntry([]byte(line))

		if err != nil {
			failedLines = append(failedLines, line)
			t.Logf("Line %d failed to parse: %v", lineCount, err)
			t.Logf("Raw line: %s", line)
			continue
		}

		// Validate that all required fields are set
		g.Expect(entry.timestamp).ToNot(gomega.BeEmpty(),
			"Line %d: timestamp field should not be empty", lineCount)
		g.Expect(entry.source).ToNot(gomega.BeEmpty(),
			"Line %d: source field should not be empty", lineCount)
		g.Expect(entry.severity).ToNot(gomega.BeEmpty(),
			"Line %d: severity field should not be empty", lineCount)

		// Content should not be empty, if msg wasn't empty
		var lineJSON MemlogLogEntry
		if err = json.Unmarshal([]byte(entry.content), &lineJSON); err == nil && lineJSON.Msg != "" {
			g.Expect(lineJSON.Msg).ToNot(gomega.BeEmpty(),
				"Line %d: msg field in content should not be empty", lineCount)
		}

		// Validate that severity is a valid log level
		_, err = logrus.ParseLevel(entry.severity)
		g.Expect(err).To(gomega.BeNil(),
			"Line %d: severity '%s' should be a valid log level", lineCount, entry.severity)

		// Log first few entries for debugging
		if lineCount <= 10 {
			t.Logf("Entry %d: source='%s', severity='%s', timestamp='%s', content_len=%d",
				lineCount, entry.source, entry.severity, entry.timestamp, len(entry.content))
		}
	}

	// Check for scanner errors
	g.Expect(scanner.Err()).To(gomega.BeNil(), "Scanner should not have errors")

	// Report results
	t.Logf("Processed %d lines from memlog", lineCount)
	t.Logf("Errors: %d", len(failedLines))

	if len(failedLines) > 0 {
		t.Logf("First few failed lines:")
		for i, line := range failedLines {
			if i >= 5 { // Show only first 5 failed lines
				break
			}
			t.Logf("  %s", line)
		}
	}

	// Verify that we processed some entries
	g.Expect(lineCount).To(gomega.BeNumerically(">", 0), "Should have processed at least one line")

	// Verify that we had no errors
	g.Expect(len(failedLines)).To(gomega.Equal(0), "Should have no parsing errors")

	t.Logf("Successfully parsed all %d entries from memlog", lineCount)
}

func TestParseMemlogEntryIndividual(t *testing.T) {
	g := gomega.NewWithT(t)
	format.TruncatedDiff = false // Disable truncation in gomega output

	testCases := []struct {
		name           string
		input          string
		expectError    bool
		expectedFields map[string]string
	}{
		{
			name:        "Simple memlogd entry",
			input:       `{"time":"2025-10-06T18:29:36.264627211Z","source":"memlogd","msg":"memlogd started"}`,
			expectError: false,
			expectedFields: map[string]string{
				"timestamp": "2025-10-06T18:29:36.264627211Z",
				"source":    "memlogd",
				"severity":  "info", // Should default to info
			},
		},
		{
			name:        "Entry with JSON message",
			input:       `{"time":"2025-10-06T18:30:00.123456789Z","source":"pillar","msg":"{\"level\":\"error\",\"time\":\"2025-10-06T18:30:00.123456789Z\",\"msg\":\"test error message\"}"}`,
			expectError: false,
			expectedFields: map[string]string{
				"timestamp": "2025-10-06T18:30:00.123456789Z",
				"source":    "pillar",
				"severity":  "error", // Should parse from inner JSON
			},
		},
		{
			name:        "Entry with many non-standard fields in JSON message",
			input:       `{"time":"2025-10-06T18:31:44.311189723Z","source":"pillar.out","msg":"{\"file\":\"/pillar/types/zedmanagertypes.go:364\",\"func\":\"github.com/lf-edge/eve/pkg/pillar/types.AppInstanceStatus.LogModify\",\"level\":\"info\",\"log_event_type\":\"log\",\"msg\":\"App instance status modify\",\"obj_key\":\"app_instance_status-173ee6b9-c454-45b8-959e-5c1e9c91a0ce\",\"obj_name\":\"nginx\",\"obj_type\":\"app_instance_status\",\"obj_uuid\":\"173ee6b9-c454-45b8-959e-5c1e9c91a0ce\",\"old-purge-in-progress\":0,\"old-restart-in-progress\":0,\"old-state\":\"BOOTING\",\"pid\":2221,\"purge-in-progress\":0,\"restart-in-progress\":0,\"source\":\"zedmanager\",\"state\":\"RUNNING\",\"time\":\"2025-10-06T18:31:44.311128265Z\"}"}`,
			expectError: false,
			expectedFields: map[string]string{
				"timestamp": "2025-10-06T18:31:44.311128265Z",
				"source":    "zedmanager",
				"severity":  "info",
				"content":   `{"file":"/pillar/types/zedmanagertypes.go:364","func":"github.com/lf-edge/eve/pkg/pillar/types.AppInstanceStatus.LogModify","level":"info","log_event_type":"log","msg":"App instance status modify","obj_key":"app_instance_status-173ee6b9-c454-45b8-959e-5c1e9c91a0ce","obj_name":"nginx","obj_type":"app_instance_status","obj_uuid":"173ee6b9-c454-45b8-959e-5c1e9c91a0ce","old-purge-in-progress":0,"old-restart-in-progress":0,"old-state":"BOOTING","pid":2221,"purge-in-progress":0,"restart-in-progress":0,"source":"zedmanager","state":"RUNNING","time":"2025-10-06T18:31:44.311128265Z"}`,
			},
		},
		{
			name:        "Entry with ANSI color codes in a JSON message",
			input:       `{"time":"2026-02-05T18:52:28.551352594Z","source":"pillar","msg":"{\"appuuid\":\"ff9d588b-e22c-4256-abe4-9da5bae810d9\",\"level\":\"info\",\"msg\":\"Hello, \\u001b[31m this is my text \\u001b[0m. How does it look?\",\"time\":\"2026-02-05T18:52:28.551046324Z\"}"}`,
			expectError: false,
			expectedFields: map[string]string{
				"timestamp": "2026-02-05T18:52:28.551046324Z",
				"source":    "pillar",
				"severity":  "info",
				"content":   `{"appuuid":"ff9d588b-e22c-4256-abe4-9da5bae810d9","level":"info","msg":"Hello,  this is my text . How does it look?","time":"2026-02-05T18:52:28.551046324Z"}`,
			},
		},
		{
			name:        "Entry with key=value format",
			input:       `{"time":"2025-10-06T18:30:00.123456789Z","source":"zedagent","msg":"level=warning time=\"2025-10-06T18:30:00.123456789Z\" msg=\"warning message\""}`,
			expectError: false,
			expectedFields: map[string]string{
				"timestamp": "2025-10-06T18:30:00.123456789Z",
				"source":    "zedagent",
				"severity":  "warning", // Should parse from key=value format
			},
		},
		{
			name:        "Invalid JSON",
			input:       `{"time":"2025-10-06T18:29:36.264627211Z","source":"memlogd","msg":"memlogd started"`,
			expectError: true,
		},
		{
			name:        "Empty input",
			input:       ``,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			entry, err := parseMemlogEntry([]byte(tc.input))

			if tc.expectError {
				g.Expect(err).ToNot(gomega.BeNil(), "Should have an error")
				return
			}

			g.Expect(err).To(gomega.BeNil(), "Should not have an error")

			// Check required fields are not empty
			g.Expect(entry.timestamp).ToNot(gomega.BeEmpty(), "timestamp should not be empty")
			g.Expect(entry.source).ToNot(gomega.BeEmpty(), "source should not be empty")
			g.Expect(entry.severity).ToNot(gomega.BeEmpty(), "severity should not be empty")

			// Validate severity is a valid log level
			_, err = logrus.ParseLevel(entry.severity)
			g.Expect(err).To(gomega.BeNil(), "severity should be a valid log level")

			// Check expected field values if provided
			v := reflect.ValueOf(entry)
			for fieldName, expectedValue := range tc.expectedFields {
				f := v.FieldByName(fieldName)
				g.Expect(f.IsValid()).To(gomega.BeTrue(), "Field %s not found in entry", fieldName)
				g.Expect(f.String()).To(gomega.Equal(expectedValue), "Field %s mismatch", fieldName)
			}

			t.Logf("Entry: source='%s', severity='%s', timestamp='%s'",
				entry.source, entry.severity, entry.timestamp)
		})
	}
}

func TestParseLevelTimeMsg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expLevel string
		expTime  string
		expMsg   string
	}{
		{
			name:     "Full format with quotes",
			input:    `level=info time="2025-10-02T11:21:24Z" msg="Test message"`,
			expLevel: "info",
			expTime:  "2025-10-02T11:21:24Z",
			expMsg:   "Test message",
		},
		{
			name:     "No time",
			input:    `level=error msg="Error occurred"`,
			expLevel: "error",
			expTime:  "",
			expMsg:   "Error occurred",
		},
		{
			name:     "Only level",
			input:    `level=warning something else`,
			expLevel: "warning",
			expTime:  "",
			expMsg:   "",
		},
		{
			name:     "Time without quotes (not parsed)",
			input:    `level=info time=2025-10-02T11:21:24Z msg="Test"`,
			expLevel: "info",
			expTime:  "", // Won't be parsed without quotes
			expMsg:   "Test",
		},
		{
			name:     "JSON format (should be skipped)",
			input:    `{"level":"info","msg":"Test"}`,
			expLevel: "",
			expTime:  "",
			expMsg:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			level, timeStr, msg := parseLevelTimeMsg(tt.input)
			g.Expect(level).To(gomega.Equal(tt.expLevel))
			g.Expect(timeStr).To(gomega.Equal(tt.expTime))
			g.Expect(msg).To(gomega.Equal(tt.expMsg))
		})
	}
}

func TestCleanForLogParsing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "ANSI color codes",
			input:    "\x1b[31mRed text\x1b[0m",
			expected: "Red text",
		},
		{
			name:     "ANSI color codes (unicode)",
			input:    "\u001b[31m this is my text \u001b[0m.",
			expected: " this is my text .",
		},
		{
			name:     "Newlines at start and end",
			input:    "\nLine content\n",
			expected: "Line content",
		},
		{
			name:     "Carriage returns at start and end",
			input:    "\rLine content\r",
			expected: "Line content",
		},
		{
			name:     "Tab characters (should be preserved)",
			input:    "Col1\tCol2\tCol3",
			expected: "Col1\tCol2\tCol3",
		},
		{
			name:     "Mixed special characters",
			input:    "\x1b[32mGreen\x1b[0m\n",
			expected: "Green",
		},
		{
			name:     "Newlines in middle (not removed)",
			input:    "Line 1\nLine 2",
			expected: "Line 1\nLine 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			result := cleanForLogParsing(tt.input)
			g.Expect(result).To(gomega.Equal(tt.expected))
		})
	}
}
