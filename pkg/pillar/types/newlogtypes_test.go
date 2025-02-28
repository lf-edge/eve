// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"
	"time"

	"github.com/onsi/gomega"
)

func TestGetTimestampFromFileName(t *testing.T) {
	t.Parallel()
	g := gomega.NewWithT(t)

	tests := []struct {
		name      string
		filename  string
		wantTime  time.Time
		wantError bool
	}{
		{
			name:      "Valid timestamp in filename",
			filename:  "dev.log.1731491904032.gz",
			wantTime:  time.Unix(0, 1731491904032*int64(time.Millisecond)),
			wantError: false,
		},
		{
			name:      "Valid timestamp in regular filename",
			filename:  "dev.log.1731491904032",
			wantTime:  time.Unix(0, 1731491904032*int64(time.Millisecond)),
			wantError: false,
		},
		{
			name:      "Valid timestamp with UUID",
			filename:  "app.8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d.log.1731935033496.gz",
			wantTime:  time.Unix(0, 1731935033496*int64(time.Millisecond)),
			wantError: false,
		},
		{
			name:      "Two timestamps in filename",
			filename:  "dev.log.1731935033496.123.gz",
			wantTime:  time.Unix(0, 1731935033496*int64(time.Millisecond)),
			wantError: false,
		},
		{
			name:      "Invalid timestamp in filename",
			filename:  "dev.log.invalidtimestamp.gz",
			wantTime:  time.Time{},
			wantError: true,
		},
		{
			name:      "No timestamp in filename",
			filename:  "dev.log.gz",
			wantTime:  time.Time{},
			wantError: true,
		},
		{
			name:      "Old timestamp (short format) in filename",
			filename:  "dev.log.123.gz",
			wantTime:  time.Unix(0, 123*int64(time.Millisecond)),
			wantError: false,
		},
		{
			name:      "Old timestamp (long format) in filename",
			filename:  "dev.log.0000000000123.gz",
			wantTime:  time.Unix(0, 123*int64(time.Millisecond)),
			wantError: false,
		},
	}

	for _, tt := range tests {
		tt := tt // create a new variable to hold the value of tt to avoid being overwritten by the next iteration (needed until Go 1.23)
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotTime, err := GetTimestampFromFileName(tt.filename)
			if tt.wantError {
				g.Expect(err).To(gomega.HaveOccurred())
			} else {
				g.Expect(err).NotTo(gomega.HaveOccurred())
				g.Expect(gotTime).To(gomega.Equal(tt.wantTime))
			}
		})
	}
}

func FuzzGetTimestampFromFileName(f *testing.F) {
	testcases := []string{
		"dev.log.1731491904032.gz",
		"app.8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d.log.1731935033496.gz",
		"dev.log.invalidtimestamp.gz",
		"dev.log.gz",
		"dev.log.123456789012.gz",
		"dev.log.1234567890123456.gz",
	}

	for _, tc := range testcases {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, filename string) {
		_, _ = GetTimestampFromFileName(filename)
	})
}

func TestGetUUIDFromFileName(t *testing.T) {
	t.Parallel()
	g := gomega.NewWithT(t)

	tests := []struct {
		name      string
		filename  string
		wantUUID  string
		wantError bool
	}{
		{
			name:      "Valid UUID in filename",
			filename:  "app.8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d.log.1731935033496.gz",
			wantUUID:  "8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d",
			wantError: false,
		},
		{
			name:      "Valid UUID in regular filename",
			filename:  "app.8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d.log.1731935033496",
			wantUUID:  "8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d",
			wantError: false,
		},
		{
			name:      "Valid UUID with timestamp",
			filename:  "app.123e4567-e89b-12d3-a456-426614174000.log.1731935033496.gz",
			wantUUID:  "123e4567-e89b-12d3-a456-426614174000",
			wantError: false,
		},
		{
			name:      "No UUID in filename",
			filename:  "dev.log.1731491904032.gz",
			wantUUID:  "",
			wantError: true,
		},
		{
			name:      "Invalid UUID in filename",
			filename:  "app.invalid-uuid-string.log.1731935033496.gz",
			wantUUID:  "",
			wantError: true,
		},
		{
			name:      "UUID at the end of filename",
			filename:  "app.log.1731935033496.8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d.gz",
			wantUUID:  "8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d",
			wantError: false,
		},
	}

	for _, tt := range tests {
		tt := tt // create a new variable to hold the value of tt to avoid being overwritten by the next iteration (needed until Go 1.23)
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotUUID, err := GetUUIDFromFileName(tt.filename)
			if tt.wantError {
				g.Expect(err).To(gomega.HaveOccurred())
			} else {
				g.Expect(err).NotTo(gomega.HaveOccurred())
				g.Expect(gotUUID).To(gomega.Equal(tt.wantUUID))
			}
		})
	}
}

func FuzzGetUUIDFromFileName(f *testing.F) {
	testcases := []string{
		"app.8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d.log.1731935033496.gz",
		"app.123e4567-e89b-12d3-a456-426614174000.log.1731935033496.gz",
		"dev.log.1731491904032.gz",
		"app.invalid-uuid-string.log.1731935033496.gz",
		"app.log.1731935033496.8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d.gz",
	}

	for _, tc := range testcases {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, filename string) {
		_, _ = GetUUIDFromFileName(filename)
	})
}
