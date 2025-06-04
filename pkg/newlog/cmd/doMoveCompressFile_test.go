// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/onsi/gomega"
)

func TestGetFileInfo(t *testing.T) {
	t.Parallel()
	g := gomega.NewWithT(t)

	tests := []struct {
		name          string
		fileChanInfo  fileChanInfo
		expectedDir   string
		expectedAppID string
	}{
		{
			name: "Device log file for upload",
			fileChanInfo: fileChanInfo{
				tmpfile:   "../testdata/collect/dev.log.upload.123456",
				isApp:     false,
				notUpload: false,
			},
			expectedDir:   uploadDevDir,
			expectedAppID: "",
		},
		{
			name: "Device log file to keep",
			fileChanInfo: fileChanInfo{
				tmpfile:   "../testdata/collect/dev.log.keep.123456",
				isApp:     false,
				notUpload: true,
			},
			expectedDir:   keepSentDir,
			expectedAppID: "",
		},
		{
			name: "App log file for upload",
			fileChanInfo: fileChanInfo{
				tmpfile:   "../testdata/collect/app.8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d.log.123456",
				isApp:     true,
				notUpload: false,
			},
			expectedDir:   uploadAppDir,
			expectedAppID: "8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d",
		},
		{
			name: "App log file to keep",
			fileChanInfo: fileChanInfo{
				tmpfile:   "../testdata/collect/app.8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d.log.123456",
				isApp:     true,
				notUpload: true,
			},
			expectedDir:   keepSentDir,
			expectedAppID: "8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dirName, appuuid := getFileInfo(tt.fileChanInfo)
			g.Expect(dirName).To(gomega.Equal(tt.expectedDir))
			g.Expect(appuuid).To(gomega.Equal(tt.expectedAppID))
		})
	}
}
