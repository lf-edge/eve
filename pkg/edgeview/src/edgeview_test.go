// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

func TestWalkLogDirs(t *testing.T) {
	g := NewWithT(t)

	// test the walkLogDirs function
	newlogDir = "../../newlog/testdata"

	const layout = "2006-01-02 15:04:05.000 -0700 MST"
	timestamp := "2024-11-13 10:58:52.618 +0100 CET"
	parsedTime, err := time.Parse(layout, timestamp)
	g.Expect(err).NotTo(HaveOccurred(), "failed to parse timestamp")

	from := parsedTime.Add(-1 * time.Second)
	to := parsedTime.Add(1 * time.Second)
	foundFiles := walkLogDirs(to.Unix(), from.Unix())
	g.Expect(foundFiles).To(HaveLen(1), "expected exactly one file to be found")

	expected := logfiletime{
		filepath: path.Join(newlogDir, "keepSentQueue/dev.log.keep.1731491932618.gz"),
		filesec:  1731491932,
	}
	g.Expect(foundFiles[0]).To(Equal(expected))
}
