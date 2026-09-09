// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"encoding/json"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
)

// blobReuseAllowanceBytes is how much the downloader may still pull and have
// the deployment count as a reuse. It is not zero because a redeploy re-reads
// small metadata -- a manifest, a tag resolution -- even when every layer is
// already in the store; an actual layer download is orders of magnitude larger.
const blobReuseAllowanceBytes = int64(1) << 20

// downloaderRecvBytes totals what the downloader has pulled since boot.
//
// The counter lives under /run, so it resets on every boot. Both readings of a
// before/after pair therefore have to be taken within the same boot, and a
// second reading lower than the first means the device rebooted in between
// rather than that nothing was downloaded.
func downloaderRecvBytes(device *evetest.EdgeDevice) (int64, error) {
	out, err := runEVE(device,
		"eve exec pillar cat /run/downloader/MetricsMap/global.json 2>/dev/null")
	if err != nil {
		return 0, err
	}
	if out == "" {
		return 0, nil
	}
	var metrics map[string]struct {
		URLCounters map[string]struct {
			RecvByteCount int64 `json:"RecvByteCount"`
		} `json:"URLCounters"`
	}
	if err := json.Unmarshal([]byte(out), &metrics); err != nil {
		return 0, err
	}
	var total int64
	for _, conn := range metrics {
		for _, counter := range conn.URLCounters {
			total += counter.RecvByteCount
		}
	}
	return total, nil
}

// snapshotDownloaderBytes takes the "before" reading of a blob-reuse check.
func snapshotDownloaderBytes(t Gomega, device *evetest.EdgeDevice) int64 {
	var total int64
	t.Eventually(func(g Gomega) {
		var err error
		total, err = downloaderRecvBytes(device)
		g.Expect(err).NotTo(HaveOccurred())
	}, 3*time.Minute, 10*time.Second).Should(Succeed())
	evetest.Logger().Infof("downloader has received %d bytes so far this boot", total)
	return total
}

// assertBlobsReused asserts the downloader pulled essentially nothing since
// before, i.e. that whatever was deployed came out of the content store the
// conversion carried over.
//
// Measured in bytes rather than by comparing digests: a redeploy that fetches
// the same layers again ends up holding the same digests it started with, so a
// digest comparison would call that a reuse.
func assertBlobsReused(t Gomega, device *evetest.EdgeDevice, before int64) {
	after, err := downloaderRecvBytes(device)
	t.Expect(err).NotTo(HaveOccurred())
	t.Expect(after).To(BeNumerically(">=", before),
		"the downloader's byte counter went backwards (%d -> %d), so the device "+
			"rebooted between the two readings and they cannot be compared",
		before, after)
	delta := after - before
	evetest.Logger().Infof("downloader received %d bytes across the deployment", delta)
	t.Expect(delta).To(BeNumerically("<", blobReuseAllowanceBytes),
		"the deployment downloaded %d bytes, so it did not reuse the blobs the "+
			"conversion carried over", delta)
}
