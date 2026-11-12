// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// noRedownloadWindow is how long the datastore is watched for a renewed
// request for the file after the device has confirmed the configuration with
// the replaced token. A device that downloads the file again starts doing so
// within seconds of processing that configuration.
const noRedownloadWindow = time.Minute

// TestNoRedownloadOnURLTokenChange verifies that EVE does not download a file
// again when only a GET parameter of its URL changes, while the SHA256
// declared for it, and therefore its content, stays the same.
//
// Some datastores expect an access token as a GET parameter of the download
// URL, for example the shared access signature (SAS) of an Azure blob. Such a
// token expires, so the controller replaces it from time to time, which
// changes the URL of the content tree in the device configuration and nothing
// else. The content is identified by its SHA256, and a device that already
// holds it has no reason to fetch it again. Regression test for volumemgr
// treating every change of a content tree's URL as new content: it deleted
// the content tree together with its blobs and downloaded the file again, on
// every replacement of the token.
//
// The datastore is an HTTP server run by the test itself (see
// recordingDatastore), which records every request it receives. A download is
// thus observed where it cannot be missed, at the datastore, instead of being
// inferred from the state the device reports.
//
// Network model: netmodels.SingleEthWithDHCP -- a single management port. The
// datastore listens on the address of evetest's image server, on a port of its
// own, and the device reaches it the same way as the image server.
//
// Device config: one DHCP management port and one standalone content tree in
// RAW format with its SHA256 declared, whose URL is the name of a file of
// random bytes on the test's datastore followed by "?sig=<token>". No
// application and no volume is involved: volumemgr downloads a standalone
// content tree on its own.
//
// Phases:
//  1. Apply the management port configuration.
//  2. Start the datastore, add the content tree with the first token in its
//     URL, and wait until the device reports it as loaded. Require that the
//     datastore has received a request for the file, and that every request
//     carried the token, so that the GET parameter is known to be part of
//     what the device downloads with.
//  3. Replace the token in the URL of the content tree, leaving everything
//     else as it is, in particular the SHA256, and wait until the device
//     confirms the new configuration as processed.
//  4. Require that the datastore receives no further request for the file
//     for one minute, and that the device then still reports the content
//     tree as loaded and without an error.
//
// Parameters: HYPERVISOR (shared with the rest of the suite).
func TestNoRedownloadOnURLTokenChange(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Phase 1: a single DHCP management port.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("mgmt-network-ready")

	// Phase 2: download the file from the test's own datastore, with the first
	// token as a GET parameter of the content tree's URL.
	const (
		fileName    = "url-token-change.bin"
		fileSize    = 4 * evetest.MiB
		firstQuery  = "sig=first-token"
		secondQuery = "sig=second-token"
	)
	datastore := startRecordingDatastore(t)
	defer datastore.stop()
	sha256Hex := datastore.addRandomFile(t, fileName, fileSize)

	ctUUID := devConfig.AddContentTree("url-token-change", evetest.HTTPStorage{
		ImageFormat:       eveconfig.Format_RAW,
		ImageRelativePath: fileName + "?" + firstQuery,
		ImageSHA256:       sha256Hex,
		ServerAddress:     evetest.GetImageServerIPv4().String(),
		ServerPort:        datastore.port(),
	})
	ctUpdates, stopCTWatch := device.WatchContentTreeInfo(ctUUID)
	defer stopCTWatch()
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("content-tree-config-applied")

	t.Eventually(ctUpdates, 10*time.Minute).Should(Receive(matchers.SatisfyPredicate(
		"content tree is downloaded, verified and loaded",
		contentTreeIsLoaded,
	).StopIf(func(info *eveinfo.ZInfoContentTree) (string, bool) {
		return "Content tree reports an error", contentTreeHasError(info)
	})))

	firstDownload := datastore.requestsFor(fileName)
	t.Expect(firstDownload).ToNot(BeEmpty(),
		"the device reports the content tree as loaded, but the datastore has "+
			"not received any request for %s", fileName)
	t.Expect(firstDownload).To(HaveEach(Equal("GET /"+fileName+"?"+firstQuery)),
		"the device did not request %s with the query string of the content "+
			"tree's URL", fileName)
	evetest.Checkpoint("content-tree-loaded")

	// Phase 3: replace the token. Nothing else changes, in particular not the
	// SHA256, so the content tree still describes the content the device holds.
	var contentTree *eveconfig.ContentTree
	for _, candidate := range devConfig.ContentInfo {
		if candidate.GetUuid() == ctUUID.String() {
			contentTree = candidate
		}
	}
	t.Expect(contentTree).ToNot(BeNil(),
		"content tree %s is missing from the device configuration", ctUUID)
	contentTree.URL = fileName + "?" + secondQuery
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("url-token-replaced")

	// Phase 4: the device must not ask the datastore for the file again.
	t.Consistently(func() []string {
		return datastore.requestsFor(fileName)[len(firstDownload):]
	}, noRedownloadWindow, 5*time.Second).Should(BeEmpty(),
		"the device requested %s from the datastore again, although only the "+
			"token in the URL of its content tree was replaced and the SHA256 "+
			"stayed the same", fileName)

	t.Eventually(func() *eveinfo.ZInfoContentTree {
		return device.GetContentTreeInfo(ctUUID)
	}, time.Minute, 10*time.Second).Should(matchers.SatisfyPredicate(
		"content tree is still loaded and reports no error",
		func(info *eveinfo.ZInfoContentTree) bool {
			return contentTreeIsLoaded(info) && !contentTreeHasError(info)
		}))
	evetest.Checkpoint("no-redownload-verified")
}
