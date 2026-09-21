// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"fmt"
	"sort"
	"strings"
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
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// parallelDownloadsParamKey selects how many content trees
// TestDownloadBurstWithDeadMgmtPorts deploys at once.
const parallelDownloadsParamKey = "PARALLEL_DOWNLOADS"

// downloadRetryTime replaces the framework's one-minute download retry timer
// for the duration of the test: a parked download would otherwise be retried
// every 18 to 60 seconds, and the resulting status churn of a whole burst of
// them floods the device's report queue.
const downloadRetryTime = 30 * time.Minute

// transportHandlers is the number of workers the downloader's zedUpload
// transport is configured with. With one, the request queue in front of them
// holds a single request, and every burst of concurrent requests has some of
// them refused for certain (see the test's description).
const transportHandlers = 1

// transportHandlersKey is the downloader.transport.handlers property, spelled
// out because the pillar version evetest builds against predates it.
const transportHandlersKey pillartypes.GlobalSettingKey = "downloader.transport.handlers"

// transportHandlersLogFmt is the start of the line the downloader logs when it
// starts its transport; the number is the configured transportHandlers.
const transportHandlersLogFmt = "zedUpload transport handlers: %d ("

// noProgressLimit is how long the count of content trees in an awaited state
// may stay unchanged, with some still missing, before they count as stuck.
const noProgressLimit = 5 * time.Minute

// burstTree is one content tree of the burst.
type burstTree struct {
	uuid      uuid.UUID
	name      string
	sha256Hex string
}

// TestDownloadBurstWithDeadMgmtPorts verifies that every download of a burst
// of concurrent downloads completes on a device whose management ports mostly
// cannot reach the datastore, while the downloader's zedUpload transport
// refuses requests under the burst. Regression test for downloads that hang
// forever, at 0% and without any error, after the downloader dropped a
// request to its transport: the request queue between the downloader and the
// transport's workers holds as many requests as there are workers, eleven by
// default, and a request that finds it full is refused. The downloader used
// to ignore that refusal and wait for a reply that could never come, so the
// affected blob stayed DOWNLOAD_STARTED forever, nothing retried it, and the
// applications depending on it never came up.
//
// A worker hands each request straight to a transfer goroutine, so with the
// default eleven the queue only fills while all of them are stuck at the same
// time, which on the field node, a busy box under a deployment burst,
// happened now and then. The test makes it happen for certain: it configures
// the transport with a single worker (downloader.transport.handlers), so the
// queue holds one request, and a request posted before that one has been
// taken out is refused. The downloads post from separate goroutines, and a
// burst has them post by the dozens within milliseconds, so plenty of them
// collide. The bursts have the shape of the field one:
//
//   - Four of the five management ports are IPv6-only while the datastore is
//     IPv4 (netmodels.FiveMgmtPortsOneIPv4Uplink). The downloader tries them
//     first and does not skip ports known to be failing; an attempt from them
//     fails at once and locally ("no suitable address found"), so every
//     download posts its request five times within milliseconds before the
//     working uplink, listed last, serves it.
//   - The content trees are first deployed against a datastore path that does
//     not exist, so that every download parks in an error state, and fixing
//     all datastores in one configuration change then makes the downloader
//     re-drive all of them in the same instant, as a datastore credential
//     refresh did on the field node.
//
// The fixed downloader logs every refusal it retries. The last phase requires
// at least one such line from either burst, the deployment against the
// missing path or the wave, so that a run in which the queue never filled
// fails there instead of passing for the wrong reason.
//
// Network model: netmodels.FiveMgmtPortsOneIPv4Uplink -- five ports with a
// shared dual-stack DNS server; only eth4 has IPv4 and reaches the controller
// and evetest's image server; eth0-eth3 are IPv6-only islands.
//
// Device config: five management ports (ethernet0-3 IPv6-only and dead for
// the datastore, ethernet4 the IPv4 uplink, in that order), a download retry
// timer of thirty minutes, so that a parked download stays quiet until the
// burst re-drives it, a transport with a single worker, and PARALLEL_DOWNLOADS
// standalone content trees, each a small random file served by evetest's
// built-in HTTP image server (addressed by its IPv4 address) with its SHA256
// declared. No application and no volume is involved: volumemgr downloads a
// standalone content tree on its own, so the download path is exercised in
// isolation.
//
// Phases:
//  1. Apply the five-port configuration and the two properties, and wait
//     until the device reports the controller-pushed port configuration as
//     current, the dead ports with a global IPv6 address, the uplink with an
//     IPv4 address and without a connectivity error. Then reboot the device,
//     since the downloader sizes its transport once, when it starts, and
//     require the start-up line in which it reports a single worker.
//  2. Add all content trees in a single configuration change, with every
//     datastore pointing at a path that does not exist, and wait until every
//     content tree reports the resulting error. With the retry timer raised,
//     nothing moves on its own after that until the burst.
//  3. Fix all datastores in a single configuration change: the burst.
//  4. Wait until every content tree reaches the loaded state.
//  5. Require the downloader to have logged at least one refused request
//     since the deployment, so that the run is known to have exercised the
//     retry.
//
// The waits of phases 2 and 4 watch for progress rather than the clock. The
// device reports every state change of a content tree or blob as one message
// through a single queue, so with a hundred of them the reports trail the
// device and the budgets are generous; a hang does not need the whole budget
// to show, because nothing is left to report once the other trees are done:
// content trees still missing while the count has not moved for five minutes
// are stuck, and the wait stops there. On failure the test names the content
// trees that never arrived, logs how many objects the device itself holds in
// each state, and the downloader's own view of a few of the unfinished ones
// (bytes, retries, error).
//
// Parameters: HYPERVISOR (shared with the rest of the suite),
// PARALLEL_DOWNLOADS (number of content trees deployed at once, default 100).
func TestDownloadBurstWithDeadMgmtPorts(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.TestParameterDefinition{
			Key:          parallelDownloadsParamKey,
			DefaultValue: 100,
			Description: evetest.TestParameterDescription{
				Summary: "Number of content trees deployed at once, " +
					"i.e. the size of the download burst",
				Default: "100",
			},
		},
	)
	hypervisor := evetest.GetHypervisorParameterValue()
	parallelDownloads := evetest.GetTestParameter[int](parallelDownloadsParamKey)

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.FiveMgmtPortsOneIPv4Uplink,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Phase 1: five management ports; the dead ones first, the uplink last.
	deadPorts := []string{"ethernet0", "ethernet1", "ethernet2", "ethernet3"}
	uplinkPort := "ethernet4"
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	props := pillartypes.NewConfigItemValueMap()
	props.SetGlobalValueInt(pillartypes.DownloadRetryTime,
		uint32(downloadRetryTime.Seconds()))
	props.SetGlobalValueInt(transportHandlersKey, transportHandlers)
	devConfig.SetConfigProperties(props)
	ipv6Net := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V6Only,
	})
	ipv4Net := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	for i, port := range append(deadPorts, uplinkPort) {
		network := ipv6Net
		if port == uplinkPort {
			network = ipv4Net
		}
		devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
			LogicalLabel:  port,
			PhysicalLabel: fmt.Sprintf("eth%d", i),
			InterfaceName: fmt.Sprintf("eth%d", i),
			NetworkUUID:   network,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtOnly,
		})
	}
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(devConfig, true, true)

	t.Eventually(devUpdates, 5*time.Minute).Should(Receive(matchers.SatisfyPredicate(
		"controller port config is current, dead ports have IPv6, "+
			"the uplink has IPv4 and no error",
		func(dinfo *eveinfo.ZInfoDevice) bool {
			if dpc := getCurrentDPC(dinfo); dpc == nil || dpc.GetKey() != "zedagent" {
				return false
			}
			for _, port := range deadPorts {
				if getPortIPv6GlobalAddr(port, dinfo) == nil {
					return false
				}
			}
			return getPortIPv4Addr(uplinkPort, dinfo) != nil &&
				getDevicePort(uplinkPort, dinfo).GetErr().GetDescription() == ""
		})))
	evetest.Checkpoint("mgmt-ports-ready")

	// The downloader sizes its transport once, when it starts, so the single
	// worker configured above needs a reboot to take effect. The downloader
	// reports the size when it starts; require that line before deploying.
	rebootIssued := time.Now()
	device.RequestReboot(true)
	t.Eventually(func() []evetest.LogMsg {
		return device.GetLogs(evetest.LogMsgMatch{
			MsgHasSubstring: fmt.Sprintf(transportHandlersLogFmt, transportHandlers),
			NotBefore:       rebootIssued,
		})
	}, 5*time.Minute, 10*time.Second).ShouldNot(BeEmpty(),
		"the downloader did not report a transport with %d worker(s) after the "+
			"reboot, so the downloader.transport.handlers property did not take effect",
		transportHandlers)
	evetest.Checkpoint("transport-resized")

	// Phase 2: deploy all content trees against a datastore path that does
	// not exist, so that every download fails fast and parks in error.
	const fileSize = 256 * evetest.KiB
	trees := make([]burstTree, 0, parallelDownloads)
	treeUUIDs := make([]uuid.UUID, 0, parallelDownloads)
	for i := range parallelDownloads {
		name := fmt.Sprintf("burst-%03d", i)
		imgFile, sha256Hex := evetest.CreateRandomImageFile(name+".bin", fileSize)
		ctUUID := devConfig.AddContentTree(name, evetest.HTTPStorage{
			ImageFormat:       eveconfig.Format_RAW,
			ImageRelativePath: imgFile,
			ImageSHA256:       sha256Hex,
			ServerAddress:     evetest.GetImageServerIPv4().String(),
			ServerPort:        evetest.GetImageServerPort(),
		})
		trees = append(trees, burstTree{uuid: ctUUID, name: name, sha256Hex: sha256Hex})
		treeUUIDs = append(treeUUIDs, ctUUID)
	}
	for _, datastore := range devConfig.Datastores {
		datastore.Dpath = "not-there"
	}
	tracker := trackContentTrees(device, treeUUIDs)
	defer tracker.stop()
	defer func() {
		if !evetestT.Failed() {
			return
		}
		pending := make(map[string]string)
		for _, tree := range trees {
			if !contentTreeIsLoaded(tracker.get(tree.uuid)) {
				pending[tree.sha256Hex] = tree.name
			}
		}
		logDeviceObjectStates(device)
		logDownloaderView(device, pending, 5)
	}()
	deployStart := time.Now()
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("downloads-deployed")

	awaitContentTrees(t, tracker, trees, "parked in error", contentTreeHasError,
		15*time.Minute)
	evetest.Checkpoint("downloads-parked")

	// Phase 3: fix every datastore in one change; the downloader re-drives
	// every parked download in the same instant.
	for _, datastore := range devConfig.Datastores {
		datastore.Dpath = ""
	}
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("download-burst-started")

	// Phase 4: every content tree must get loaded; none may stay behind.
	awaitContentTrees(t, tracker, trees, "loaded", contentTreeIsLoaded, 30*time.Minute)
	evetest.Checkpoint("download-burst-completed")

	// Phase 5: the downloader logs every refused request it retried. Without
	// at least one in either burst, the deployment against the missing path or
	// the wave, the queue never filled and the run has not exercised what it is
	// meant to exercise.
	var refused []evetest.LogMsg
	t.Eventually(func() []evetest.LogMsg {
		refused = device.GetLogs(evetest.LogMsgMatch{
			MsgHasSubstring: "request queue is full",
			NotBefore:       deployStart,
		})
		return refused
	}, 5*time.Minute, 10*time.Second).ShouldNot(BeEmpty(),
		"the transport never refused a request in either burst although its "+
			"queue holds a single request, so the downloader's retry of a "+
			"refused request was not exercised")
	evetest.Logger().Infof("%d refused requests were retried across both bursts",
		len(refused))
}

// awaitContentTrees waits until the latest report of every content tree
// satisfies reached, polling the tracker and logging each change of the
// count. Content trees still missing while the count has not moved for
// noProgressLimit are stuck, and the wait stops early then, naming them.
func awaitContentTrees(t *WithT, tracker *contentTreeTracker, trees []burstTree,
	state string, reached func(*eveinfo.ZInfoContentTree) bool, budget time.Duration) {
	log := evetest.Logger()
	reachedBefore, lastProgress := -1, time.Now()
	t.Eventually(func(g Gomega) {
		var missing []string
		for _, tree := range trees {
			if info := tracker.get(tree.uuid); !reached(info) {
				missing = append(missing, tree.name+": "+describeContentTree(info))
			}
		}
		if n := len(trees) - len(missing); n != reachedBefore {
			log.Infof("%d of %d content trees %s", n, len(trees), state)
			reachedBefore, lastProgress = n, time.Now()
		}
		sort.Strings(missing)
		if len(missing) > 0 && time.Since(lastProgress) > noProgressLimit {
			StopTrying(fmt.Sprintf("%d of %d content trees are left behind, nothing has "+
				"made progress for %v:\n%s", len(missing), len(trees),
				noProgressLimit, strings.Join(missing, "\n"))).Now()
		}
		g.Expect(missing).To(BeEmpty(), "%d of %d content trees never got %s:\n%s",
			len(missing), len(trees), state, strings.Join(missing, "\n"))
	}, budget, 10*time.Second).Should(Succeed())
}
