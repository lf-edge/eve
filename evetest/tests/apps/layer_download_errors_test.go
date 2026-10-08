// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package apps_test

import (
	"fmt"
	"net"
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
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// missingLayersParamKey selects how many layers the image deployed by
// TestLayerDownloadErrorsBounded has; every one of them fails to download.
const missingLayersParamKey = "MISSING_LAYERS"

// defaultMissingLayers is the layer count at which, on the two management
// ports of netmodels.TwoMgmtPorts, the unbounded error lands in the middle
// of the window where the application status alone overflows a pubsub
// message; see the test's description for the sizes.
const defaultMissingLayers = 24

// maxReportedErrorBytes bounds the error an application may report to the
// controller for a failed download. A pubsub message carries 64 KiB, the
// application status embeds its volume's error twice, so an error over
// ~24 KB cannot be published at all and one not far below it leaves no room
// for a second volume or a longer registry name; a bound of 16 KiB fails
// the error the unbounded code produces here (~31 KB) and passes any fix
// that keeps a volume's error well inside the message.
const maxReportedErrorBytes = 16 * 1024

// heartbeatInterval is how often the device reports metrics during the test
// (timer.metric.interval): a metrics report received more than one interval
// after the last layer failed proves that pillar survived publishing the
// full error, whatever the delivery order of info and metrics messages.
const heartbeatInterval = 5 * time.Second

// missingLayersRetryTime replaces the framework's one-minute download retry
// timer for the duration of the test, so that a failed layer stays failed
// instead of having its error cleared and set again every retry.
const missingLayersRetryTime = 30 * time.Minute

// portTestInterval replaces the default five-minute port retest timer
// (timer.port.testinterval) with its minimum. Verifying a new port
// configuration can leave a stale error on a port (typically ethernet0's
// "All attempts to connect to <controller>" from the moment of the switch),
// and nim only clears it at the next periodic retest; waiting for error-free
// ports would otherwise take a full five minutes.
const portTestInterval = time.Minute

// missingBlobErrorCode is the OCI distribution error code a registry answers
// for a blob it does not have, which every layer pull of the test ends with.
const missingBlobErrorCode = "BLOB_UNKNOWN"

// Image name under which the layer-less image is published into evetest's
// registry, and the display name of the application pulling it.
const (
	missingLayersRepo = "lfedge/evetest-missing-layers"
	missingLayersTag  = "1.0"
	missingLayersApp  = "missing-layers-app"
)

// TestLayerDownloadErrorsBounded verifies that an application whose image
// cannot be downloaded -- every layer fails, from every management port --
// is reported to the controller as an application in error, with an error of
// bounded size, and that the device stays up while reporting it.
//
// Regression test for zedmanager killing the whole of pillar (log.Fatalf in
// the pubsub socket driver, BootReasonFatal, a watchdog reboot of the node,
// every application restarted) because the AppInstanceStatus it published
// had grown past the 64 KiB a pubsub message may carry. Nothing
// bounds the error on its way up: the downloader appends the failure of every
// source address it tried (one per management port), volumemgr joins the
// errors of every blob of the content tree and prefixes the result into the
// volume's error, and zedmanager embeds that twice in the application status,
// once in the volume reference and once more in the app-level error. On the
// field node an 8-layer image whose registry hostname did not resolve, on a
// device with four management addresses, was enough.
//
// The download fails because the image is published into evetest's own OCI
// registry with its manifest and config but without its layer blobs
// (PushImageWithMissingLayersToLocalRegistry): EVE resolves the tag,
// downloads the manifest and the config, and then fails to pull every layer,
// once per management port, with the registry's BLOB_UNKNOWN. That is the
// field failure's shape -- there a DNS timeout per port -- in a form that is
// immediate and needs no network fault: what overflows the status is the
// number of layers times the number of ports, not what each attempt says.
//
// Sizes: each attempt's error is ~640 bytes, as the image name, the pending
// file and the layer reference each carry a digest. With two ports and 24
// layers the error reaches ~31 KB and the unbounded application status,
// which carries it twice, ~86 KB on the wire, a third over the limit, while
// the content tree's and the volume's own statuses, which carry it once, stay
// a quarter under it, so that the unfixed code fails where the field node
// did: in zedmanager. (At 20 layers the application status would only just
// overflow; at 28 the content tree status gets close to the limit itself.)
//
// Network model: netmodels.TwoMgmtPorts -- two ports, each on its own network
// with DHCP and a route to the controller and to evetest's image server, so
// that the downloader has two source addresses to try, and fail from, as the
// field node had four.
//
// Device config: both ports as management ports (ethernet0 and ethernet1, on
// one DHCP IPv4 network), a 5-second metrics interval, a 30-minute download
// retry timer, a one-minute port retest timer (see portTestInterval), no
// network instance -- the application never gets to run and needs no network
// adapter -- and one container application with the image above.
//
// Phases:
//  1. Apply the two-port configuration and wait until the device reports the
//     controller-pushed port configuration as current, with an IPv4 address
//     and no error on both ports: a download started before the second port
//     is up would be tried from one address only, and one started while a
//     port is still failing would not fail the same way from both.
//  2. Publish the image without its layers and deploy the application.
//  3. Wait until the content tree reports every layer as failed, the
//     application reports an error, and a metrics report arrives after that,
//     which proves pillar outlived the full status. Stop at once if the
//     device reboots on its own or an agent logs a fatal: on the unfixed code
//     that is what happens instead, and nothing more is reported until the
//     device is back up.
//  4. Require the reported error to name the registry's error code and to be
//     bounded (maxReportedErrorBytes).
//  5. Delete the application and wait until it is gone.
//
// Parameters: HYPERVISOR (shared with the rest of the suite), MISSING_LAYERS
// (number of layers in the image, default 24).
//
// Suite placement: TestAppsSuite, next to the other TwoMgmtPorts test.
func TestLayerDownloadErrorsBounded(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.TestParameterDefinition{
			Key:          missingLayersParamKey,
			DefaultValue: defaultMissingLayers,
			Description: evetest.TestParameterDescription{
				Summary: "Number of layers in the application's image, " +
					"every one of which fails to download",
				Default: fmt.Sprint(defaultMissingLayers),
			},
		},
	)
	hypervisor := evetest.GetHypervisorParameterValue()
	numLayers := evetest.GetTestParameter[int](missingLayersParamKey)

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.TwoMgmtPorts,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")
	log := evetest.Logger()

	// Phase 1: both ports as management ports, with the timers of the test.
	mgmtPorts := []string{"ethernet0", "ethernet1"}
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	props := types.NewConfigItemValueMap()
	props.SetGlobalValueInt(types.MetricInterval, uint32(heartbeatInterval.Seconds()))
	props.SetGlobalValueInt(types.DownloadRetryTime,
		uint32(missingLayersRetryTime.Seconds()))
	props.SetGlobalValueInt(types.NetworkTestInterval, uint32(portTestInterval.Seconds()))
	devConfig.SetConfigProperties(props)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	for i, port := range mgmtPorts {
		devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
			LogicalLabel:  port,
			PhysicalLabel: fmt.Sprintf("eth%d", i),
			InterfaceName: fmt.Sprintf("eth%d", i),
			NetworkUUID:   dhcpNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})
	}
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	t.Eventually(devUpdates, 5*time.Minute).Should(Receive(matchers.SatisfyPredicate(
		"controller port config is current, both management ports have an "+
			"IPv4 address and no error",
		func(dinfo *eveinfo.ZInfoDevice) bool {
			return mgmtPortsReady(dinfo, mgmtPorts)
		})))
	evetest.Checkpoint("mgmt-ports-ready")

	// Phase 2: publish the image without its layers and deploy the app.
	image, layerDigests, err := evetest.PushImageWithMissingLayersToLocalRegistry(
		missingLayersRepo, missingLayersTag, numLayers)
	if err != nil {
		evetestT.Fatalf("Failed to publish the image without its layers: %v", err)
	}
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName:        missingLayersApp,
		Activate:           true,
		Image:              image,
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        512 * evetest.MiB,
	})
	ctUUID := contentTreeOfImage(evetestT, devConfig, image)
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	ctUpdates, stopCTWatch := device.WatchContentTreeInfo(ctUUID)
	defer stopCTWatch()
	metricUpdates, stopMetricWatch := device.WatchDeviceMetrics()
	defer stopMetricWatch()
	fatals, stopFatalWatch := device.WatchLogs(evetest.LogMsgMatch{
		Severity:  "fatal",
		NotBefore: time.Now(),
	})
	defer stopFatalWatch()
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("app-deployed")

	// Phase 3: every layer failed, the app reports an error, and the device
	// is still alive afterwards.
	var (
		latestApp         *eveinfo.ZInfoApp
		latestCT          *eveinfo.ZInfoContentTree
		lastHeartbeat     time.Time
		allLayersFailedAt time.Time
	)
	crashed := func() string {
		select {
		case msg := <-fatals:
			return fmt.Sprintf("agent %s died: %s", msg.Source, msg.Message)
		default:
		}
		if device.UnexpectedRebootCount() > 0 {
			return fmt.Sprintf("the device rebooted on its own: %s",
				device.GetDeviceInfo().GetLastRebootReason())
		}
		return ""
	}
	t.Eventually(func(g Gomega) {
		for drained := false; !drained; {
			select {
			case info, ok := <-appUpdates:
				drained = !ok
				if ok {
					latestApp = info
				}
			case info, ok := <-ctUpdates:
				drained = !ok
				if ok {
					latestCT = info
				}
			case _, ok := <-metricUpdates:
				drained = !ok
				if ok {
					lastHeartbeat = time.Now()
				}
			default:
				drained = true
			}
		}
		if reason := crashed(); reason != "" {
			StopTrying("pillar did not survive the failed download: " + reason).Now()
		}
		failed := failedLayers(latestCT, layerDigests)
		g.Expect(failed).To(Equal(numLayers),
			"the content tree reports %d of %d layers as failed", failed, numLayers)
		if allLayersFailedAt.IsZero() {
			allLayersFailedAt = time.Now()
		}
		g.Expect(appError(latestApp)).ToNot(BeEmpty(),
			"the application does not report an error")
		g.Expect(lastHeartbeat.After(allLayersFailedAt.Add(heartbeatInterval))).To(BeTrue(),
			"no metrics report from the device since every layer failed")
	}, 10*time.Minute, 5*time.Second).Should(Succeed())
	evetest.Checkpoint("app-error-reported")

	// Phase 4: the error is what the registry said, and bounded.
	errDesc := appError(latestApp)
	log.Infof("The application reports a %d-byte error for its %d failed layers",
		len(errDesc), numLayers)
	t.Expect(errDesc).To(ContainSubstring(missingBlobErrorCode),
		"the application's error does not say why the layers failed to download")
	t.Expect(len(errDesc)).To(BeNumerically("<=", maxReportedErrorBytes),
		"the application's error is %d bytes long, more than the %d bytes a "+
			"bounded error may take", len(errDesc), maxReportedErrorBytes)

	// Phase 5: cleanup.
	deleteAppAndWait(t, device, devConfig, appUUID)
}

// mgmtPortsReady reports whether dinfo shows the controller-pushed port
// configuration as current, with an IPv4 address and no error on every one
// of the named ports.
func mgmtPortsReady(dinfo *eveinfo.ZInfoDevice, ports []string) bool {
	sa := dinfo.GetSystemAdapter()
	if sa == nil || int(sa.GetCurrentIndex()) >= len(sa.GetStatus()) {
		return false
	}
	dpc := sa.GetStatus()[sa.GetCurrentIndex()]
	if dpc.GetKey() != "zedagent" {
		return false
	}
	for _, name := range ports {
		var port *eveinfo.DevicePort
		for _, candidate := range dpc.GetPorts() {
			if candidate.GetName() == name {
				port = candidate
				break
			}
		}
		if port == nil || port.GetErr().GetDescription() != "" {
			return false
		}
		hasIPv4 := false
		for _, addr := range port.GetIPAddrs() {
			if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil {
				hasIPv4 = true
				break
			}
		}
		if !hasIPv4 {
			return false
		}
	}
	return true
}

// contentTreeOfImage returns the UUID of the content tree AddApplication
// created for image, found by the image's URL in the device configuration.
func contentTreeOfImage(evetestT *evetest.T, devConfig *evetest.EdgeDeviceConfig,
	image evetest.DockerContainer) uuid.UUID {
	url := image.ImageName + ":" + image.Tag
	for _, ct := range devConfig.ContentInfo {
		if ct.GetURL() != url {
			continue
		}
		ctUUID, err := uuid.FromString(ct.GetUuid())
		if err != nil {
			evetestT.Fatalf("Content tree %q has an invalid UUID %q: %v",
				url, ct.GetUuid(), err)
		}
		return ctUUID
	}
	evetestT.Fatalf("No content tree for image %q in the device configuration", url)
	return uuid.Nil
}

// failedLayers counts how many of the layers with the given digests the
// content tree's error names as failed blobs. Zero when there is no content
// tree info or no error yet.
func failedLayers(info *eveinfo.ZInfoContentTree, layerDigests []string) int {
	layers := make(map[string]struct{}, len(layerDigests))
	for _, digest := range layerDigests {
		layers[digest] = struct{}{}
	}
	failed := 0
	for _, entity := range info.GetErr().GetEntities() {
		if entity.GetEntity() != eveinfo.Entity_ENTITY_CONTENT_BLOB {
			continue
		}
		if _, ok := layers[entity.GetEntityId()]; ok {
			failed++
			delete(layers, entity.GetEntityId())
		}
	}
	return failed
}

// appError returns the description of the first error the application
// reports, or "" when it reports none (or no info was received yet).
func appError(info *eveinfo.ZInfoApp) string {
	for _, appErr := range info.GetAppErr() {
		if desc := appErr.GetDescription(); desc != "" {
			return desc
		}
	}
	return ""
}
