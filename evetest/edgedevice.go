// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	eveflowlog "github.com/lf-edge/eve-api/go/flowlog"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	evelogs "github.com/lf-edge/eve-api/go/logs"
	evemetrics "github.com/lf-edge/eve-api/go/metrics"
	"github.com/lf-edge/eve/evetest/constants"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/logger"
	"github.com/lf-edge/eve/evetest/utils"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// EdgeDevice represents a single onboarded EVE device and provides
// operations to manage its lifecycle, configuration, applications,
// and runtime state.
type EdgeDevice struct {
	th      *TestHarness
	devName string
	// Set of app UUIDs (strings) for which WaitUntilAppIsRunning is active.
	// Used by WatchAppInfo to suppress duplicate state logging.
	appsBeingWaited sync.Map
	// Per-handle override of how long to wait for an upgrade; see
	// SetUpgradeTimeout. Zero means use the package default.
	upgradeTimeout time.Duration
}

// GetEdgeDevice returns a handle to an onboarded EdgeDevice identified by devName.
func GetEdgeDevice(devName string) *EdgeDevice {
	th := getTestHarness()
	if !th.isDeviceOnboarded(devName) {
		th.t.Fatalf("Unknown device %q", devName)
	}
	return &EdgeDevice{th: th, devName: devName}
}

// GetAllEdgeDevices returns handles for all EdgeDevices currently known to the
// test th.
func GetAllEdgeDevices() (devices []*EdgeDevice) {
	th := getTestHarness()
	th.devicesM.Lock()
	defer th.devicesM.Unlock()
	for _, devState := range th.devices {
		devices = append(devices, &EdgeDevice{th: th, devName: devState.name})
	}
	return devices
}

const (
	// All EdgeDevice.Watch* methods return channels with a buffer size of 100.
	// This reduces the risk of dropping info/metrics notifications even if the
	// test is temporarily not reading from the channel (e.g., while waiting on
	// another condition).
	watchChannelBufSize = 100
)

// LogMsg represents a single log message emitted by the device or an application.
type LogMsg struct {
	Severity  string
	Source    string
	Filename  string
	Message   string
	Timestamp time.Time
}

// LogMsgMatch defines filtering criteria for matching log messages.
type LogMsgMatch struct {
	Severity         string
	Source           string
	Filename         string
	MsgHasSubstring  string
	MsgMatchesRegexp regexp.Regexp
	NotBefore        time.Time
	NotAfter         time.Time
}

// FlowLogMatch defines filtering criteria for matching application flow logs.
type FlowLogMatch struct {
	Flow              *eveflowlog.IpFlow // match every non-zero value from the 5-tuple
	Inbound           bool
	VirtualNetAdapter string // logical label
	NetworkInstance   uuid.UUID
	// NotBefore and NotAfter relates to FlowRecord.startTime
	NotBefore time.Time
	NotAfter  time.Time
}

// DNSLogMatch defines filtering criteria for matching application DNS logs.
type DNSLogMatch struct {
	VirtualNetAdapter string // logical label
	NetworkInstance   uuid.UUID
	// NotBefore and NotAfter relates to DnsRequest.requestTime
	NotBefore time.Time
	NotAfter  time.Time
}

// AuthMethod is a marker interface for application authentication methods.
type AuthMethod interface {
	isAuthMethod()
}

// UsernamePasswordAuth represents username/password authentication.
type UsernamePasswordAuth struct {
	Username string
	Password string
}

func (UsernamePasswordAuth) isAuthMethod() {}

// ClientCertAuth represents client certificate–based authentication.
type ClientCertAuth struct {
	KeyPEM string
}

func (ClientCertAuth) isAuthMethod() {}

// GetState returns the current lifecycle state of the device.
func (d *EdgeDevice) GetState() api.EVEDeviceState {
	d.th.devicesM.Lock()
	defer d.th.devicesM.Unlock()
	devState, found := d.th.devices[d.devName]
	if !found {
		return api.EVEDeviceState_EVE_DEVICE_STATE_UNDEFINED
	}
	return devState.state
}

// ApplyConfig applies a device configuration and optionally waits for
// confirmation that it was received and/or processed by the device.
//
// If waitUntilFetched is true, the function blocks until EVE fetches the new
// config from the controller. This is reliable even when the config changes
// the management port, because EVE downloads the config before activating
// the new port — the wait completes while connectivity is still intact.
//
// If waitUntilConfirmed is true, the function additionally waits until EVE
// reports LastProcessedConfig >= the config's timestamp in device metrics,
// which indicates that zedagent has parsed the config and distributed it to
// other microservices. Do not combine this with configs that change the
// management port: the device may lose controller connectivity right after
// applying the change, delaying the metrics publish indefinitely.
//
// The two flags are evaluated in order: fetch first, then confirm.
func (d *EdgeDevice) ApplyConfig(config *EdgeDeviceConfig, waitUntilFetched bool, waitUntilConfirmed bool) {
	if d.devName != config.DeviceName {
		d.th.t.Fatalf("Device name mismatch: "+
			"EdgeDevice handle is for %q but config is for %q",
			d.devName, config.DeviceName)
	}

	// Get previous config.
	d.th.devicesM.Lock()
	devState, found := d.th.devices[d.devName]
	if !found {
		d.th.t.Fatalf("Unknown device %q", d.devName)
	}
	devUUID := devState.ID
	prevConfig := devState.config
	d.th.devicesM.Unlock()

	// Set config ID.
	configVer := d.th.nextConfigVersion(prevConfig)
	newConfig := config.Clone()
	newConfig.Id = &eveconfig.UUIDandVersion{
		Uuid:    devUUID.String(),
		Version: configVer,
	}

	// Set timestamp.
	newConfig.ConfigTimestamp = timestamppb.New(time.Now())

	// Set default global configuration properties.
	newConfig.setDefaultConfigProperties()

	// Preserve device reboot counter and per-app restart/purge counters from
	// the previous config when the new config does not set them explicitly.
	// This prevents a subsequent RequestReboot or Reboot/PurgeApplication
	// call from re-issuing a command the device has already processed.
	if prevConfig != nil {
		if newConfig.Reboot == nil {
			newConfig.Reboot = prevConfig.GetReboot()
		}
		prevApps := make(map[string]*eveconfig.AppInstanceConfig,
			len(prevConfig.GetApps()))
		for _, app := range prevConfig.GetApps() {
			prevApps[app.GetUuidandversion().GetUuid()] = app
		}
		for _, app := range newConfig.GetApps() {
			prev, ok := prevApps[app.GetUuidandversion().GetUuid()]
			if !ok {
				continue
			}
			if app.Restart == nil {
				app.Restart = prev.GetRestart()
			}
			if app.Purge == nil {
				app.Purge = prev.GetPurge()
			}
		}
	}

	// Always keep a non-nil Reboot command in the config so EVE records a baseline
	// counter on first boot. Without this, the first RequestReboot call lands when
	// EVE has no saved counter (opCfg == nil) and EVE's "first boot" guard skips the
	// reboot, saving the counter but never triggering the operation.
	if newConfig.Reboot == nil {
		newConfig.Reboot = &eveconfig.DeviceOpsCmd{Counter: 0, DesiredState: false}
	}

	// Preserve cipher contexts.
	if prevConfig != nil {
		newConfig.CipherContexts = prevConfig.GetCipherContexts()
	}

	ctx, cancel := context.WithTimeout(d.th.ctx, adamApplyConfigTimeout)
	err := d.th.adamClient.ApplyDeviceConfig(ctx, devUUID, newConfig.EdgeDevConfig)
	cancel()
	if err != nil {
		d.th.t.Fatalf("Failed to apply the new configuration "+
			"(version %s) for device %q: %v", configVer, d.devName, err)
	}

	// Save the applied config.
	d.th.devicesM.Lock()
	d.th.devices[d.devName].config = newConfig
	d.th.devicesM.Unlock()

	if waitUntilFetched {
		d.th.log.Infof(
			"Waiting for device %q to fetch the latest config (version %s)...",
			d.devName, configVer)
		ctx, cancel = context.WithTimeout(d.th.ctx, deviceApplyConfigTimeout)
		err = d.th.adamClient.WaitUntilDevRequest(ctx, devUUID, "/config")
		cancel()
		if err != nil {
			d.th.t.Fatalf(
				"Device %q failed to fetch the latest config (version %s): %v",
				d.devName, configVer, err)
		}
		d.th.log.Infof("Device %q fetched the latest config (version %s)",
			d.devName, configVer)
	}

	if waitUntilConfirmed {
		// Wait for DeviceMetric.LastProcessedConfig >= configTimestamp. EVE sets
		// LastProcessedConfig to the config's own ConfigTimestamp, so the
		// comparison is clock-skew-free.
		configTs := newConfig.ConfigTimestamp.AsTime()
		d.th.log.Infof(
			"Waiting for device %q to confirm the latest config (version %s)...",
			d.devName, configVer)
		ctx, cancel = context.WithTimeout(d.th.ctx, deviceApplyConfigTimeout)
		defer cancel()
		d.th.devicesM.Lock()
		dev := d.th.devices[d.devName]
		if dev.configAppliedCond == nil {
			dev.configAppliedCond = sync.NewCond(&d.th.devicesM)
		}
		// sync.Cond.Wait has no context awareness, so a separate goroutine
		// broadcasts on cancellation/timeout to unblock the loop below.
		done := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				dev.configAppliedCond.Broadcast()
			case <-done:
			}
		}()
		for dev.lastProcessedConfigTs.Before(configTs) {
			if ctx.Err() != nil {
				break
			}
			dev.configAppliedCond.Wait()
		}
		confirmed := !dev.lastProcessedConfigTs.Before(configTs)
		close(done)
		d.th.devicesM.Unlock()
		if !confirmed {
			d.th.t.Fatalf(
				"Device %q failed to confirm the latest config (version %s): "+
					"timed out waiting for LastProcessedConfig >= %v",
				d.devName, configVer, configTs)
		}
		d.th.log.Infof("Device %q confirmed the latest config (version %s)",
			d.devName, configVer)
	}
}

// GetConfig returns the current device configuration.
func (d *EdgeDevice) GetConfig() *EdgeDeviceConfig {
	return d.getConfig(true)
}

func (d *EdgeDevice) getConfig(clone bool) *EdgeDeviceConfig {
	d.th.devicesM.Lock()
	defer d.th.devicesM.Unlock()
	devState, found := d.th.devices[d.devName]
	if !found {
		d.th.t.Fatalf("Unknown device %q", d.devName)
	}
	if !clone {
		return devState.config
	}
	return devState.config.Clone()
}

// GetDeviceIPAddress returns IP addresses assigned to the specified network adapter.
// If netAdapterLogicalLabel is empty, IP addresses from all adapters are returned.
func (d *EdgeDevice) GetDeviceIPAddress(netAdapterLogicalLabel string) []net.IP {
	deviceInfo := d.GetDeviceInfo()
	if deviceInfo == nil {
		return nil
	}
	sysAdapter := deviceInfo.GetSystemAdapter()
	if sysAdapter == nil {
		return nil
	}
	statuses := sysAdapter.GetStatus()
	idx := int(sysAdapter.GetCurrentIndex())
	if idx >= len(statuses) {
		return nil
	}
	var ips []net.IP
	for _, port := range statuses[idx].GetPorts() {
		if netAdapterLogicalLabel != "" && port.GetName() != netAdapterLogicalLabel {
			continue
		}
		for _, ipStr := range port.GetIPAddrs() {
			ip := net.ParseIP(ipStr)
			if ip != nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

// GetArch returns the CPU architecture of the device ("amd64" or "arm64"),
// as determined during Setup (see TestHarness.selectArch) -- not merely the
// preferred architecture requested via EVETEST_PREFERRED_ARCH, which can
// differ from the device's actual one on a broker that does not support it
// (selectArch falls back to whatever the broker does support).
func (d *EdgeDevice) GetArch() string {
	d.th.devicesM.Lock()
	devState, found := d.th.devices[d.devName]
	d.th.devicesM.Unlock()
	if !found {
		d.th.t.Fatalf("Unknown device %q", d.devName)
	}
	switch devState.imageRef.Arch {
	case api.ArchType_ARCH_AMD64:
		return "amd64"
	case api.ArchType_ARCH_ARM64:
		return "arm64"
	default:
		d.th.t.Fatalf("Device %q has unknown architecture: %v",
			d.devName, devState.imageRef.Arch)
		return ""
	}
}

// BaseOSDatastoreType selects how EdgeDevice.UpgradeEVE delivers the target
// EVE rootfs to the device.
type BaseOSDatastoreType int

const (
	// BaseOSDatastoreHTTP has evetest extract the raw rootfs image from the
	// locally-pulled EVE docker image and serve it over evetest's own
	// embedded HTTP image server. This is the traditional/default path and
	// works even when the target image is not (or cannot be) hosted on a
	// registry reachable from the device.
	BaseOSDatastoreHTTP BaseOSDatastoreType = iota
	// BaseOSDatastoreOCI has EVE pull the target rootfs directly from the
	// same OCI registry the target image was tagged in (e.g. Docker Hub),
	// using a container-registry Datastore. evetest still pulls the image
	// locally first to determine the target short version, but skips
	// extracting the raw rootfs and serving it over HTTP.
	BaseOSDatastoreOCI
)

func (t BaseOSDatastoreType) String() string {
	switch t {
	case BaseOSDatastoreOCI:
		return "oci"
	case BaseOSDatastoreHTTP:
		fallthrough
	default:
		return "http"
	}
}

// FromString parses a datastore type name string and sets the
// BaseOSDatastoreType value.
func (t *BaseOSDatastoreType) FromString(s string) error {
	switch strings.ToLower(s) {
	case "", "http":
		*t = BaseOSDatastoreHTTP
	case "oci":
		*t = BaseOSDatastoreOCI
	default:
		return fmt.Errorf("invalid BaseOSDatastoreType: %q", s)
	}
	return nil
}

// UpgradeEVE upgrades the EVE OS to the specified version and optionally
// waits until the upgrade completes or reverts.
// datastoreType selects how the target rootfs is delivered to the device --
// see BaseOSDatastoreType.
// When expectRevert is true, the upgrade is expected to fail and EVE to revert
// to the previous version -- the function then waits for the target version to
// show a FAILED status instead of waiting for it to become active.
// A reverted upgrade causes two reboots (one to try the new version, one to
// revert), so the expected reboot count is incremented accordingly.
func (d *EdgeDevice) UpgradeEVE(targetEVEVersion string, targetEVEHypervisor Hypervisor,
	datastoreType BaseOSDatastoreType, waitUntilUpgraded bool, expectRevert bool) {

	// Read current device arch (set during Setup).
	d.th.devicesM.Lock()
	devState, found := d.th.devices[d.devName]
	if !found {
		d.th.devicesM.Unlock()
		d.th.t.Fatalf("Unknown device %q", d.devName)
	}
	currentImageRef := devState.imageRef
	d.th.devicesM.Unlock()

	// BaseOSDatastoreOCI has EVE pull a container image, while the live image transport
	// delivers a local disk image instead of a container.
	// This combination does not make sense.
	if datastoreType == BaseOSDatastoreOCI && LocalLiveImageRequested() {
		d.th.t.Fatalf(
			"UpgradeEVE: BaseOSDatastoreOCI requires EVE to pull a container image, but "+
				"%s%s selects a local EVE live (disk) image instead of a container image -- "+
				"unset %s%s to upgrade via OCI, or use BaseOSDatastoreHTTP to upgrade with "+
				"the live image",
			constants.EnvPrefix, constants.EVELiveImageEnv,
			constants.EnvPrefix, constants.EVELiveImageEnv)
	}

	// The live transport delivers an upgrade as the raw rootfs the local build
	// already contains, rather than pulling a container image to extract the same
	// file from. Which build that is comes from the version axis exactly as it
	// does for a fresh device, so an explicitly requested target version is
	// honoured (and must be built locally) while an unset one means the newest.
	if datastoreType == BaseOSDatastoreHTTP && LocalLiveImageRequested() {
		d.upgradeEVEFromLocalBuild(targetEVEVersion, currentImageRef.Arch,
			currentImageRef.Hypervisor, waitUntilUpgraded, expectRevert)
		return
	}

	targetImageRef := &api.ImageRef{
		Repo:       currentImageRef.Repo,
		Version:    targetEVEVersion,
		Hypervisor: targetEVEHypervisor.toAPIType(),
		Arch:       currentImageRef.Arch,
	}
	imageName, err := utils.EVEDockerImageName(targetImageRef)
	if err != nil {
		d.th.t.Fatalf("Invalid target image ref: %v", err)
	}
	d.th.log.Infof("Pulling EVE image %s", imageName)

	ctx, cancel := context.WithTimeout(d.th.ctx, eveImagePullTimeout)
	defer cancel()

	logger := d.th.log.WithField("component", "upgrade")
	err = utils.PullDockerImage(ctx, logger, imageName)
	if err != nil {
		d.th.t.Fatalf("Failed to pull EVE image %s: %v", imageName, err)
	}

	archStr := "amd64"
	if currentImageRef.Arch == api.ArchType_ARCH_ARM64 {
		archStr = "arm64"
	}
	platform := "linux/" + archStr

	// Get the actual short version string from the image.
	versionOut, err := utils.RunDockerCommand(
		ctx, logger, imageName, "version", nil, platform)
	if err != nil {
		d.th.t.Fatalf("Failed to get version from image %s: %v",
			imageName, err)
	}
	shortVersion := strings.TrimSpace(versionOut)
	d.th.log.Debugf("Target EVE short version is %q", shortVersion)

	if datastoreType == BaseOSDatastoreOCI {
		// Publish imageName to evetest's own embedded OCI registry.
		dockerContainer, err := PushDockerImageToLocalRegistry(imageName)
		if err != nil {
			d.th.t.Fatalf("UpgradeEVE: %v", err)
		}
		d.th.log.Infof(
			"Configuring EVE to pull rootfs %s from evetest's local OCI registry", imageName)
		config := d.GetConfig()
		config.SetBaseOS(dockerContainer, shortVersion)
		d.applyUpgradeConfig(config, shortVersion, waitUntilUpgraded, expectRevert)
		return
	}

	// Extract rootfs (cache by short version to avoid re-extraction on reuse).
	rootfsFilename := "rootfs-" + shortVersion + ".img"
	rootfsPath := filepath.Join(d.th.imgServerDir, rootfsFilename)
	if _, statErr := os.Stat(rootfsPath); os.IsNotExist(statErr) {
		d.th.log.Infof("Extracting EVE rootfs from %s", imageName)
		_, err = utils.RunDockerCommand(ctx, logger, imageName,
			"-f raw rootfs",
			map[string]string{"/out": d.th.imgServerDir},
			platform)
		if err != nil {
			d.th.t.Fatalf("Failed to extract EVE rootfs from %s: %v",
				imageName, err)
		}
		defaultOut := filepath.Join(d.th.imgServerDir, "rootfs.img")
		if renErr := os.Rename(defaultOut, rootfsPath); renErr != nil {
			d.th.t.Fatalf("Failed to rename EVE rootfs: %v", renErr)
		}
	} else {
		d.th.log.Infof("Reusing cached rootfs %s", rootfsFilename)
	}

	d.applyUpgradeOverHTTP(rootfsPath, rootfsFilename, shortVersion,
		waitUntilUpgraded, expectRevert)
}

// upgradeEVEFromLocalBuild delivers an upgrade from a local build's own
// installer/rootfs.img instead of pulling a container image to extract the same
// file out of. targetEVEVersion selects which local build, empty meaning the
// newest; the target hypervisor is not a choice here, since a build is delivered
// as it was built.
func (d *EdgeDevice) upgradeEVEFromLocalBuild(targetEVEVersion string,
	arch api.ArchType, runningHypervisor api.HypervisorType,
	waitUntilUpgraded, expectRevert bool) {

	zarch, err := zarchDirName(arch)
	if err != nil {
		d.th.t.Fatalf("UpgradeEVE: %v", err)
	}
	img, err := resolveLocalLiveImage(zarch, targetEVEVersion)
	if err != nil {
		d.th.t.Fatalf("UpgradeEVE: failed to resolve the local EVE build: %v", err)
	}
	if img == nil {
		// Unreachable: this path is only taken when the live transport is on.
		d.th.t.Fatalf("UpgradeEVE: the live image transport is not configured")
	}
	if img.RootfsPath == "" {
		d.th.t.Fatalf("UpgradeEVE: local EVE build %q has no installer/rootfs.img "+
			"to upgrade to", img.Version)
	}
	if img.ShortVersion == "" {
		d.th.t.Fatalf("UpgradeEVE: local EVE build %q records no "+
			"installer/eve_version, so the upgraded version could not be "+
			"recognised in the device's reported software list", img.Version)
	}
	// Whether an upgrade may change hypervisor flavor is EVE's call, not the test
	// framework's -- today EVE rejects it (the rootfs has to fit partitions sized
	// for the flavor that made them), and that is expected to change. So this
	// delivers the build either way and only leaves a breadcrumb, because EVE
	// reports the rejection as a FAILED base OS with an empty sub-status, which
	// says nothing about the cause.
	if buildHV, known := liveImageHypervisor(img.ShortVersion); known {
		if runningHV := hypervisorFromAPIType(runningHypervisor); runningHV != buildHV {
			d.th.log.Warnf("Device %q runs %s and the local EVE build being "+
				"delivered (%s) is %s; EVE may reject a base OS that changes "+
				"hypervisor flavor", d.devName, runningHV, img.Version, buildHV)
		}
	}

	// Staged as a copy rather than a link: the file is served for the whole
	// download, and rebuilding in place (LIVE_UPDATE=1) would otherwise change it
	// under the device mid-transfer. Named by version so consecutive tests
	// against the same build reuse it, exactly as the container path does.
	rootfsFilename := "rootfs-" + img.ShortVersion + ".img"
	rootfsPath := filepath.Join(d.th.imgServerDir, rootfsFilename)
	if _, statErr := os.Stat(rootfsPath); os.IsNotExist(statErr) {
		d.th.log.Infof("Staging local EVE rootfs %s for the upgrade", img.RootfsPath)
		if copyErr := utils.CopyFile(img.RootfsPath, rootfsPath); copyErr != nil {
			d.th.t.Fatalf("UpgradeEVE: failed to stage rootfs %q: %v",
				img.RootfsPath, copyErr)
		}
	} else {
		d.th.log.Infof("Reusing staged rootfs %s", rootfsFilename)
	}

	d.applyUpgradeOverHTTP(rootfsPath, rootfsFilename, img.ShortVersion,
		waitUntilUpgraded, expectRevert)
}

// applyUpgradeOverHTTP points the device's BaseOS config at a rootfs image
// already staged in the harness's HTTP image server and, optionally, waits
// for the outcome. Shared by the two HTTP-serving transports (registry-pulled
// and local-build): they differ only in how rootfsPath got there.
func (d *EdgeDevice) applyUpgradeOverHTTP(rootfsPath, rootfsFilename, shortVersion string,
	waitUntilUpgraded, expectRevert bool) {

	sha256hex, fileSize, err := utils.FileHashAndSize(rootfsPath)
	if err != nil {
		d.th.t.Fatalf("UpgradeEVE: failed to hash rootfs %s: %v", rootfsPath, err)
	}

	// Build upgrade device config from a clone of the current config.
	config := d.GetConfig()
	config.SetBaseOS(HTTPStorage{
		ImageFormat:       eveconfig.Format_RAW,
		ImageSHA256:       sha256hex,
		MaxDownloadBytes:  uint64(fileSize),
		ImageRelativePath: rootfsFilename,
		ServerAddress:     GetImageServerIPv4().String(),
		ServerPort:        GetImageServerPort(),
	}, shortVersion)

	d.applyUpgradeConfig(config, shortVersion, waitUntilUpgraded, expectRevert)
}

// applyUpgradeConfig applies an already-built upgrade device config and,
// optionally, waits for the outcome. Shared by all datastore transports:
// they differ only in how the BaseOS config gets built.
func (d *EdgeDevice) applyUpgradeConfig(config *EdgeDeviceConfig, shortVersion string,
	waitUntilUpgraded, expectRevert bool) {

	d.th.log.Infof("Applying EVE upgrade config (target=%s)", shortVersion)
	// A successful upgrade reboots once; a reverted upgrade reboots twice
	// (once to try the new version, once to revert to the previous one).
	d.th.incExpectedRebootCount(d.devName)
	if expectRevert {
		d.th.incExpectedRebootCount(d.devName)
	}
	d.th.devicesM.Lock()
	d.th.devices[d.devName].wasUpgraded = true
	d.th.devicesM.Unlock()
	d.ApplyConfig(config, false, false)

	if waitUntilUpgraded {
		if expectRevert {
			d.waitForRevert(shortVersion)
		} else {
			d.waitForUpgrade(shortVersion)
		}
	}
}

// waitForUpgrade blocks until the device's SwList contains an entry for
// targetShortVersion with PartitionState=="active", or fatals on failure/timeout.
func (d *EdgeDevice) waitForUpgrade(targetShortVersion string) {
	d.th.log.Infof("Waiting for device %q to upgrade to %s",
		d.devName, targetShortVersion)
	devUUID := d.getDevUUID()

	infoCh := make(chan *eveinfo.ZInfoMsg, 20)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiDevice
		},
		infoCh)
	if err != nil {
		d.th.t.Fatalf("Failed to subscribe to info messages: %v", err)
	}
	defer unsub()

	ctx, cancel := context.WithTimeout(d.th.ctx, d.upgradeWaitTimeout())
	defer cancel()

	var lastLoggedState, lastLoggedStatus string
	for {
		select {
		case msg, ok := <-infoCh:
			if !ok {
				d.th.t.Fatalf("Device info subscription closed unexpectedly")
			}
			for _, sw := range msg.GetDinfo().GetSwList() {
				if sw.GetShortVersion() != targetShortVersion {
					continue
				}
				if sw.GetUserStatus() == eveinfo.BaseOsStatus_FAILED {
					d.th.t.Fatalf("EVE upgrade to %s failed: %s",
						targetShortVersion, sw.GetSubStatusStr())
				}
				if sw.GetPartitionState() == "active" {
					d.th.log.Infof("Device %q successfully upgraded to %s",
						d.devName, targetShortVersion)
					return
				}
				state := sw.GetPartitionState()
				status := sw.GetUserStatus().String()
				if state != lastLoggedState || status != lastLoggedStatus {
					d.th.log.Infof("EVE upgrade in progress for device %s "+
						"(state=%s, status=%s)", d.devName, state, status)
					lastLoggedState, lastLoggedStatus = state, status
				}
			}
		case <-ctx.Done():
			d.th.t.Fatalf("Timed out waiting for device %q to upgrade to %s",
				d.devName, targetShortVersion)
		}
	}
}

// waitForRevert blocks until the device's SwList shows the target version with
// a FAILED status (indicating EVE rejected it and reverted to the previous version),
// or fatals on timeout.
func (d *EdgeDevice) waitForRevert(targetShortVersion string) {
	d.th.log.Infof("Waiting for device %q to revert from failed upgrade to %s",
		d.devName, targetShortVersion)
	devUUID := d.getDevUUID()

	infoCh := make(chan *eveinfo.ZInfoMsg, 20)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiDevice
		},
		infoCh)
	if err != nil {
		d.th.t.Fatalf("Failed to subscribe to info messages: %v", err)
	}
	defer unsub()

	ctx, cancel := context.WithTimeout(d.th.ctx, eveUpgradeTimeout)
	defer cancel()

	var lastLoggedState, lastLoggedStatus string
	for {
		select {
		case msg, ok := <-infoCh:
			if !ok {
				d.th.t.Fatalf("Device info subscription closed unexpectedly")
			}
			for _, sw := range msg.GetDinfo().GetSwList() {
				if sw.GetShortVersion() != targetShortVersion {
					continue
				}
				if sw.GetUserStatus() == eveinfo.BaseOsStatus_FAILED {
					d.th.log.Infof("Device %q successfully reverted from %s: %s",
						d.devName, targetShortVersion, sw.GetSubStatusStr())
					return
				}
				state := sw.GetPartitionState()
				status := sw.GetUserStatus().String()
				if state != lastLoggedState || status != lastLoggedStatus {
					d.th.log.Infof("Upgrade revert in progress (state=%s, status=%s)",
						state, status)
					lastLoggedState, lastLoggedStatus = state, status
				}
			}
		case <-ctx.Done():
			d.th.t.Fatalf("Timed out waiting for device %q to revert from upgrade to %s",
				d.devName, targetShortVersion)
		}
	}
}

// RequestReboot requests a device reboot via configuration and optionally
// waits until the reboot completes.
func (d *EdgeDevice) RequestReboot(waitUntilRebooted bool) {
	d.th.incExpectedRebootCount(d.devName)
	config := d.getConfig(true)
	reboot := config.GetReboot()
	if reboot == nil {
		config.Reboot = &eveconfig.DeviceOpsCmd{
			Counter: 1, DesiredState: true}
	} else {
		config.Reboot = &eveconfig.DeviceOpsCmd{
			Counter: reboot.GetCounter() + 1, DesiredState: true}
	}
	d.rebootAndWait(waitUntilRebooted, func() {
		d.ApplyConfig(config, false, false)
	})
}

// SoftReboot reboots the device from the console/SSH.
func (d *EdgeDevice) SoftReboot(waitUntilRebooted bool) {
	d.th.incExpectedRebootCount(d.devName)
	d.th.collectCoverageFromDevice(d.th.ctx, d.devName)
	d.rebootAndWait(waitUntilRebooted, func() {
		ctx, cancel := context.WithTimeout(d.th.ctx, quickSSHCommandTimeout)
		err := d.th.runScriptOnEVEOverSSH(ctx, d.devName, "reboot", nil, nil, 0)
		cancel()
		if err != nil {
			d.th.t.Fatalf("SoftReboot: failed to run reboot over SSH: %v", err)
		}
	})
}

// HardReboot triggers device reboot through the broker.
func (d *EdgeDevice) HardReboot(waitUntilRebooted bool) {
	d.th.incExpectedRebootCount(d.devName)
	d.th.collectCoverageFromDevice(d.th.ctx, d.devName)
	d.rebootAndWait(waitUntilRebooted, func() {
		devCtrlReq := &api.DeviceControlRequest{
			ClientId:   d.th.brokerClientID,
			DeviceName: d.devName,
		}
		rebootCtx, rebootCancel := context.WithTimeout(
			d.th.ctx, brokerRebootEVEDeviceTimeout)
		_, err := d.th.brokerClient.RebootDevice(rebootCtx, devCtrlReq)
		rebootCancel()
		if err != nil {
			d.th.t.Fatalf("HardReboot: broker failed to reboot device %q: %v",
				d.devName, err)
		}
	})
}

// PowerOff hard-powers off the device through the broker (bypassing any
// graceful ACPI shutdown). The broker RPC blocks until the provider confirms
// the VM is stopped, so no separate wait parameter is needed.
func (d *EdgeDevice) PowerOff() {
	d.th.collectCoverageFromDevice(d.th.ctx, d.devName)
	devCtrlReq := &api.DeviceControlRequest{
		ClientId:   d.th.brokerClientID,
		DeviceName: d.devName,
	}
	ctx, cancel := context.WithTimeout(d.th.ctx, brokerPowerOffEVEDeviceTimeout)
	defer cancel()
	_, err := d.th.brokerClient.PowerOffDevice(ctx, devCtrlReq)
	if err != nil {
		d.th.t.Fatalf("PowerOff: broker failed to power off device %q: %v",
			d.devName, err)
	}
}

// PowerOn powers the device back on through the broker and optionally waits
// until it boots and reports back to the controller.
//
// TODO: following a true hard power-off, nodeagent does not reliably
// republish an updated ZInfoDevice.LastRebootTime (the reboot-reason
// detection that rebootAndWait's wait relies on appears to assume a
// cooperative in-place OS reboot, not an external power-cycle).
// Until that's root-caused on the EVE side, pass waitUntilOnline=false here
// and confirm recovery some other way (e.g. via WaitUntilAppIsRunning
// on the relevant apps).
func (d *EdgeDevice) PowerOn(waitUntilOnline bool) {
	d.th.incExpectedRebootCount(d.devName)
	d.rebootAndWait(waitUntilOnline, func() {
		devCtrlReq := &api.DeviceControlRequest{
			ClientId:   d.th.brokerClientID,
			DeviceName: d.devName,
		}
		ctx, cancel := context.WithTimeout(d.th.ctx, brokerPowerOnEVEDeviceTimeout)
		defer cancel()
		_, err := d.th.brokerClient.PowerOnDevice(ctx, devCtrlReq)
		if err != nil {
			d.th.t.Fatalf("PowerOn: broker failed to power on device %q: %v",
				d.devName, err)
		}
	})
}

// ExpectAdditionalReboots tells the harness to expect n more device-initiated
// reboots beyond those it already accounts for (UpgradeEVE counts one reboot per
// upgrade). A cross-flavor boot-disk conversion that runs an offline shrink/grow
// reboots additional times; the number is known only to the test driving it (a
// plain kvm<->k conversion with no resize reboots differently than a shrink+grow),
// so the test declares it here to keep the teardown reboot-count check accurate.
func (d *EdgeDevice) ExpectAdditionalReboots(n int) {
	for i := 0; i < n; i++ {
		d.th.incExpectedRebootCount(d.devName)
	}
}

// SetUpgradeTimeout overrides how long UpgradeEVE waits for the device to come
// back running the target version, for this handle only.
//
// The default is sized for an ordinary base-OS upgrade: download, one reboot,
// done. A cross-flavor boot-disk conversion is a different animal — it also runs
// an offline shrink+grow across several reboots and then brings up a whole
// container-cluster stack — and it lands close enough to the default that a
// healthy conversion and an expired budget are decided by a couple of minutes of
// host load. A test driving one should raise the timeout, otherwise it reports a
// conversion that was still progressing as a failure.
func (d *EdgeDevice) SetUpgradeTimeout(timeout time.Duration) {
	d.upgradeTimeout = timeout
}

// upgradeWaitTimeout is the effective upgrade wait for this handle.
func (d *EdgeDevice) upgradeWaitTimeout() time.Duration {
	if d.upgradeTimeout > 0 {
		return d.upgradeTimeout
	}
	return eveUpgradeTimeout
}

// rebootAndWait executes triggerFn to initiate a device reboot and, if
// wait is true, blocks until the device confirms the reboot by reporting
// a ZInfoDevice.lastRebootTime strictly after the moment triggerFn was called.
//
// The subscription is established before triggerFn is invoked to avoid
// missing the post-reboot info message. Device and evetest clocks are
// assumed to be in sync.
func (d *EdgeDevice) rebootAndWait(wait bool, triggerFn func()) {
	if !wait {
		triggerFn()
		return
	}

	devUUID := d.getDevUUID()

	// Subscribe before triggering the reboot so we cannot miss the
	// post-reboot info message that arrives after the device comes back.
	infoCh := make(chan *eveinfo.ZInfoMsg, 20)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiDevice
		},
		infoCh,
	)
	if err != nil {
		d.th.t.Fatalf("Failed to subscribe to info messages for device %q: %v",
			d.devName, err)
	}
	defer unsub()

	// Record local time just before issuing the reboot command.
	// lastRebootTime > rebootIssuedAt confirms the device has completed
	// the reboot triggered by this call.
	// Assumes that evetest and device clocks are in-sync.
	rebootIssuedAt := time.Now()
	triggerFn()
	d.th.log.Infof("Waiting for device %q to reboot (issued at: %s)...",
		d.devName, rebootIssuedAt)

	waitCtx, waitCancel := context.WithTimeout(d.th.ctx, deviceRebootTimeout)
	defer waitCancel()

	for {
		select {
		case msg, ok := <-infoCh:
			if !ok {
				d.th.t.Fatalf("Info subscription closed while waiting "+
					"for device %q to reboot", d.devName)
			}
			ts := msg.GetDinfo().GetLastRebootTime()
			if ts != nil && ts.AsTime().After(rebootIssuedAt) {
				d.th.log.Infof("Device %q has rebooted (last reboot time: %s)",
					d.devName, ts.AsTime())
				return
			}
		case <-waitCtx.Done():
			d.th.t.Fatalf("Timed out waiting for device %q to reboot", d.devName)
		}
	}
}

// GetLogs returns device log messages matching the provided criteria.
func (d *EdgeDevice) GetLogs(match LogMsgMatch) []LogMsg {
	devUUID := d.getDevUUID()
	collector := &logMsgCollector{match: match}
	ctx, cancel := context.WithTimeout(d.th.ctx, gatherLogsTimeout)
	err := d.th.adamClient.IterateDeviceLogs(
		ctx, devUUID, collector.toMatcher(), collector, false)
	cancel()
	if err != nil {
		d.th.t.Fatalf("Failed to retrieve logs for device %q: %v", d.devName, err)
	}
	return collector.msgs
}

// WatchLogs subscribes to device log entries and returns a buffered channel
// that receives each new matching LogMsg as it arrives.
// Call the returned stop function to unsubscribe and close the channel.
func (d *EdgeDevice) WatchLogs(match LogMsgMatch) (logs <-chan LogMsg, stop func()) {
	devUUID := d.getDevUUID()
	collector := &logMsgCollector{match: match}
	rawCh := make(chan *evelogs.LogEntry, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceLogs(
		devUUID, rawCh, collector.toMatcher())
	if err != nil {
		d.th.t.Fatalf("WatchLogs: failed to subscribe to device logs "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan LogMsg, watchChannelBufSize)
	go func() {
		defer close(ch)
		for entry := range rawCh {
			ch <- LogMsg{
				Severity:  entry.GetSeverity(),
				Source:    entry.GetSource(),
				Filename:  entry.GetFilename(),
				Message:   entry.GetContent(),
				Timestamp: entry.GetTimestamp().AsTime(),
			}
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetAppLogs returns application log messages matching the provided criteria.
func (d *EdgeDevice) GetAppLogs(appUUID uuid.UUID, match LogMsgMatch) []LogMsg {
	devUUID := d.getDevUUID()
	collector := &logMsgCollector{match: match}
	ctx, cancel := context.WithTimeout(d.th.ctx, gatherLogsTimeout)
	err := d.th.adamClient.IterateAppLogs(
		ctx, devUUID, appUUID, collector.toMatcher(), collector, false)
	cancel()
	if err != nil {
		d.th.t.Fatalf("Failed to retrieve app logs for device %q app %q: %v",
			d.devName, appUUID, err)
	}
	return collector.msgs
}

// GetAppFlowLogs returns flow records for the specified application
// matching the provided criteria.
func (d *EdgeDevice) GetAppFlowLogs(
	appUUID uuid.UUID, match FlowLogMatch) []*eveflowlog.FlowRecord {
	devUUID := d.getDevUUID()
	scopeMatch := flowScopeMatcher(appUUID, match.VirtualNetAdapter, match.NetworkInstance)

	var records []*eveflowlog.FlowRecord
	ctx, cancel := context.WithTimeout(d.th.ctx, gatherLogsTimeout)
	err := d.th.adamClient.IterateDeviceFlowLogs(ctx, devUUID, scopeMatch,
		flowMsgIterFn(func(msg *eveflowlog.FlowMessage) (bool, error) {
			for _, rec := range msg.GetFlows() {
				if flowRecordMatches(rec, match) {
					records = append(records, rec)
				}
			}
			return false, nil
		}), false)
	cancel()
	if err != nil {
		d.th.t.Fatalf("Failed to retrieve app flow logs for device %q app %q: %v",
			d.devName, appUUID, err)
	}
	return records
}

// flowScopeMatcher returns a match function for IterateDeviceFlowLogs /
// SubscribeToDeviceFlowLogs that selects FlowMessages belonging to the given
// application and, if non-empty/non-zero, the given VIF logical label and
// network instance.
func flowScopeMatcher(appUUID uuid.UUID, virtualNetAdapter string,
	networkInstance uuid.UUID) func(*eveflowlog.FlowMessage) bool {
	appUUIDStr := appUUID.String()
	niUUIDStr := networkInstance.String()
	return func(msg *eveflowlog.FlowMessage) bool {
		scope := msg.GetScope()
		if scope.GetUuid() != appUUIDStr {
			return false
		}
		if virtualNetAdapter != "" && scope.GetIntf() != virtualNetAdapter {
			return false
		}
		if networkInstance != NilUUID && scope.GetNetInstUUID() != niUUIDStr {
			return false
		}
		return true
	}
}

// flowRecordMatches reports whether rec satisfies match's flow-record-level
// criteria. Scope-level criteria (VirtualNetAdapter, NetworkInstance) are
// checked by the caller against the enclosing FlowMessage's Scope instead,
// since FlowRecord itself carries no scope information.
func flowRecordMatches(rec *eveflowlog.FlowRecord, match FlowLogMatch) bool {
	if rec.GetInbound() != match.Inbound {
		return false
	}
	if match.Flow != nil {
		flow := rec.GetFlow()
		if match.Flow.GetSrc() != "" && flow.GetSrc() != match.Flow.GetSrc() {
			return false
		}
		if match.Flow.GetSrcPort() != 0 && flow.GetSrcPort() != match.Flow.GetSrcPort() {
			return false
		}
		if match.Flow.GetDest() != "" && flow.GetDest() != match.Flow.GetDest() {
			return false
		}
		if match.Flow.GetDestPort() != 0 && flow.GetDestPort() != match.Flow.GetDestPort() {
			return false
		}
		if match.Flow.GetProtocol() != 0 && flow.GetProtocol() != match.Flow.GetProtocol() {
			return false
		}
	}
	ts := rec.GetStartTime().AsTime()
	if !match.NotBefore.IsZero() && ts.Before(match.NotBefore) {
		return false
	}
	if !match.NotAfter.IsZero() && ts.After(match.NotAfter) {
		return false
	}
	return true
}

// GetAppDNSLogs returns DNS request logs for the specified application
// matching the provided criteria.
func (d *EdgeDevice) GetAppDNSLogs(
	appUUID uuid.UUID, match DNSLogMatch) []*eveflowlog.DnsRequest {
	devUUID := d.getDevUUID()
	scopeMatch := flowScopeMatcher(appUUID, match.VirtualNetAdapter, match.NetworkInstance)

	var records []*eveflowlog.DnsRequest
	ctx, cancel := context.WithTimeout(d.th.ctx, gatherLogsTimeout)
	err := d.th.adamClient.IterateDeviceFlowLogs(ctx, devUUID, scopeMatch,
		flowMsgIterFn(func(msg *eveflowlog.FlowMessage) (bool, error) {
			for _, req := range msg.GetDnsReqs() {
				ts := req.GetRequestTime().AsTime()
				if !match.NotBefore.IsZero() && ts.Before(match.NotBefore) {
					continue
				}
				if !match.NotAfter.IsZero() && ts.After(match.NotAfter) {
					continue
				}
				records = append(records, req)
			}
			return false, nil
		}), false)
	cancel()
	if err != nil {
		d.th.t.Fatalf("Failed to retrieve app DNS logs for device %q app %q: %v",
			d.devName, appUUID, err)
	}
	return records
}

// waitUntilAppState waits until the app reaches one of targetStates,
// logging every state transition along the way.
//
// Safe to call even if the app already has matching state history from an
// earlier phase (e.g. it was already RUNNING before): it subscribes to live
// updates before checking the current snapshot, so a stale historical
// record can never be mistaken for a new transition.
//
// ctx controls the deadline; callers must derive it from d.th.ctx.
// Calls t.Fatalf on timeout or error.
func (d *EdgeDevice) waitUntilAppState(
	ctx context.Context, appUUID uuid.UUID, targetStates ...eveinfo.ZSwState) {
	devUUID := d.getDevUUID()
	appUUIDStr := appUUID.String()
	filter := func(msg *eveinfo.ZInfoMsg) bool {
		if msg.GetZtype() != eveinfo.ZInfoTypes_ZiApp {
			return false
		}
		ainfo := msg.GetAinfo()
		return ainfo != nil && ainfo.GetAppID() == appUUIDStr
	}

	d.th.log.Infof("Waiting for app %q on device %q to reach state(s) %v",
		appUUID, d.devName, targetStates)

	// Subscribe before taking the initial snapshot, so a transition landing
	// between the two calls can never be missed.
	ch := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID, filter, ch)
	if err != nil {
		d.th.t.Fatalf("Failed to subscribe to info messages for app %q on device %q: %v",
			appUUID, d.devName, err)
	}
	defer unsub()

	var lastState = eveinfo.ZSwState_INVALID
	logIfChanged := func(ainfo *eveinfo.ZInfoApp) {
		state := ainfo.GetState()
		if state != lastState {
			lastState = state
			d.th.log.Infof("App %q (%s) on device %q state changed to %s",
				appUUID, ainfo.GetAppName(), d.devName, state)
		}
	}

	// Snapshot: the app may already be in one of the target states right now.
	// Logged as the current state, not a "change", since nothing just
	// happened -- this is a fact we already knew, not a new event.
	if info := d.GetAppInfo(appUUID); info != nil {
		lastState = info.GetState()
		d.th.log.Infof("App %q (%s) on device %q currently in state %s",
			appUUID, info.GetAppName(), d.devName, lastState)
		if generics.ContainsItem(targetStates, lastState) {
			return
		}
	}

	for {
		select {
		case <-ctx.Done():
			d.th.t.Fatalf("Waiting for app %q on device %q to reach state(s) %v: %v",
				appUUID, d.devName, targetStates, ctx.Err())
		case msg, ok := <-ch:
			if !ok {
				d.th.t.Fatalf("Info subscription closed while waiting for app %q "+
					"on device %q to reach state(s) %v", appUUID, d.devName, targetStates)
			}
			logIfChanged(msg.GetAinfo())
			if generics.ContainsItem(targetStates, lastState) {
				return
			}
		}
	}
}

// WaitUntilAppIsRunning waits until the specified application reaches
// the running state or fails.
//
// Safe to call even if the app already has RUNNING history from an earlier
// phase: it subscribes to live updates before checking the current
// snapshot, so a stale historical record can never be mistaken for a new
// transition.
//
// timeoutExcludingDownload is the maximum time to wait excluding any
// period spent actively downloading (i.e. in DOWNLOAD_STARTED state with
// advancing progress). If a download stalls for downloadStalledTimeout the
// function fails immediately regardless of this timeout.
func (d *EdgeDevice) WaitUntilAppIsRunning(
	appUUID uuid.UUID, timeoutExcludingDownload time.Duration) {
	devUUID := d.getDevUUID()
	appUUIDStr := appUUID.String()
	d.appsBeingWaited.Store(appUUIDStr, struct{}{})
	defer d.appsBeingWaited.Delete(appUUIDStr)
	d.th.log.Infof("Waiting for app %q on device %q to reach RUNNING state...",
		appUUID, d.devName)

	var (
		lastState          = eveinfo.ZSwState_INVALID
		lastDownloadPct    uint32
		nonDownloadStart   = time.Now()
		nonDownloadElapsed time.Duration
		inDownload         bool
		appName            string
		volumeRefs         []string
		lastAppErrs        string // concatenated error descriptions for change detection
		// Keyed by volume UUID; accumulates the latest ZInfoVolume for each volume.
		volumes = make(map[string]*eveinfo.ZInfoVolume)
		// timer is nil during the initial snapshot replay (see below), so
		// iterCb's Reset calls are guarded and become no-ops until the live
		// phase arms it.
		timer *time.Timer
	)

	// Accept ZiApp messages for this app and all ZiVolume messages.
	// Volume messages are further filtered in the iterator once the app's
	// VolumeRefs are known.
	filter := func(msg *eveinfo.ZInfoMsg) bool {
		switch msg.GetZtype() {
		case eveinfo.ZInfoTypes_ZiApp:
			ainfo := msg.GetAinfo()
			return ainfo != nil && ainfo.GetAppID() == appUUIDStr
		case eveinfo.ZInfoTypes_ZiVolume:
			return true
		}
		return false
	}

	// iterCb processes a single info message, updating all the tracking state
	// above. live distinguishes the two contexts it's called from: false
	// during the initial snapshot replay (state is still established, but
	// nothing is logged -- these are historical facts, not new events, and
	// logging each one would misleadingly read as if they just happened);
	// true during the live phase (normal logging of genuinely new events).
	iterCb := func(msg *eveinfo.ZInfoMsg, live bool) (bool, error) {
		// Handle volume updates: store the latest state for each volume
		// and re-evaluate download progress if the app is currently downloading.
		if msg.GetZtype() == eveinfo.ZInfoTypes_ZiVolume {
			vinfo := msg.GetVinfo()
			if vinfo == nil {
				return false, nil
			}
			volumes[vinfo.GetUuid()] = vinfo
			// If the app is in DOWNLOAD_STARTED state, a volume update may
			// change the reported progress -- check and log.
			if inDownload {
				pct := appDownloadProgress(volumeRefs, volumes)
				if pct != lastDownloadPct {
					lastDownloadPct = pct
					if timer != nil {
						timer.Reset(downloadStalledTimeout)
					}
					if live {
						d.th.log.Infof("App %q (%s) on device %q state changed to %s (%d%%)",
							appUUID, appName, d.devName, lastState, pct)
					}
				}
			}
			return false, nil
		}

		ainfo := msg.GetAinfo()
		state := ainfo.GetState()
		appName = ainfo.GetAppName()

		// Update volume refs from the latest app info.
		volumeRefs = ainfo.GetVolumeRefs()

		// Maintain non-download elapsed time and update the timer when
		// transitioning between download and non-download phases.
		nowInDownload := state == eveinfo.ZSwState_DOWNLOAD_STARTED
		if inDownload && !nowInDownload {
			// Leaving download: resume non-download clock and set timer to
			// the remaining non-download budget. Only meaningful once the
			// live timer is armed -- during the initial snapshot replay,
			// elapsed wall-clock time is negligible and this check is skipped.
			nonDownloadStart = time.Now()
			if timer != nil {
				remaining := timeoutExcludingDownload - nonDownloadElapsed
				if remaining <= 0 {
					return true, fmt.Errorf(
						"timed out after %s (excluding download) waiting for app %q (%s) "+
							"on device %q to reach RUNNING state (last state: %s)",
						timeoutExcludingDownload, appUUID, appName, d.devName, state)
				}
				timer.Reset(remaining)
			}
		} else if !inDownload && nowInDownload {
			// Entering download: freeze non-download clock and arm stall timer.
			nonDownloadElapsed += time.Since(nonDownloadStart)
			if timer != nil {
				timer.Reset(downloadStalledTimeout)
			}
		}
		inDownload = nowInDownload

		// Log every state change and every download-progress change.
		if state != lastState {
			lastState = state
			if state == eveinfo.ZSwState_DOWNLOAD_STARTED {
				pct := appDownloadProgress(volumeRefs, volumes)
				lastDownloadPct = pct
				if live {
					d.th.log.Infof("App %q (%s) on device %q state changed to %s (%d%%)",
						appUUID, appName, d.devName, state, pct)
				}
			} else if live {
				d.th.log.Infof("App %q (%s) on device %q state changed to %s",
					appUUID, appName, d.devName, state)
			}
		} else if state == eveinfo.ZSwState_DOWNLOAD_STARTED {
			pct := appDownloadProgress(volumeRefs, volumes)
			if pct != lastDownloadPct {
				lastDownloadPct = pct
				if timer != nil {
					timer.Reset(downloadStalledTimeout)
				}
				if live {
					d.th.log.Infof("App %q (%s) on device %q state changed to %s (%d%%)",
						appUUID, appName, d.devName, state, pct)
				}
			}
		}

		// Log changes in app errors.
		var errDescs []string
		for _, e := range ainfo.GetAppErr() {
			if desc := e.GetDescription(); desc != "" {
				errDescs = append(errDescs, desc)
			}
		}
		currentAppErrs := strings.Join(errDescs, "; ")
		if currentAppErrs != lastAppErrs {
			lastAppErrs = currentAppErrs
			if live {
				if currentAppErrs != "" {
					d.th.log.Warnf("App %q (%s) on device %q errors: %s",
						appUUID, appName, d.devName, currentAppErrs)
				} else {
					d.th.log.Infof("App %q (%s) on device %q errors cleared",
						appUUID, appName, d.devName)
				}
			}
		}

		// Fail immediately on unrecoverable error.
		if state == eveinfo.ZSwState_ERROR {
			if currentAppErrs != "" {
				return true, fmt.Errorf(
					"app %q (%s) on device %q entered ERROR state: %s",
					appUUID, appName, d.devName, currentAppErrs)
			}
			return true, fmt.Errorf(
				"app %q (%s) on device %q entered ERROR state",
				appUUID, appName, d.devName)
		}

		// Success.
		if state == eveinfo.ZSwState_RUNNING {
			if live {
				d.th.log.Infof("App %q (%s) on device %q is RUNNING",
					appUUID, appName, d.devName)
			}
			return true, nil
		}

		return false, nil
	}

	// Subscribe before taking the initial snapshot, so a transition landing
	// between the two calls can never be missed.
	ch := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID, filter, ch)
	if err != nil {
		d.th.t.Fatalf("Failed to subscribe to info messages for app %q on device %q: %v",
			appUUID, d.devName, err)
	}
	defer unsub()

	// Snapshot: replay every already-known message (app and volume) through
	// iterCb with no timer armed (its Reset calls are then no-ops), keeping
	// only the LAST app-state evaluation -- i.e. the app's current state,
	// not the first historical occurrence of any target condition.
	var (
		snapshotDone bool
		snapshotErr  error
	)
	d.iterateInfoMsgs(devUUID, filter, func(msg *eveinfo.ZInfoMsg) {
		done, cbErr := iterCb(msg, false)
		if msg.GetZtype() == eveinfo.ZInfoTypes_ZiApp {
			snapshotDone, snapshotErr = done, cbErr
		}
	})
	if snapshotDone {
		if snapshotErr != nil {
			d.th.t.Fatalf("%v", snapshotErr)
		}
		d.th.log.Infof("App %q (%s) on device %q is already RUNNING",
			appUUID, appName, d.devName)
		return
	}
	d.th.log.Infof("App %q (%s) on device %q currently in state %s; "+
		"waiting for it to reach RUNNING", appUUID, appName, d.devName, lastState)

	// Live phase: arm the real timer -- matching the app's current phase,
	// established during the snapshot above -- and wait for a genuinely
	// new transition.
	nonDownloadStart = time.Now()
	initialTimeout := timeoutExcludingDownload
	if inDownload {
		initialTimeout = downloadStalledTimeout
	}
	timer = time.NewTimer(initialTimeout)
	defer timer.Stop()

	// ctx is canceled either by the timer above (timeout) or by d.th.ctx (test end).
	ctx, cancel := context.WithCancel(d.th.ctx)
	defer cancel()
	go func() {
		select {
		case <-timer.C:
			cancel()
		case <-ctx.Done():
		}
	}()

	for {
		select {
		case <-ctx.Done():
			// If the test framework context was canceled, propagate that.
			if d.th.ctx.Err() != nil {
				d.th.t.Fatalf("Waiting for app %q (%s) on device %q to reach "+
					"RUNNING state: %v", appUUID, appName, d.devName, d.th.ctx.Err())
			}

			// Otherwise our own timer fired -- determine which timeout occurred.
			if inDownload {
				d.th.t.Fatalf(
					"app %q (%s) on device %q download stalled at %d%% for more than %s",
					appUUID, appName, d.devName, lastDownloadPct, downloadStalledTimeout)
			}
			nonDownloadTotal := nonDownloadElapsed + time.Since(nonDownloadStart)
			d.th.t.Fatalf(
				"timed out after %s (excluding download) waiting for app %q (%s) "+
					"on device %q to reach RUNNING state (last state: %s)",
				nonDownloadTotal, appUUID, appName, d.devName, lastState)
		case msg, ok := <-ch:
			if !ok {
				d.th.t.Fatalf("Info subscription closed while waiting for app %q "+
					"(%s) on device %q to reach RUNNING state", appUUID, appName, d.devName)
			}
			done, cbErr := iterCb(msg, true)
			if !done {
				continue
			}
			if cbErr != nil {
				d.th.t.Fatalf("%v", cbErr)
			}
			return
		}
	}
}

// RebootApplication requests a reboot of the specified application instance.
func (d *EdgeDevice) RebootApplication(appUUID uuid.UUID, waitUntilRebooted bool,
	timeout time.Duration) {
	config := d.getConfig(true)
	appUUIDStr := appUUID.String()

	// Locate the application in the config and increment the restart counter.
	found := false
	for _, app := range config.GetApps() {
		if app.GetUuidandversion().GetUuid() == appUUIDStr {
			restart := app.GetRestart()
			if restart == nil {
				app.Restart = &eveconfig.InstanceOpsCmd{Counter: 1}
			} else {
				app.Restart = &eveconfig.InstanceOpsCmd{Counter: restart.GetCounter() + 1}
			}
			found = true
			break
		}
	}
	if !found {
		d.th.t.Fatalf("App %q not found in device %q config", appUUID, d.devName)
	}
	d.ApplyConfig(config, false, false)
	if waitUntilRebooted {
		ctx, cancel := context.WithTimeout(d.th.ctx, timeout)
		defer cancel()
		d.waitUntilAppState(ctx, appUUID,
			eveinfo.ZSwState_RESTARTING, eveinfo.ZSwState_HALTING)
		d.waitUntilAppState(ctx, appUUID, eveinfo.ZSwState_RUNNING)
	}
}

// PurgeApplication purges the specified application instance and its state.
func (d *EdgeDevice) PurgeApplication(appUUID uuid.UUID, waitUntilPurged bool,
	timeout time.Duration) {
	config := d.getConfig(true)
	appUUIDStr := appUUID.String()

	// Locate the application in the config and increment the purge counter.
	found := false
	for _, app := range config.GetApps() {
		if app.GetUuidandversion().GetUuid() == appUUIDStr {
			purge := app.GetPurge()
			if purge == nil {
				app.Purge = &eveconfig.InstanceOpsCmd{Counter: 1}
			} else {
				app.Purge = &eveconfig.InstanceOpsCmd{Counter: purge.GetCounter() + 1}
			}
			for _, volRef := range app.GetVolumeRefList() {
				volRef.GenerationCount++
				for _, vol := range config.GetVolumes() {
					if vol.GetUuid() == volRef.GetUuid() {
						vol.GenerationCount++
						break
					}
				}
			}
			found = true
			break
		}
	}
	if !found {
		d.th.t.Fatalf("App %q not found in device %q config", appUUID, d.devName)
	}
	d.ApplyConfig(config, false, false)
	if waitUntilPurged {
		ctx, cancel := context.WithTimeout(d.th.ctx, timeout)
		defer cancel()
		d.waitUntilAppState(ctx, appUUID,
			eveinfo.ZSwState_PURGING, eveinfo.ZSwState_HALTING)
		d.waitUntilAppState(ctx, appUUID, eveinfo.ZSwState_RUNNING)
	}
}

// DialViaSSH opens a TCP connection to address, tunneled through an SSH
// connection to this device (an SSH direct-tcpip channel), as if address is
// dialed from the device itself. Useful for reaching services that only
// listen on the device's own loopback interface, e.g. the Kubevirt VNC proxy
// gated by ApplicationInstanceConfig.RemoteConsole.
func (d *EdgeDevice) DialViaSSH(network, address string) (net.Conn, error) {
	return d.th.dialViaSSH(d.th.ctx, d.devName, network, address)
}

// ActivateApplication activates the specified application instance.
func (d *EdgeDevice) ActivateApplication(appUUID uuid.UUID, waitUntilActivated bool,
	timeout time.Duration) {
	config := d.getConfig(true)
	appUUIDStr := appUUID.String()

	// Locate the application in the config and mark it as activated.
	found := false
	for _, app := range config.GetApps() {
		if app.GetUuidandversion().GetUuid() == appUUIDStr {
			app.Activate = true
			found = true
			break
		}
	}
	if !found {
		d.th.t.Fatalf("App %q not found in device %q config", appUUID, d.devName)
	}

	d.ApplyConfig(config, false, false)
	if waitUntilActivated {
		d.WaitUntilAppIsRunning(appUUID, timeout)
	}
}

// DeactivateApplication deactivates the specified application instance.
func (d *EdgeDevice) DeactivateApplication(appUUID uuid.UUID, waitUntilDeactivated bool,
	timeout time.Duration) {
	config := d.getConfig(true)
	appUUIDStr := appUUID.String()

	// Locate the application in the config and mark it as deactivated.
	found := false
	for _, app := range config.GetApps() {
		if app.GetUuidandversion().GetUuid() == appUUIDStr {
			app.Activate = false
			found = true
			break
		}
	}
	if !found {
		d.th.t.Fatalf("App %q not found in device %q config", appUUID, d.devName)
	}

	d.ApplyConfig(config, false, false)
	if waitUntilDeactivated {
		ctx, cancel := context.WithTimeout(d.th.ctx, timeout)
		defer cancel()
		d.waitUntilAppState(ctx, appUUID, eveinfo.ZSwState_HALTED)
	}
}

// RunShellScript executes the provided shell script on the device over SSH
// and returns its standard output and standard error as strings.
//
// If timeout is non-zero, execution is bounded by the given duration and
// will be canceled if the timeout expires. If timeout is zero, no explicit
// deadline is applied.
//
// If stdoutWatchdogTimeout is non-zero, the script will be terminated if
// it produces no output on stdout for longer than the specified duration.
// This acts as a "watchdog" to detect stalled scripts.
func (d *EdgeDevice) RunShellScript(script string, timeout time.Duration,
	stdoutWatchdogTimeout time.Duration) (stdout, stderr string, err error) {
	ctx := d.th.ctx
	if timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(d.th.ctx, timeout)
		defer cancel()
	}
	var stdoutBuf, stderrBuf bytes.Buffer
	err = d.th.runScriptOnEVEOverSSH(
		ctx, d.devName, script, &stdoutBuf, &stderrBuf, stdoutWatchdogTimeout)
	if err != nil {
		err = fmt.Errorf(
			"failed to execute script over SSH for EVE device %s: %w (stderr: %s)",
			d.devName, err, stderrBuf.String())
	}
	return stdoutBuf.String(), stderrBuf.String(), err
}

// RunShellScriptInsideApp executes a shell script inside an application
// instance over SSH and returns its standard output and standard error.
//
// The method discovers SSH endpoints for the application by inspecting:
//  1. Port-forwarding ACL rules (port 22 mapped through a local network
//     instance) -- the device IP on the uplink adapter plus the external port.
//  2. Switch network instance interfaces -- the app IP at port 22 (directly
//     bridged, reachable on the SDN network).
//  3. RoutesTowardsEve entries in the SDN network model -- if any SDN network's
//     router has a route towards the EVE device that covers a VIF's IP, that
//     IP:22 is tried. This makes air-gap NI apps reachable once the app acting
//     as their gateway has IP forwarding enabled.
//
// auth specifies how to authenticate with the application's SSH server
// (username/password or client certificate). timeout and stdoutWatchdogTimeout
// behave the same as in RunShellScript.
func (d *EdgeDevice) RunShellScriptInsideApp(appUUID uuid.UUID, auth AuthMethod,
	script string, timeout time.Duration,
	stdoutWatchdogTimeout time.Duration) (stdout, stderr string, err error) {

	ctx := d.th.ctx
	if timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(d.th.ctx, timeout)
		defer cancel()
	}

	appUUIDStr := appUUID.String()
	config := d.getConfig(false)

	// Find the app in the device config.
	var appConfig *eveconfig.AppInstanceConfig
	for _, app := range config.GetApps() {
		if app.GetUuidandversion().GetUuid() == appUUIDStr {
			appConfig = app
			break
		}
	}
	if appConfig == nil {
		d.th.t.Fatalf("app %q not found in device %q config", appUUID, d.devName)
	}

	var addrs []string

	// Collect SSH endpoints for the app:
	// 1. Port-forwarded endpoints: device-IP:mappedPort where ACLs
	//    map external port to app's port 22.
	// 2. Switch (bridged) endpoints: app-IP:22 for interfaces
	//    connected to switch network instances.
	appInfo := d.GetAppInfo(appUUID)
	for _, iface := range appConfig.GetInterfaces() {
		networkID := iface.GetNetworkId()

		// Find the network instance config for this interface.
		var niConfig *eveconfig.NetworkInstanceConfig
		for _, ni := range config.GetNetworkInstances() {
			if ni.GetUuidandversion().GetUuid() == networkID {
				niConfig = ni
				break
			}
		}
		if niConfig == nil {
			continue
		}

		// Check ACLs for port-map rules that forward to app port 22.
		for _, acl := range iface.GetAcls() {
			var devicePort, adapterLabel string
			var mapsToApp22 bool
			for _, action := range acl.GetActions() {
				if action.GetPortmap() && action.GetAppPort() == 22 {
					mapsToApp22 = true
					break
				}
			}
			if !mapsToApp22 {
				continue
			}
			// Find the external port from "lport" and optional adapter restriction.
			for _, match := range acl.GetMatches() {
				switch match.GetType() {
				case "lport":
					devicePort = match.GetValue()
				case "adapter":
					adapterLabel = match.GetValue()
				}
			}
			if devicePort == "" {
				continue
			}

			// Port-forwarding applies to adapters that match the NI port label
			// AND, if an "adapter" ACE match is defined, also carry that label.
			adapters := getAdaptersByLabel(config, niConfig.GetPort().GetName())
			if adapterLabel != "" {
				aclAdapters := getAdaptersByLabel(config, adapterLabel)
				var filtered []string
				for _, name := range adapters {
					if generics.ContainsItem(aclAdapters, name) {
						filtered = append(filtered, name)
					}
				}
				adapters = filtered
			}
			for _, name := range adapters {
				for _, ip := range d.GetDeviceIPAddress(name) {
					addrs = append(addrs, net.JoinHostPort(ip.String(), devicePort))
				}
			}
		}

		// For switch network instances, the app is directly reachable
		// on the IP assigned to this interface.
		if niConfig.GetInstType() == eveconfig.ZNetworkInstType_ZnetInstSwitch {
			for _, netInfo := range appInfo.GetNetwork() {
				if netInfo.GetDevName() != iface.GetName() {
					continue
				}
				for _, ipStr := range netInfo.GetIPAddrs() {
					if net.ParseIP(ipStr) != nil {
						addrs = append(addrs, net.JoinHostPort(ipStr, "22"))
					}
				}
			}
		}
	}

	// Check RoutesTowardsEve in the SDN network model: any VIF IP that falls
	// within a subnet listed in RoutesTowardsEve is reachable from the evetest
	// host via the SDN router (which forwards those subnets towards app-gw).
	d.th.netModelM.Lock()
	for _, network := range d.th.netModel.GetNetworks() {
		for _, route := range network.GetRouter().GetRoutesTowardsEve() {
			_, dstNet, err2 := net.ParseCIDR(route.GetDstNetwork())
			if err2 != nil {
				continue
			}
			for _, netInfo := range appInfo.GetNetwork() {
				for _, ipStr := range netInfo.GetIPAddrs() {
					ip := net.ParseIP(ipStr)
					if ip != nil && dstNet.Contains(ip) {
						addrs = append(addrs, net.JoinHostPort(ipStr, "22"))
					}
				}
			}
		}
	}
	d.th.netModelM.Unlock()

	if len(addrs) == 0 {
		return "", "", fmt.Errorf(
			"no SSH endpoints found for app %q on device %q", appUUID, d.devName)
	}

	addr, err := d.th.probeReachableAddr(ctx, addrs)
	if err != nil {
		return "", "", fmt.Errorf(
			"unable to reach app %q SSH on device %q: %w", appUUID, d.devName, err)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	err = d.th.runScriptOverSSH(ctx, addr, auth, script,
		&stdoutBuf, &stderrBuf, stdoutWatchdogTimeout)
	if err != nil {
		err = fmt.Errorf(
			"failed to execute script over SSH for app %s: %w (stderr: %s)",
			appUUID, err, stderrBuf.String())
	}
	return stdoutBuf.String(), stderrBuf.String(), err
}

// getAdapterNamesByLabel returns the logical labels of adapters whose Name
// equals the given label or whose SharedLabels contain it.
func getAdaptersByLabel(config *EdgeDeviceConfig, label string) []string {
	var names []string
	for _, sa := range config.GetSystemAdapterList() {
		if sa.GetName() == label ||
			generics.ContainsItem(sa.GetSharedLabels(), label) ||
			label == "all" ||
			(label == "uplink" && sa.Uplink) ||
			(label == "freeuplink" && sa.Uplink && sa.Cost == 0) {
			names = append(names, sa.GetName())
		}
	}
	return names
}

// FileExists checks whether a file exists on the device.
func (d *EdgeDevice) FileExists(fileName string) bool {
	// "; true" forces the overall exit status to 0 regardless of whether
	// the file exists, so a missing file (test -f exits nonzero) can't be
	// conflated with a genuine SSH/transport failure -- err is asserted nil
	// for the latter, and only the "EXISTS" marker in stdout answers the
	// actual question.
	stdout, _, err := d.RunShellScript(
		"test -f "+shellEscape(fileName)+" && echo EXISTS; true",
		quickSSHCommandTimeout, 0)
	if err != nil {
		d.th.t.Fatalf("FileExists: SSH command failed: %v", err)
	}
	return strings.Contains(stdout, "EXISTS")
}

// ReadFile reads the contents of a file from the device.
func (d *EdgeDevice) ReadFile(fileName string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(d.th.ctx, fileTransferTimeout)
	defer cancel()

	tmpFile, err := os.CreateTemp("", "eve-file-*")
	if err != nil {
		return nil, fmt.Errorf("ReadFile: failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	err = d.th.scpFromEVE(ctx, d.devName, fileName, tmpPath, false)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: failed to copy %q from device %q: %w",
			fileName, d.devName, err)
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: failed to read temp file: %w", err)
	}
	return data, nil
}

// WriteFile writes content to a file on the device.
func (d *EdgeDevice) WriteFile(fileName string, content []byte) {
	ctx, cancel := context.WithTimeout(d.th.ctx, fileTransferTimeout)
	defer cancel()

	tmpFile, err := os.CreateTemp("", "eve-file-*")
	if err != nil {
		d.th.t.Fatalf("WriteFile: failed to create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(content); err != nil {
		tmpFile.Close()
		d.th.t.Fatalf("WriteFile: failed to write temp file: %v", err)
	}
	tmpFile.Close()

	err = d.th.scpToEVE(ctx, d.devName, tmpPath, fileName, false)
	if err != nil {
		d.th.t.Fatalf("WriteFile: failed to copy %q to device %q: %v",
			fileName, d.devName, err)
	}
}

// DeleteFile removes a file from the device.
func (d *EdgeDevice) DeleteFile(fileName string) {
	_, _, err := d.RunShellScript(
		"rm -f "+shellEscape(fileName), quickSSHCommandTimeout, 0)
	if err != nil {
		d.th.t.Fatalf("DeleteFile: SSH command failed: %v", err)
	}
}

// GetDeviceInfo returns the last recorded device information,
// or nil if no info message has been received yet.
func (d *EdgeDevice) GetDeviceInfo() *eveinfo.ZInfoDevice {
	devUUID := d.getDevUUID()
	var result *eveinfo.ZInfoDevice
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiDevice
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetDinfo()
		},
	)
	return result
}

// WatchDeviceInfo subscribes to device info updates and returns a buffered
// channel that receives each new ZInfoDevice as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchDeviceInfo() (updates <-chan *eveinfo.ZInfoDevice, stop func()) {
	devUUID := d.getDevUUID()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiDevice
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchDeviceInfo: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoDevice, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			ch <- msg.GetDinfo()
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// trackWatcherUnsub registers an unsubscribe callback so it can be automatically
// called during Close() if the test forgets to stop the watcher.
// Returns a wrapped stop function that unsubscribes and removes the tracking entry.
func (d *EdgeDevice) trackWatcherUnsub(unsub func()) func() {
	d.th.devicesM.Lock()
	defer d.th.devicesM.Unlock()
	devState := d.th.devices[d.devName]
	if devState.watcherUnsubs == nil {
		devState.watcherUnsubs = make(map[*func()]func())
	}
	key := &unsub
	devState.watcherUnsubs[key] = unsub
	return func() {
		unsub()
		d.th.devicesM.Lock()
		defer d.th.devicesM.Unlock()
		delete(devState.watcherUnsubs, key)
	}
}

// GetAppInfo returns the last recorded runtime information for the specified
// application, or nil if no info message for that app has been received yet.
func (d *EdgeDevice) GetAppInfo(appUUID uuid.UUID) *eveinfo.ZInfoApp {
	devUUID := d.getDevUUID()
	appUUIDStr := appUUID.String()
	var result *eveinfo.ZInfoApp
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			if msg.GetZtype() != eveinfo.ZInfoTypes_ZiApp {
				return false
			}
			return msg.GetAinfo().GetAppID() == appUUIDStr
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetAinfo()
		},
	)
	return result
}

// WatchAppInfo subscribes to info updates for the specified application and
// returns a buffered channel that receives each new ZInfoApp as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchAppInfo(
	appUUID uuid.UUID) (updates <-chan *eveinfo.ZInfoApp, stop func()) {
	devUUID := d.getDevUUID()
	appUUIDStr := appUUID.String()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiApp &&
				msg.GetAinfo().GetAppID() == appUUIDStr
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchAppInfo: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoApp, watchChannelBufSize)
	go func() {
		defer close(ch)
		var lastState eveinfo.ZSwState
		for msg := range rawCh {
			ainfo := msg.GetAinfo()
			// Skip logging if WaitUntilAppIsRunning is active for this app,
			// as it already logs state changes and errors.
			_, waiting := d.appsBeingWaited.Load(appUUIDStr)
			if !waiting {
				if ainfo.State != lastState {
					d.th.log.Infof("App %q (%s) on device %q state changed: %s -> %s",
						appUUID, ainfo.AppName, d.devName, lastState, ainfo.State)
				}
				for _, appErr := range ainfo.AppErr {
					d.th.log.Warnf("App %q (%s) on device %q error: %s",
						appUUID, ainfo.AppName, d.devName, appErr.GetDescription())
				}
			}
			lastState = ainfo.State
			ch <- ainfo
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetNetworkInstanceInfo returns the last recorded information about the
// specified network instance, or nil if no info message for it has been
// received yet.
func (d *EdgeDevice) GetNetworkInstanceInfo(niUUID uuid.UUID) *eveinfo.ZInfoNetworkInstance {
	devUUID := d.getDevUUID()
	niUUIDStr := niUUID.String()
	var result *eveinfo.ZInfoNetworkInstance
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			if msg.GetZtype() != eveinfo.ZInfoTypes_ZiNetworkInstance {
				return false
			}
			return msg.GetNiinfo().GetNetworkID() == niUUIDStr
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetNiinfo()
		},
	)
	return result
}

// WatchNetworkInstanceInfo subscribes to info updates for the specified network
// instance and returns a buffered channel that receives each new
// ZInfoNetworkInstance as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchNetworkInstanceInfo(
	niUUID uuid.UUID) (updates <-chan *eveinfo.ZInfoNetworkInstance, stop func()) {
	devUUID := d.getDevUUID()
	niUUIDStr := niUUID.String()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiNetworkInstance &&
				msg.GetNiinfo().GetNetworkID() == niUUIDStr
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchNetworkInstanceInfo: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoNetworkInstance, watchChannelBufSize)
	go func() {
		defer close(ch)
		var lastState eveinfo.ZNetworkInstanceState
		for msg := range rawCh {
			niInfo := msg.GetNiinfo()
			if niInfo.State != lastState {
				d.th.log.Infof("Network instance %q (%s) on device %q state changed: %s -> %s",
					niUUID, niInfo.Displayname, d.devName,
					shortNIState(lastState), shortNIState(niInfo.State))
				lastState = niInfo.State
			}
			for _, niErr := range niInfo.NetworkErr {
				d.th.log.Warnf("Network instance %q (%s) on device %q error: %s",
					niUUID, niInfo.Displayname, d.devName, niErr)
			}
			ch <- niInfo
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

func shortNIState(s eveinfo.ZNetworkInstanceState) string {
	return strings.TrimPrefix(s.String(), "ZNETINST_STATE_")
}

// GetVolumeInfo returns the last recorded information about the specified
// storage volume, or nil if no info message for it has been received yet.
func (d *EdgeDevice) GetVolumeInfo(volumeUUID uuid.UUID) *eveinfo.ZInfoVolume {
	devUUID := d.getDevUUID()
	volUUIDStr := volumeUUID.String()
	var result *eveinfo.ZInfoVolume
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			if msg.GetZtype() != eveinfo.ZInfoTypes_ZiVolume {
				return false
			}
			return msg.GetVinfo().GetUuid() == volUUIDStr
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetVinfo()
		},
	)
	return result
}

// WatchVolumeInfo subscribes to info updates for the specified storage volume
// and returns a buffered channel that receives each new ZInfoVolume as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchVolumeInfo(volumeUUID uuid.UUID) (
	updates <-chan *eveinfo.ZInfoVolume, stop func()) {

	devUUID := d.getDevUUID()
	volUUIDStr := volumeUUID.String()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiVolume &&
				msg.GetVinfo().GetUuid() == volUUIDStr
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchVolumeInfo: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoVolume, watchChannelBufSize)
	go func() {
		defer close(ch)
		var lastState eveinfo.ZSwState
		for msg := range rawCh {
			vinfo := msg.GetVinfo()
			if vinfo.State != lastState {
				d.th.log.Infof("Volume %q (%s) on device %q state changed: %s -> %s",
					volumeUUID, vinfo.DisplayName, d.devName, lastState, vinfo.State)
				lastState = vinfo.State
			}
			if volErr := vinfo.GetVolumeErr(); volErr != nil && volErr.GetDescription() != "" {
				d.th.log.Warnf("Volume %q (%s) on device %q error: %s",
					volumeUUID, vinfo.DisplayName, d.devName, volErr.GetDescription())
			}
			ch <- vinfo
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetContentTreeInfo returns the last recorded information about the specified
// content tree, or nil if no info message for it has been received yet.
func (d *EdgeDevice) GetContentTreeInfo(ctUUID uuid.UUID) *eveinfo.ZInfoContentTree {
	devUUID := d.getDevUUID()
	ctUUIDStr := ctUUID.String()
	var result *eveinfo.ZInfoContentTree
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			if msg.GetZtype() != eveinfo.ZInfoTypes_ZiContentTree {
				return false
			}
			return msg.GetCinfo().GetUuid() == ctUUIDStr
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetCinfo()
		},
	)
	return result
}

// WatchContentTreeInfo subscribes to info updates for the specified content tree
// and returns a buffered channel that receives each new ZInfoContentTree as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchContentTreeInfo(
	ctUUID uuid.UUID) (updates <-chan *eveinfo.ZInfoContentTree, stop func()) {
	devUUID := d.getDevUUID()
	ctUUIDStr := ctUUID.String()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiContentTree &&
				msg.GetCinfo().GetUuid() == ctUUIDStr
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchContentTreeInfo: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoContentTree, watchChannelBufSize)
	go func() {
		defer close(ch)
		var lastState eveinfo.ZSwState
		for msg := range rawCh {
			cinfo := msg.GetCinfo()
			if cinfo.State != lastState {
				d.th.log.Infof("Content tree %q (%s) on device %q state changed: %s -> %s",
					ctUUID, cinfo.DisplayName, d.devName, lastState, cinfo.State)
				lastState = cinfo.State
			}
			if ctErr := cinfo.GetErr(); ctErr != nil && ctErr.GetDescription() != "" {
				d.th.log.Warnf("Content tree %q (%s) on device %q error: %s",
					ctUUID, cinfo.DisplayName, d.devName, ctErr.GetDescription())
			}
			ch <- cinfo
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetBlobInfo returns the last recorded information about stored blobs on the
// device, or nil if no blob info message has been received yet.
func (d *EdgeDevice) GetBlobInfo() *eveinfo.ZInfoBlobList {
	devUUID := d.getDevUUID()
	var result *eveinfo.ZInfoBlobList
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiBlobList
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetBinfo()
		},
	)
	return result
}

// WatchBlobInfo subscribes to blob info updates and returns a buffered channel
// that receives each new ZInfoBlobList as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchBlobInfo() (updates <-chan *eveinfo.ZInfoBlobList, stop func()) {
	devUUID := d.getDevUUID()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiBlobList
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchBlobInfo: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoBlobList, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			ch <- msg.GetBinfo()
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetAppMetadata returns the last recorded metadata associated with the
// specified application instance, or nil if none has been received yet.
func (d *EdgeDevice) GetAppMetadata(appUUID uuid.UUID) *eveinfo.ZInfoAppInstMetaData {
	devUUID := d.getDevUUID()
	appUUIDStr := appUUID.String()
	var result *eveinfo.ZInfoAppInstMetaData
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			if msg.GetZtype() != eveinfo.ZInfoTypes_ZiAppInstMetaData {
				return false
			}
			return msg.GetAmdinfo().GetUuid() == appUUIDStr
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetAmdinfo()
		},
	)
	return result
}

// WatchAppMetadata subscribes to metadata updates for the specified application
// instance and returns a buffered channel that receives each new
// ZInfoAppInstMetaData as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchAppMetadata(
	appUUID uuid.UUID) (updates <-chan *eveinfo.ZInfoAppInstMetaData, stop func()) {
	devUUID := d.getDevUUID()
	appUUIDStr := appUUID.String()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiAppInstMetaData &&
				msg.GetAmdinfo().GetUuid() == appUUIDStr
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchAppMetadata: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoAppInstMetaData, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			ch <- msg.GetAmdinfo()
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetHardwareInfo returns the last recorded hardware inventory information,
// or nil if no hardware info message has been received yet.
func (d *EdgeDevice) GetHardwareInfo() *eveinfo.ZInfoHardware {
	devUUID := d.getDevUUID()
	var result *eveinfo.ZInfoHardware
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiHardware
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetHwinfo()
		},
	)
	return result
}

// WatchHardwareInfo subscribes to hardware info updates and returns a buffered
// channel that receives each new ZInfoHardware as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchHardwareInfo() (
	updates <-chan *eveinfo.ZInfoHardware, stop func()) {
	devUUID := d.getDevUUID()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiHardware
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchHardwareInfo: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoHardware, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			ch <- msg.GetHwinfo()
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetLocationInfo returns the last recorded device location information,
// or nil if no location info message has been received yet.
func (d *EdgeDevice) GetLocationInfo() *eveinfo.ZInfoLocation {
	devUUID := d.getDevUUID()
	var result *eveinfo.ZInfoLocation
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiLocation
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetLocinfo()
		},
	)
	return result
}

// WatchLocationInfo subscribes to location info updates and returns a buffered
// channel that receives each new ZInfoLocation as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchLocationInfo() (
	updates <-chan *eveinfo.ZInfoLocation, stop func()) {
	devUUID := d.getDevUUID()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiLocation
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchLocationInfo: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoLocation, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			ch <- msg.GetLocinfo()
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetNTPSources returns the last recorded NTP sources configured on the device,
// or nil if no NTP sources info message has been received yet.
func (d *EdgeDevice) GetNTPSources() *eveinfo.ZInfoNTPSources {
	devUUID := d.getDevUUID()
	var result *eveinfo.ZInfoNTPSources
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiNTPSources
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetNtpSources()
		},
	)
	return result
}

// WatchNTPSources subscribes to NTP sources updates and returns a buffered
// channel that receives each new ZInfoNTPSources as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchNTPSources() (
	updates <-chan *eveinfo.ZInfoNTPSources, stop func()) {
	devUUID := d.getDevUUID()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiNTPSources
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchNTPSources: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoNTPSources, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			ch <- msg.GetNtpSources()
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetClusterInfo returns the last recorded information about the Kubernetes
// cluster, or nil if no such info message has been received yet.
func (d *EdgeDevice) GetClusterInfo() *eveinfo.ZInfoKubeCluster {
	devUUID := d.getDevUUID()
	var result *eveinfo.ZInfoKubeCluster
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiKubeCluster &&
				msg.GetClusterInfo() != nil
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetClusterInfo()
		},
	)
	return result
}

// WatchClusterInfo subscribes to Kubernetes cluster info updates and returns a
// buffered channel that receives each new ZInfoKubeCluster as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchClusterInfo() (
	updates <-chan *eveinfo.ZInfoKubeCluster, stop func()) {
	devUUID := d.getDevUUID()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiKubeCluster &&
				msg.GetClusterInfo() != nil
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchClusterInfo: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoKubeCluster, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			ch <- msg.GetClusterInfo()
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// WaitForClusterNodeIsReady waits until this device's own ZInfoKubeCluster
// report shows this device as a Ready node with healthy cluster storage.
//
// Only the elected leader node publishes cluster info, so this is only
// meaningful when called on a single-node cluster (where the sole device is
// necessarily the leader) or on a device already known to be the leader; for
// a multi-node cluster where the leader isn't known in advance, use
// EdgeCluster.WaitUntilNodesAreReady instead.
func (d *EdgeDevice) WaitForClusterNodeIsReady(timeout time.Duration) {
	d.th.log.Infof("Waiting for cluster node %q to become ready...", d.devName)

	// Subscribe before taking the initial snapshot, so a transition landing
	// between the two calls can never be missed.
	updates, stop := d.WatchClusterInfo()
	defer stop()

	if info := d.GetClusterInfo(); info != nil && clusterNodeReady(info, d.devName) {
		d.th.log.Infof("Cluster node %q is already ready", d.devName)
		return
	}

	ctx, cancel := context.WithTimeout(d.th.ctx, timeout)
	defer cancel()
	for {
		select {
		case info, ok := <-updates:
			if !ok {
				d.th.t.Fatalf("Cluster info subscription closed while waiting "+
					"for node %q to become ready", d.devName)
			}
			if clusterNodeReady(info, d.devName) {
				d.th.log.Infof("Cluster node %q is now ready", d.devName)
				return
			}
		case <-ctx.Done():
			d.th.t.Fatalf("Timed out waiting for cluster node %q to become ready",
				d.devName)
		}
	}
}

// GetClusterUpdateInfo returns the last recorded information regarding the Kubernetes
// cluster update, or nil if no such info message has been received yet.
func (d *EdgeDevice) GetClusterUpdateInfo() *eveinfo.ZInfoKubeClusterUpdateStatus {
	devUUID := d.getDevUUID()
	var result *eveinfo.ZInfoKubeClusterUpdateStatus
	d.iterateInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiKubeClusterUpdateStatus &&
				msg.GetClusterUpdateInfo() != nil
		},
		func(msg *eveinfo.ZInfoMsg) {
			result = msg.GetClusterUpdateInfo()
		},
	)
	return result
}

// WatchClusterUpdateInfo subscribes to Kubernetes cluster-update info messages
// and returns a buffered channel that receives each new ZInfoKubeClusterUpdateStatus
// as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchClusterUpdateInfo() (
	updates <-chan *eveinfo.ZInfoKubeClusterUpdateStatus, stop func()) {
	devUUID := d.getDevUUID()
	rawCh := make(chan *eveinfo.ZInfoMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceInfoMsgs(devUUID,
		func(msg *eveinfo.ZInfoMsg) bool {
			return msg.GetZtype() == eveinfo.ZInfoTypes_ZiKubeClusterUpdateStatus &&
				msg.GetClusterUpdateInfo() != nil
		},
		rawCh,
	)
	if err != nil {
		d.th.t.Fatalf("WatchClusterUpdateInfo: failed to subscribe to info messages "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *eveinfo.ZInfoKubeClusterUpdateStatus, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			ch <- msg.GetClusterUpdateInfo()
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetDeviceMetrics returns the last recorded device-level metrics,
// or nil if no metrics message has been received yet.
func (d *EdgeDevice) GetDeviceMetrics() *evemetrics.DeviceMetric {
	devUUID := d.getDevUUID()
	var result *evemetrics.DeviceMetric
	d.iterateMetricMsgs(devUUID,
		func(msg *evemetrics.ZMetricMsg) {
			if msg.GetDm() != nil {
				result = msg.GetDm()
			}
		},
	)
	return result
}

// WatchDeviceMetrics subscribes to device-level metrics updates and returns a
// buffered channel that receives each new DeviceMetric as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchDeviceMetrics() (
	updates <-chan *evemetrics.DeviceMetric, stop func()) {
	devUUID := d.getDevUUID()
	rawCh := make(chan *evemetrics.ZMetricMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceMetrics(devUUID, rawCh)
	if err != nil {
		d.th.t.Fatalf("WatchDeviceMetrics: failed to subscribe to metrics "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *evemetrics.DeviceMetric, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			if dm := msg.GetDm(); dm != nil {
				ch <- dm
			}
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetAppMetrics returns the last recorded metrics for the specified application,
// or nil if no metrics message for that app has been received yet.
func (d *EdgeDevice) GetAppMetrics(appUUID uuid.UUID) *evemetrics.AppMetric {
	devUUID := d.getDevUUID()
	appUUIDStr := appUUID.String()
	var result *evemetrics.AppMetric
	d.iterateMetricMsgs(devUUID,
		func(msg *evemetrics.ZMetricMsg) {
			for _, am := range msg.GetAm() {
				if am.GetAppID() == appUUIDStr {
					result = am
				}
			}
		},
	)
	return result
}

// WatchAppMetrics subscribes to metrics updates for the specified application
// and returns a buffered channel that receives each new AppMetric as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchAppMetrics(
	appUUID uuid.UUID) (updates <-chan *evemetrics.AppMetric, stop func()) {
	devUUID := d.getDevUUID()
	appUUIDStr := appUUID.String()
	rawCh := make(chan *evemetrics.ZMetricMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceMetrics(devUUID, rawCh)
	if err != nil {
		d.th.t.Fatalf("WatchAppMetrics: failed to subscribe to metrics "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *evemetrics.AppMetric, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			for _, am := range msg.GetAm() {
				if am.GetAppID() == appUUIDStr {
					ch <- am
				}
			}
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetNetworkInstanceMetrics returns the last recorded metrics for the specified
// network instance, or nil if no metrics message for it has been received yet.
func (d *EdgeDevice) GetNetworkInstanceMetrics(
	niUUID uuid.UUID) *evemetrics.ZMetricNetworkInstance {
	devUUID := d.getDevUUID()
	niUUIDStr := niUUID.String()
	var result *evemetrics.ZMetricNetworkInstance
	d.iterateMetricMsgs(devUUID,
		func(msg *evemetrics.ZMetricMsg) {
			for _, nm := range msg.GetNm() {
				if nm.GetNetworkID() == niUUIDStr {
					result = nm
				}
			}
		},
	)
	return result
}

// WatchNetworkInstanceMetrics subscribes to metrics updates for the specified
// network instance and returns a buffered channel that receives each new
// ZMetricNetworkInstance as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchNetworkInstanceMetrics(
	niUUID uuid.UUID) (updates <-chan *evemetrics.ZMetricNetworkInstance, stop func()) {
	devUUID := d.getDevUUID()
	niUUIDStr := niUUID.String()
	rawCh := make(chan *evemetrics.ZMetricMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceMetrics(devUUID, rawCh)
	if err != nil {
		d.th.t.Fatalf("WatchNetworkInstanceMetrics: failed to subscribe to metrics "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *evemetrics.ZMetricNetworkInstance, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			for _, nm := range msg.GetNm() {
				if nm.GetNetworkID() == niUUIDStr {
					ch <- nm
				}
			}
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetVolumeMetrics returns the last recorded metrics for the specified storage
// volume, or nil if no metrics message for it has been received yet.
func (d *EdgeDevice) GetVolumeMetrics(volumeUUID uuid.UUID) *evemetrics.ZMetricVolume {
	devUUID := d.getDevUUID()
	volUUIDStr := volumeUUID.String()
	var result *evemetrics.ZMetricVolume
	d.iterateMetricMsgs(devUUID,
		func(msg *evemetrics.ZMetricMsg) {
			for _, vm := range msg.GetVm() {
				if vm.GetUuid() == volUUIDStr {
					result = vm
				}
			}
		},
	)
	return result
}

// WatchVolumeMetrics subscribes to metrics updates for the specified storage
// volume and returns a buffered channel that receives each new ZMetricVolume
// as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchVolumeMetrics(
	volumeUUID uuid.UUID) (updates <-chan *evemetrics.ZMetricVolume, stop func()) {
	devUUID := d.getDevUUID()
	volUUIDStr := volumeUUID.String()
	rawCh := make(chan *evemetrics.ZMetricMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceMetrics(devUUID, rawCh)
	if err != nil {
		d.th.t.Fatalf("WatchVolumeMetrics: failed to subscribe to metrics "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *evemetrics.ZMetricVolume, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			for _, vm := range msg.GetVm() {
				if vm.GetUuid() == volUUIDStr {
					ch <- vm
				}
			}
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// GetClusterMetrics returns the last recorded metrics for the Kubernetes cluster,
// or nil if no cluster metrics message has been received yet.
func (d *EdgeDevice) GetClusterMetrics() *evemetrics.KubeClusterMetrics {
	devUUID := d.getDevUUID()
	var result *evemetrics.KubeClusterMetrics
	d.iterateMetricMsgs(devUUID,
		func(msg *evemetrics.ZMetricMsg) {
			if msg.GetCm() != nil {
				result = msg.GetCm()
			}
		},
	)
	return result
}

// WatchClusterMetrics subscribes to Kubernetes cluster metrics updates and
// returns a buffered channel that receives each new KubeClusterMetrics as it arrives.
// Call the returned close function to stop watching and close the channel.
func (d *EdgeDevice) WatchClusterMetrics() (
	updates <-chan *evemetrics.KubeClusterMetrics, stop func()) {
	devUUID := d.getDevUUID()
	rawCh := make(chan *evemetrics.ZMetricMsg, watchChannelBufSize)
	unsub, err := d.th.adamClient.SubscribeToDeviceMetrics(devUUID, rawCh)
	if err != nil {
		d.th.t.Fatalf("WatchClusterMetrics: failed to subscribe to metrics "+
			"for device %q: %v", d.devName, err)
	}
	ch := make(chan *evemetrics.KubeClusterMetrics, watchChannelBufSize)
	go func() {
		defer close(ch)
		for msg := range rawCh {
			if cm := msg.GetCm(); cm != nil {
				ch <- cm
			}
		}
	}()
	return ch, d.trackWatcherUnsub(unsub)
}

// ReadPublication retrieves a single message from a pub-sub topic published by
// the specified device and agent (microservice).
//
// Parameters:
//   - d: the EdgeDevice handle to read from
//   - fromAgent: the name of the agent/microservice publishing the topic
//   - key: identifies the specific message within the topic to fetch
//   - output: pointer to a value of type T to unmarshal the message into
//
// Returns an error if the message does not exist yet (e.g. before the agent has
// first published it), cannot be read, or does not unmarshal into T. Callers
// waiting for a message to appear should poll until the error clears.
func ReadPublication[T any](d *EdgeDevice, fromAgent string, persistent bool,
	key string, output *T) error {
	fullName := fmt.Sprintf("%T", *new(T))
	typeName := fullName[strings.LastIndex(fullName, ".")+1:]
	var path string
	if persistent {
		path = fmt.Sprintf("/persist/status/%s/%s/%s.json", fromAgent, typeName, key)
	} else {
		path = fmt.Sprintf("/run/%s/%s/%s.json", fromAgent, typeName, key)
	}
	data, err := d.ReadFile(path)
	if err != nil {
		return fmt.Errorf("ReadPublication: %w", err)
	}
	if err := json.Unmarshal(data, output); err != nil {
		return fmt.Errorf("ReadPublication: failed to unmarshal %q from device %q: %w",
			path, d.devName, err)
	}
	return nil
}

// ReadAllPublications retrieves all messages from a pub-sub topic published by
// the specified device and agent (microservice).
//
// Parameters:
//   - d: the EdgeDevice handle to read from
//   - fromAgent: the name of the agent/microservice publishing the topic
//
// Returns a slice of values of type T representing all messages from the topic,
// or an error if reading or unmarshaling fails.
func ReadAllPublications[T any](d *EdgeDevice, fromAgent string,
	persistent bool) ([]T, error) {
	fullName := fmt.Sprintf("%T", *new(T))
	typeName := fullName[strings.LastIndex(fullName, ".")+1:]
	var dir string
	if persistent {
		dir = fmt.Sprintf("/persist/status/%s/%s", fromAgent, typeName)
	} else {
		dir = fmt.Sprintf("/run/%s/%s", fromAgent, typeName)
	}
	// List all JSON files in the directory; suppress errors if the dir is absent.
	stdout, _, err := d.RunShellScript(
		"find "+shellEscape(dir)+" -maxdepth 1 -name '*.json' -type f 2>/dev/null || true",
		quickSSHCommandTimeout, 0)
	if err != nil {
		return nil, fmt.Errorf("ReadAllPublications: failed to list %q on device %q: %w",
			dir, d.devName, err)
	}
	var results []T
	// Pubsub keys become file names and may contain spaces.
	for _, file := range strings.Split(stdout, "\n") {
		file = strings.TrimRight(file, "\r")
		if file == "" {
			continue
		}
		data, err := d.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("ReadAllPublications: %w", err)
		}
		var item T
		if err := json.Unmarshal(data, &item); err != nil {
			return nil, fmt.Errorf(
				"ReadAllPublications: failed to unmarshal %q from device %q: %w",
				file, d.devName, err)
		}
		results = append(results, item)
	}
	return results, nil
}

// getDevUUID returns the device UUID, calling t.Fatalf if not found/onboarded.
func (d *EdgeDevice) getDevUUID() uuid.UUID {
	d.th.devicesM.Lock()
	defer d.th.devicesM.Unlock()
	devState, found := d.th.devices[d.devName]
	if !found {
		d.th.t.Fatalf("Unknown device %q", d.devName)
	}
	if devState.ID == NilUUID {
		d.th.t.Fatalf("Device %q is not onboarded", d.devName)
	}
	return devState.ID
}

// iterateInfoMsgs fetches all info messages from Adam matching the filter,
// calling onMatch for each. It uses a short timeout and calls t.Fatalf on error.
func (d *EdgeDevice) iterateInfoMsgs(devUUID uuid.UUID,
	filter func(*eveinfo.ZInfoMsg) bool, onMatch func(*eveinfo.ZInfoMsg)) {
	ctx, cancel := context.WithTimeout(d.th.ctx, gatherInfoMsgsTimeout)
	defer cancel()
	err := d.th.adamClient.IterateDeviceInfoMsgs(ctx, devUUID, filter,
		infoMsgIterFn(func(msg *eveinfo.ZInfoMsg) (bool, error) {
			onMatch(msg)
			return false, nil
		}), false)
	if err != nil {
		d.th.t.Fatalf("Failed to retrieve info messages for device %q: %v",
			d.devName, err)
	}
}

// iterateMetricMsgs fetches all metric messages from Adam, calling onMatch for each.
// It uses a short timeout and calls t.Fatalf on error.
func (d *EdgeDevice) iterateMetricMsgs(
	devUUID uuid.UUID, onMatch func(*evemetrics.ZMetricMsg)) {
	ctx, cancel := context.WithTimeout(d.th.ctx, gatherMetricsMsgsTimeout)
	defer cancel()
	err := d.th.adamClient.IterateDeviceMetrics(ctx, devUUID,
		metricMsgIterFn(func(msg *evemetrics.ZMetricMsg) (bool, error) {
			onMatch(msg)
			return false, nil
		}), false)
	if err != nil {
		d.th.t.Fatalf("Failed to retrieve metrics for device %q: %v",
			d.devName, err)
	}
}

// infoMsgIterFn adapts a function to the controller.InfoMsgIterator interface.
type infoMsgIterFn func(*eveinfo.ZInfoMsg) (bool, error)

func (f infoMsgIterFn) Iterate(msg *eveinfo.ZInfoMsg) (bool, error) { return f(msg) }

// metricMsgIterFn adapts a function to the controller.MetricMsgIterator interface.
type metricMsgIterFn func(*evemetrics.ZMetricMsg) (bool, error)

func (f metricMsgIterFn) Iterate(msg *evemetrics.ZMetricMsg) (bool, error) { return f(msg) }

// flowMsgIterFn adapts a function to the controller.FlowMsgIterator interface.
type flowMsgIterFn func(*eveflowlog.FlowMessage) (bool, error)

func (f flowMsgIterFn) Iterate(msg *eveflowlog.FlowMessage) (bool, error) { return f(msg) }

// appDownloadProgress returns the average download progress (0–100) across
// the app's volumes. For each volume UUID listed in volumeRefs the progress
// is taken from the latest ZInfoVolume in volumes:
//   - INVALID or INITIAL state → 0%
//   - DOWNLOADED or above      → 100%
//   - any other state          → ProgressPercentage as reported
//
// Returns 0 if volumeRefs is empty or no volume info has been received yet.
func appDownloadProgress(
	volumeRefs []string, volumes map[string]*eveinfo.ZInfoVolume) uint32 {
	if len(volumeRefs) == 0 {
		return 0
	}
	var total uint32
	for _, ref := range volumeRefs {
		vol, ok := volumes[ref]
		if !ok {
			// No info received yet for this volume; treat as 0%.
			continue
		}
		state := vol.GetState()
		switch {
		case state == eveinfo.ZSwState_INVALID || state == eveinfo.ZSwState_INITIAL:
			// 0 -- nothing added
		case state >= eveinfo.ZSwState_DOWNLOADED:
			total += 100
		default:
			total += vol.GetProgressPercentage()
		}
	}
	return total / uint32(len(volumeRefs))
}

// logMsgCollector accumulates log entries into []LogMsg, applying LogMsgMatch filters.
type logMsgCollector struct {
	match LogMsgMatch
	msgs  []LogMsg
}

func (c *logMsgCollector) toMatcher() logger.LogEntryMatcher {
	m := c.match
	return func(entry *evelogs.LogEntry) bool {
		ts := entry.GetTimestamp().AsTime()
		if m.Severity != "" && entry.GetSeverity() != m.Severity {
			return false
		}
		if m.Source != "" && entry.GetSource() != m.Source {
			return false
		}
		if m.Filename != "" && entry.GetFilename() != m.Filename {
			return false
		}
		if m.MsgHasSubstring != "" &&
			!strings.Contains(entry.GetContent(), m.MsgHasSubstring) {
			return false
		}
		if m.MsgMatchesRegexp.String() != "" &&
			!m.MsgMatchesRegexp.MatchString(entry.GetContent()) {
			return false
		}
		if !m.NotBefore.IsZero() && ts.Before(m.NotBefore) {
			return false
		}
		if !m.NotAfter.IsZero() && ts.After(m.NotAfter) {
			return false
		}
		return true
	}
}

func (c *logMsgCollector) Iterate(entry *evelogs.LogEntry) (bool, error) {
	c.msgs = append(c.msgs, LogMsg{
		Severity:  entry.GetSeverity(),
		Source:    entry.GetSource(),
		Filename:  entry.GetFilename(),
		Message:   entry.GetContent(),
		Timestamp: entry.GetTimestamp().AsTime(),
	})
	return false, nil
}

// shellEscape returns a single-quoted shell-safe version of s.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
