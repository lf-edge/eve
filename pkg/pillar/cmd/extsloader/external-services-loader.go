// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// External Services Loader manages services from split rootfs extension image.
// It discovers extension image for the active slot, mounts it, and starts
// services using the containerd API so they appear in `eve list`

package extsloader

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/edge-containers/pkg/registry"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cas"
	evecontainerd "github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

const (
	agentName            = "extsloader"
	errorTime            = 3 * time.Minute
	warningTime          = 40 * time.Second
	containerdRPCTimeout = 20 * time.Second
	extMount             = "/persist/exts"
	extRootHashHostPath  = types.ExtVerityRootHashHostPath
	extRootHashPath      = types.ExtVerityRootHashPath
	extVerityMapperPref  = "exts-verity-"
	servicesDir          = "/persist/eve-services"
	containerdSock       = "/run/containerd/containerd.sock"
	containerdNamespace  = "services.linuxkit"
	scanInterval         = 30 * time.Second
	hvTypePath           = "/run/eve-hv-type"
	// stateFilePath kept for backward compatibility with Eden tests reading it via SSH.
	// TODO: remove once tests switch to pubsub-derived checking.
	stateFilePath           = "/run/extsloader-state.json"
	serviceOverrideDir      = "/run/eve-service-overrides"
	serviceOverrideEnabled  = "enabled"
	serviceOverrideDisabled = "disabled"

	// PCR12 is used for Extension Image measurement. It is already in the
	// default sealing PCR set (DefaultDiskKeySealingPCRs) and currently
	// unused (zero). Extending it here binds extension state to vault
	// unseal and attestation.
	pcrIndexExtension       = 12
	pcrHandleExtension      = tpmutil.Handle(tpm2.PCRFirst + pcrIndexExtension)
	extensionMeasurementLog = "/persist/status/extsloader_tpm_event_log"
)

// hvOnlyServices maps service names to the HV flavor they require.
// Services not listed here run on all flavors.
var hvOnlyServices = map[string]string{
	"kube": "k",
}

// disabledServices maps global config keys to the service names they control.
// These services are still started during bootstrap so watcher can pause them
// to preserve the legacy lifecycle (started first, then paused if disabled).
var disabledServices = map[types.GlobalSettingKey]string{
	types.MemoryMonitorEnabled: "memory-monitor",
}

// extendPCR12 extends PCR12 with a SHA256 hash of the given measurement string.
// On devices without a TPM, it logs a notice and returns nil so the caller
// can proceed normally. An event log entry is appended for attestation.
func extendPCR12(measurement string) error {
	rw, err := tpm2.OpenTPM(evetpm.TpmDevicePath)
	if err != nil {
		log.Noticef("TPM not available, skipping PCR12 extend for %q", measurement)
		return nil
	}
	defer rw.Close()

	hash := sha256.Sum256([]byte(measurement))
	if err := tpm2.PCRExtend(rw, pcrHandleExtension, tpm2.AlgSHA256, hash[:], ""); err != nil {
		return fmt.Errorf("PCR12 extend failed for %q: %w", measurement, err)
	}

	pcr, _ := tpm2.ReadPCR(rw, pcrIndexExtension, tpm2.AlgSHA256)
	log.Noticef("PCR12 extended: %q -> %s", measurement, hex.EncodeToString(pcr))
	return nil
}

// writeMeasurementLog writes a simple text log of PCR12 extension events
// for attestation payload context (same pattern as measure-config).
func writeMeasurementLog(events []string) {
	if err := os.MkdirAll(filepath.Dir(extensionMeasurementLog), 0755); err != nil {
		log.Warnf("Failed to create measurement log directory: %v", err)
		return
	}
	content := strings.Join(events, "\n") + "\n"
	if err := os.WriteFile(extensionMeasurementLog, []byte(content), 0644); err != nil {
		log.Warnf("Failed to write measurement log: %v", err)
	}
}

type externalServicesContext struct {
	agentbase.AgentBase
	ps                   *pubsub.PubSub
	subGlobalConfig      pubsub.Subscription
	subBaseOsStatus      pubsub.Subscription
	subContentTreeStatus pubsub.Subscription
	pubExtsloaderStatus  pubsub.Publication
	pkgsImgPath          string
	pkgsImgMounted       bool
	servicesStarted      map[string]bool
	servicesSkipped      map[string]bool // services intentionally not started
	containerdClient     *containerd.Client
	ctx                  context.Context
}

type extensionLoaderState struct {
	State      string    `json:"state"`
	Reason     string    `json:"reason,omitempty"`
	Partition  string    `json:"partition,omitempty"`
	ImagePath  string    `json:"imagePath,omitempty"`
	MountPoint string    `json:"mountPoint,omitempty"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

type serviceTaskLogIO struct {
	cio.IO
	closers []io.Closer
}

var logger *logrus.Logger
var log *base.LogObject

func (s *serviceTaskLogIO) Close() error {
	err := s.IO.Close()
	for _, closer := range s.closers {
		if closer == nil {
			continue
		}
		if closeErr := closer.Close(); err == nil {
			err = closeErr
		}
	}
	return err
}

// Run is the entry point for the extsloader agent
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int {
	logger = loggerArg
	log = logArg

	log.Noticef("========================================")
	log.Noticef("Starting %s agent", agentName)
	log.Noticef("Base directory: %s", baseDir)
	log.Noticef("Arguments: %v", arguments)
	log.Noticef("========================================")

	// Create agent context
	log.Functionf("Creating agent context")
	ctx := &externalServicesContext{
		ps:              ps,
		servicesStarted: make(map[string]bool),
		servicesSkipped: make(map[string]bool),
	}

	log.Functionf("Initializing agent base")
	agentbase.Init(ctx, logger, log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithWatchdog(ps, warningTime, errorTime),
		agentbase.WithArguments(arguments))

	// Publish ExtsloaderStatus for nodeagent testing window validation
	pubExtsloaderStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.ExtsloaderStatus{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubExtsloaderStatus = pubExtsloaderStatus
	publishExtsloaderStatus(ctx, types.ExtsloaderStateStarting, "", "", "")

	// Extend PCR12 to mark loader startup. This is the first extend in
	// the boot sequence; PCR12 transitions from all-zeros to a known value.
	if err := extendPCR12("extsloader:starting"); err != nil {
		log.Errorf("PCR12 starting extend: %v", err)
	}

	// Subscribe to global config
	log.Functionf("Setting up global config subscription")
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Activate:      false,
		Ctx:           ctx,
		CreateHandler: handleGlobalConfigCreate,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subGlobalConfig = subGlobalConfig
	log.Functionf("Activating global config subscription")
	subGlobalConfig.Activate()

	// Subscribe to BaseOsStatus (from baseosmgr) for CAS self-heal.
	// This lets us find the active BaseOS ContentTree UUID.
	subBaseOsStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "baseosmgr",
		MyAgentName: agentName,
		TopicImpl:   types.BaseOsStatus{},
		Activate:    true,
		Ctx:         ctx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Errorf("BaseOsStatus subscription failed: %v", err)
	} else {
		ctx.subBaseOsStatus = subBaseOsStatus
	}

	// Subscribe to ContentTreeStatus (from volumemgr) for CAS self-heal.
	// This lets us resolve ContentTree UUID to the CAS reference ID.
	subContentTreeStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "volumemgr",
		MyAgentName: agentName,
		TopicImpl:   types.ContentTreeStatus{},
		Activate:    true,
		Ctx:         ctx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Errorf("ContentTreeStatus subscription failed: %v", err)
	} else {
		ctx.subContentTreeStatus = subContentTreeStatus
	}

	// Connect to containerd
	log.Noticef("Connecting to containerd at %s", containerdSock)
	log.Functionf("Using containerd namespace: %s", containerdNamespace)
	ctx.ctx = namespaces.WithNamespace(context.Background(), containerdNamespace)
	client, err := containerd.New(containerdSock)
	if err != nil {
		log.Errorf("Failed to connect to containerd: %v", err)
		log.Errorf("External services will NOT be loaded!")
	} else {
		ctx.containerdClient = client
		log.Noticef("✓ Successfully connected to containerd")
	}

	// Start periodic scan for extension image.
	log.Noticef("Starting periodic scan for extension image (interval: %s)", scanInterval)
	go scanForPkgsImg(ctx)

	log.Noticef("%s initial setup complete - entering main loop", agentName)

	// Prepare channels for pubsub subscriptions (nil channels are never selected)
	var baseOsChan, contentTreeChan <-chan pubsub.Change
	if ctx.subBaseOsStatus != nil {
		baseOsChan = ctx.subBaseOsStatus.MsgChan()
	}
	if ctx.subContentTreeStatus != nil {
		contentTreeChan = ctx.subContentTreeStatus.MsgChan()
	}

	// Run forever
	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case change := <-baseOsChan:
			ctx.subBaseOsStatus.ProcessChange(change)
		case change := <-contentTreeChan:
			ctx.subContentTreeStatus.ProcessChange(change)
		}
	}
}

// scanForPkgsImg periodically scans for extension image on available disks.
func scanForPkgsImg(ctx *externalServicesContext) {
	log.Noticef("scanForPkgsImg goroutine started")
	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()

	// Try immediately on startup
	log.Functionf("Running initial scan for extension image")
	ctx.ps.StillRunning(agentName, warningTime, errorTime)
	tryMountAndStartServices(ctx)

	scanCount := 1
	for range ticker.C {
		scanCount++
		log.Functionf("Periodic scan #%d for extension image", scanCount)
		ctx.ps.StillRunning(agentName, warningTime, errorTime)
		if ctx.pkgsImgMounted {
			log.Functionf("extension image already mounted, verifying services")
			// Already mounted, verify services are running
			verifyServices(ctx)
		} else {
			log.Functionf("extension image not yet mounted, attempting to find and mount")
			// Try to find and mount extension image.
			tryMountAndStartServices(ctx)
		}
	}
}

// tryMountAndStartServices searches for extension image and starts services.
func tryMountAndStartServices(ctx *externalServicesContext) {
	log.Functionf("tryMountAndStartServices: Checking if already mounted")
	if ctx.pkgsImgMounted {
		log.Functionf("extension image already mounted, skipping...")
		publishExtsloaderStatus(ctx, types.ExtsloaderStateReady, "", "", ctx.pkgsImgPath)
		return
	}

	// Touch watchdog before starting potentially long operation
	ctx.ps.StillRunning(agentName, warningTime, errorTime)

	partName := zboot.GetCurrentPartition()
	imageName, err := extensionImageName(partName)
	if err != nil {
		log.Errorf("Failed to map active partition %q to extension image: %v", partName, err)
		log.Errorf("Falling back to %s", types.ExtImgNameIMGA)
		imageName = types.ExtImgNameIMGA
	}

	// Search extension image on all block devices.
	log.Functionf("Searching for %s (active partition: %s) on available disks...", imageName, partName)
	pkgsImgPath := findPkgsImg(imageName)
	if pkgsImgPath == "" {
		// CAS self-heal: if Extension file is missing but Core expects one,
		// extract the disk-additional blob from containerd CAS.
		// This handles forward upgrade from monolithic to split rootfs.
		pkgsImgPath = extractExtensionFromCAS(ctx, partName, imageName)
	}
	if pkgsImgPath == "" {
		log.Warnf("%s not found on any disk or CAS", imageName)
		log.Warnf("Searched locations: /persist/%s, /mnt/pkgs-disk/%s, block devices, and containerd CAS", imageName, imageName)
		log.Warnf("To use external services, ensure %s is available in /persist", imageName)
		log.Warnf("Will retry in %s...", scanInterval)
		publishExtsloaderStatus(ctx, types.ExtsloaderStateFailed, "extension image not found", partName, "")
		return
	}

	log.Noticef("✓ Found extension image at %s", pkgsImgPath)
	ctx.pkgsImgPath = pkgsImgPath

	// Touch watchdog before mount
	ctx.ps.StillRunning(agentName, warningTime, errorTime)

	// Mounting and starting extension services transiently pulls the
	// compressed erofs image (~350 MB) into page cache charged to pillar's
	// cgroup. Temporarily raise the cgroup memory limits to accommodate
	// this, then restore them after fadvise drops the cache.
	restoreLimits := raiseCgroupLimitsForExtMount(pkgsImgPath)

	// Mount extension image via dm-verity. The root hash is loaded from the
	// Core Image (/etc/ext-verity-roothash) and used both for veritysetup
	// and for PCR12 measurement. No separate file hash is needed: the root
	// hash is the Merkle tree root and uniquely identifies the image content.
	log.Functionf("Attempting to mount extension image...")
	rootHash, err := mountPkgsImg(pkgsImgPath)
	if err != nil {
		log.Errorf("Failed to mount extension image: %v", err)
		if err2 := extendPCR12("extsloader:failed:mount-failed"); err2 != nil {
			log.Errorf("PCR12 mount-failed extend: %v", err2)
		}
		publishExtsloaderStatus(ctx, types.ExtsloaderStateFailed, fmt.Sprintf("mount failed: %v", err), partName, pkgsImgPath)
		restoreLimits()
		return
	}

	ctx.pkgsImgMounted = true
	log.Noticef("✓ Mounted extension image at %s", extMount)

	// Measure the verified extension image into PCR12 using the dm-verity
	// root hash. This is the same root hash that veritysetup used to set up
	// the device mapper, so it represents exactly what the kernel verified.
	// The root hash is trusted because it comes from the read-only Core
	// squashfs (measured into PCR13 by GRUB).
	var measureEvents []string
	measureEvents = append(measureEvents, "extsloader:starting")
	verifiedMeasurement := "extsloader:image-verified:" + rootHash
	if err := extendPCR12(verifiedMeasurement); err != nil {
		log.Errorf("PCR12 image-verified extend: %v", err)
	}
	measureEvents = append(measureEvents, verifiedMeasurement)

	// Release page cache for the backing image file and restore cgroup
	// limits immediately after mount, before starting services. The
	// compressed erofs blocks pulled in during mount are cached by the
	// dm layer and charged to pillar's cgroup (~350 MB). Services
	// mmap their executables from the mount, but those decompressed
	// pages are demand-faulted independently and not affected by
	// dropping the backing-file cache.
	dropImagePageCache(pkgsImgPath)
	restoreLimits()

	// Touch watchdog before starting services
	ctx.ps.StillRunning(agentName, warningTime, errorTime)

	// Start all services from extension image.
	log.Noticef("Starting all services from extension image...")
	if err := startAllServices(ctx); err != nil {
		log.Errorf("Failed to start services: %v", err)
		failMeasurement := "extsloader:failed:services-failed"
		if err2 := extendPCR12(failMeasurement); err2 != nil {
			log.Errorf("PCR12 services-failed extend: %v", err2)
		}
		measureEvents = append(measureEvents, failMeasurement)
		writeMeasurementLog(measureEvents)
		publishExtsloaderStatus(ctx, types.ExtsloaderStateFailed, fmt.Sprintf("start services failed: %v", err), partName, pkgsImgPath)
	} else {
		log.Noticef("✓ All services started successfully")
		runningMeasurement := "extsloader:services-running"
		if err := extendPCR12(runningMeasurement); err != nil {
			log.Errorf("PCR12 services-running extend: %v", err)
		}
		measureEvents = append(measureEvents, runningMeasurement)
		writeMeasurementLog(measureEvents)
		publishExtsloaderStatus(ctx, types.ExtsloaderStateReady, "", partName, pkgsImgPath)
	}
}

func extensionImageName(partName string) (string, error) {
	switch strings.TrimSpace(partName) {
	case "IMGA":
		return types.ExtImgNameIMGA, nil
	case "IMGB":
		return types.ExtImgNameIMGB, nil
	default:
		return "", fmt.Errorf("unsupported partition label %q", partName)
	}
}

// extractExtensionFromCAS attempts CAS self-healing: when the Extension
// image file is missing on PERSIST but the Core Image expects one
// (/etc/ext-verity-roothash exists), find the active BaseOS ContentTree
// reference, locate the disk-additional layer in CAS, and extract it.
// This handles the forward upgrade case where old monolithic code wrote
// Core but skipped Extension during WriteToPartition.
func extractExtensionFromCAS(ctx *externalServicesContext, partName, imageName string) string {
	targetPath, err := types.ExtensionImagePath(partName)
	if err != nil {
		log.Errorf("extractExtensionFromCAS: %v", err)
		return ""
	}

	// Only attempt self-heal if Core expects an Extension
	if _, err := os.Stat(extRootHashHostPath); os.IsNotExist(err) {
		log.Functionf("extractExtensionFromCAS: no %s, Core does not expect Extension", extRootHashHostPath)
		return ""
	}

	log.Noticef("extractExtensionFromCAS: Extension expected but missing, attempting CAS extraction")

	// Find the active BaseOS ContentTree reference by reading
	// ContentTreeStatus published by volumemgr via pubsub filesystem.
	ref := findActiveBaseOSReference(ctx, partName)
	if ref == "" {
		log.Warnf("extractExtensionFromCAS: could not find active BaseOS ContentTree reference")
		return ""
	}

	log.Noticef("extractExtensionFromCAS: active BaseOS reference: %s", ref)

	// Use the same Puller.Pull + FilesTarget mechanism as WriteToPartition.
	// The OCI image config label org.lfedge.eci.artifact.disk-0 tells
	// edge-containers which file inside the tar layers is the Extension.
	// FilesTarget.Disks[0] receives that file.
	casClient, err := cas.NewCAS("containerd")
	if err != nil {
		log.Errorf("extractExtensionFromCAS: failed to create CAS client: %v", err)
		return ""
	}
	defer casClient.CloseClient()

	ctrdCtx, done := casClient.CtrNewUserServicesCtx()
	defer done()

	resolver, err := casClient.Resolver(ctrdCtx)
	if err != nil {
		log.Errorf("extractExtensionFromCAS: failed to get CAS resolver: %v", err)
		return ""
	}

	tmpPath := targetPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		log.Errorf("extractExtensionFromCAS: failed to create %s: %v", tmpPath, err)
		return ""
	}

	puller := registry.Puller{Image: ref}
	_, artifact, err := puller.Pull(
		&registry.FilesTarget{Disks: []io.Writer{f}, AcceptHash: true},
		0, false, os.Stderr, resolver,
	)
	f.Close()

	if err != nil {
		os.Remove(tmpPath)
		log.Errorf("extractExtensionFromCAS: pull failed for %s: %v", ref, err)
		return ""
	}
	_ = artifact // Artifact.Disks is populated from layer annotations only; we use config label routing instead

	// Verify something was actually written (config label routing via pathWriters)
	fi, err := os.Stat(tmpPath)
	if err != nil || fi.Size() == 0 {
		os.Remove(tmpPath)
		log.Warnf("extractExtensionFromCAS: no additional disk extracted from %s (monolithic image or missing label)", ref)
		return ""
	}

	if err := os.Rename(tmpPath, targetPath); err != nil {
		os.Remove(tmpPath)
		log.Errorf("extractExtensionFromCAS: rename failed: %v", err)
		return ""
	}

	log.Noticef("extractExtensionFromCAS: successfully extracted Extension (%d bytes) to %s", fi.Size(), targetPath)
	return targetPath
}

// findActiveBaseOSReference uses pubsub subscriptions to find the CAS
// reference for the BaseOS ContentTree on the given partition.
func findActiveBaseOSReference(ctx *externalServicesContext, partName string) string {
	if ctx.subBaseOsStatus == nil || ctx.subContentTreeStatus == nil {
		log.Warnf("findActiveBaseOSReference: pubsub subscriptions not available")
		return ""
	}

	// Find BaseOsStatus for our partition
	items := ctx.subBaseOsStatus.GetAll()
	for _, item := range items {
		status, ok := item.(types.BaseOsStatus)
		if !ok {
			continue
		}
		if status.PartitionLabel != partName || status.ContentTreeUUID == "" {
			continue
		}

		log.Functionf("findActiveBaseOSReference: BaseOsStatus for %s, ContentTreeUUID=%s",
			partName, status.ContentTreeUUID)

		// Look up ContentTreeStatus to get the CAS reference ID
		ctsItem, err := ctx.subContentTreeStatus.Get(status.ContentTreeUUID)
		if err != nil {
			log.Errorf("findActiveBaseOSReference: ContentTreeStatus %s not found: %v",
				status.ContentTreeUUID, err)
			// Try iterating all entries as fallback
			ctsItems := ctx.subContentTreeStatus.GetAll()
			for _, ci := range ctsItems {
				cts, ok := ci.(types.ContentTreeStatus)
				if !ok {
					continue
				}
				if cts.ContentID.String() == status.ContentTreeUUID {
					refID := cts.ReferenceID()
					log.Functionf("findActiveBaseOSReference: ContentTree %s -> ref %s",
						status.ContentTreeUUID, refID)
					return refID
				}
			}
			return ""
		}
		cts, ok := ctsItem.(types.ContentTreeStatus)
		if !ok {
			return ""
		}
		refID := cts.ReferenceID()
		log.Functionf("findActiveBaseOSReference: ContentTree %s -> ref %s",
			status.ContentTreeUUID, refID)
		return refID
	}

	log.Warnf("findActiveBaseOSReference: no BaseOsStatus found for partition %s", partName)
	return ""
}

// findPkgsImg searches for extension image on all available block devices.
func findPkgsImg(imageName string) string {
	log.Functionf("findPkgsImg: Starting search for %s", imageName)

	// Common locations to search
	searchPaths := []string{
		"/persist/" + imageName,
		"/mnt/pkgs-disk/" + imageName,
	}

	log.Functionf("Checking common locations first: %v", searchPaths)

	// Also search on all block devices
	log.Functionf("Scanning block devices...")
	blockDevs, err := filepath.Glob("/dev/sd*[0-9]")
	if err == nil {
		log.Functionf("Found %d block devices to scan", len(blockDevs))
		for _, dev := range blockDevs {
			log.Functionf("Checking device: %s", dev)
			// Try mounting temporarily to check for extension image.
			tmpMount := "/tmp/check-pkgs-" + filepath.Base(dev)
			os.MkdirAll(tmpMount, 0755)

			// Use mount command (like install-pkgs-img.sh) instead of syscall.Mount
			// This works with VVFAT and other special filesystems
			cmd := exec.Command("mount", "-o", "ro", dev, tmpMount)
			if err := cmd.Run(); err == nil {
				log.Functionf("Mounted %s to %s, checking for %s", dev, tmpMount, imageName)

				// Check if extension image exists directly in the mount point.
				pkgsPath := filepath.Join(tmpMount, imageName)
				if stat, err := os.Stat(pkgsPath); err == nil && !stat.IsDir() {
					log.Noticef("✓ Found %s on device %s at %s", imageName, dev, pkgsPath)

					// Copy to /persist before unmounting
					destPath := "/persist/" + imageName
					log.Functionf("Copying %s from %s to %s...", imageName, pkgsPath, destPath)
					if err := copyFile(pkgsPath, destPath); err == nil {
						log.Noticef("✓ Copied %s from %s to %s", imageName, dev, destPath)
						exec.Command("umount", tmpMount).Run()
						os.RemoveAll(tmpMount)
						searchPaths = append([]string{destPath}, searchPaths...)
						break // Found it, no need to check other devices
					} else {
						log.Errorf("Failed to copy %s: %v", imageName, err)
					}
				} else {
					log.Functionf("%s not found at %s, checking subdirectories...", imageName, pkgsPath)

					// List what's actually in the mounted directory
					entries, err := os.ReadDir(tmpMount)
					if err == nil {
						log.Functionf("Contents of %s:", tmpMount)
						for _, entry := range entries {
							log.Functionf("  - %s (dir=%v)", entry.Name(), entry.IsDir())
						}
					}

					log.Functionf("%s not found on %s", imageName, dev)
				}

				exec.Command("umount", tmpMount).Run()
				os.RemoveAll(tmpMount)
			} else {
				log.Functionf("Failed to mount %s: %v", dev, err)
			}
		}
	} else {
		log.Warnf("Failed to glob block devices: %v", err)
	}

	// Check each path.
	log.Functionf("Checking final search paths...")
	for _, path := range searchPaths {
		log.Functionf("Checking: %s", path)
		if _, err := os.Stat(path); err == nil {
			log.Noticef("✓ Found %s at: %s", imageName, path)
			return path
		}
	}

	log.Functionf("%s not found in any location", imageName)
	return ""
}

// mountPkgsImg mounts the Extension image via dm-verity and returns the root
// hash used for verification. The root hash is loaded exclusively from the
// Core Image (/etc/ext-verity-roothash) and serves as the cryptographic
// identity of the Extension. dm-verity verification is mandatory — there is
// no legacy fallback. If veritysetup is missing or roothash is not found,
// mount fails and the update should be rolled back.
func mountPkgsImg(imgPath string) (rootHash string, err error) {
	// Check if already mounted
	mounts, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return "", err
	}
	if strings.Contains(string(mounts), extMount) {
		log.Functionf("extension image already mounted")
		return "", nil
	}

	// Create mount point
	if err := os.MkdirAll(extMount, 0755); err != nil {
		return "", err
	}

	// dm-verity mount (mandatory, no legacy fallback)
	rootHash, mounted, err := mountPkgsImgWithVerity(imgPath)
	if err != nil {
		return "", err
	}
	if !mounted {
		return "", fmt.Errorf("dm-verity mount failed: veritysetup or roothash not available")
	}
	return rootHash, nil
}

// dropImagePageCache advises the kernel to release cached pages for the
// extension image backing file. This reclaims the compressed erofs blocks
// held in the loop/dm layer's page cache (charged to pillar's cgroup).
// Decompressed pages that services have mmap'd are in erofs's own address
// space and are NOT affected by this call.
func dropImagePageCache(imgPath string) {
	fd, err := unix.Open(imgPath, unix.O_RDONLY, 0)
	if err != nil {
		log.Warnf("dropImagePageCache: open %s: %v", imgPath, err)
		return
	}
	defer unix.Close(fd)

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		log.Warnf("dropImagePageCache: fstat %s: %v", imgPath, err)
		return
	}

	if err := unix.Fadvise(fd, 0, stat.Size, unix.FADV_DONTNEED); err != nil {
		log.Warnf("dropImagePageCache: fadvise DONTNEED %s: %v", imgPath, err)
		return
	}
	log.Noticef("dropImagePageCache: released page cache for %s (%d bytes)", imgPath, stat.Size)
}

// cgroupMemoryLimitPaths lists the cgroup memory limit files that must be
// raised (in order: parent first) to accommodate transient page cache during
// extension mount.
var cgroupMemoryLimitPaths = []string{
	types.EveMemoryLimitFile,
	types.EveServicesMemoryLimitFile,
	types.PillarHardMemoryLimitFile,
}

// raiseCgroupLimitsForExtMount temporarily increases the eve/services/pillar
// cgroup memory limits to accommodate the transient page cache from mounting
// the compressed erofs extension image. The returned function restores the
// original limits and must always be called (even on error paths).
//
// Each limit is raised by 2x the image size to cover:
//   - 1x for the compressed erofs blocks pulled into page cache
//   - 1x for startup overhead (service RSS growth, decompression buffers,
//     Go GC headroom) that occurs before fadvise reclaims the cache
//
// Parent cgroups (/eve, /eve/services) are raised by the same amount since
// the transient spike is dominated by pillar; other services' memory is
// roughly stable during extension loading.
func raiseCgroupLimitsForExtMount(imgPath string) func() {
	var imgSize int64
	if info, err := os.Stat(imgPath); err == nil {
		imgSize = info.Size()
	} else {
		log.Warnf("raiseCgroupLimits: stat %s: %v; skipping limit adjustment", imgPath, err)
		return func() {}
	}
	extraBytes := imgSize * 2

	type savedLimit struct {
		path string
		orig int64
	}
	var saved []savedLimit

	for _, limitPath := range cgroupMemoryLimitPaths {
		orig, err := types.ReadCgroupMemoryLimit(limitPath)
		if err != nil {
			log.Warnf("raiseCgroupLimits: read %s: %v; skipping", limitPath, err)
			continue
		}
		if orig <= 0 {
			// Unlimited — no adjustment needed.
			continue
		}

		newLimit := orig + extraBytes
		if err := types.WriteCgroupMemoryLimit(limitPath, newLimit); err != nil {
			log.Warnf("raiseCgroupLimits: write %s: %v; skipping", limitPath, err)
			continue
		}
		saved = append(saved, savedLimit{path: limitPath, orig: orig})
		log.Noticef("raiseCgroupLimits: %s raised %d -> %d (+%d = 2x image size)",
			limitPath, orig, newLimit, extraBytes)
	}

	return func() {
		// Restore in reverse order: children first, then parents.
		for i := len(saved) - 1; i >= 0; i-- {
			s := saved[i]
			if err := types.WriteCgroupMemoryLimit(s.path, s.orig); err != nil {
				log.Warnf("restoreCgroupLimits: write %s: %v", s.path, err)
				continue
			}
			log.Noticef("restoreCgroupLimits: %s restored to %d", s.path, s.orig)
		}
	}
}

func mountPkgsImgWithVerity(imgPath string) (string, bool, error) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		return "", false, fmt.Errorf("veritysetup binary not found in Core image: %w", err)
	}

	rootHash, hashOffset, rootHashPath, foundRootHash, err := loadExtensionRootHash()
	if err != nil {
		return "", false, err
	}
	if !foundRootHash {
		return "", false, fmt.Errorf("dm-verity root hash not found in Core (%s)", extRootHashPath)
	}

	mapperName := extensionVerityMapperName(imgPath)
	mapperPath := filepath.Join("/dev/mapper", mapperName)
	hashOffsetStr := strconv.FormatInt(hashOffset, 10)
	log.Noticef("Setting up dm-verity for extension image: data=%s hash-offset=%s root-hash-source=%s",
		imgPath, hashOffsetStr, rootHashPath)

	_ = exec.Command("veritysetup", "close", mapperName).Run()
	// The Merkle hash tree is appended to the image file at hashOffset.
	// Use the same file as both data and hash device with --hash-offset.
	cmd := exec.Command("veritysetup", "open",
		"--hash-offset", hashOffsetStr,
		imgPath, mapperName, imgPath, rootHash)
	cmdOut, err := cmd.CombinedOutput()
	if err != nil {
		return "", false, fmt.Errorf("veritysetup open failed: %w; output: %s", err, string(cmdOut))
	}

	// Split-rootfs extension image is expected to be erofs.
	mountCmd := exec.Command("mount", "-t", "erofs", "-o", "ro", mapperPath, extMount)
	mountOut, err := mountCmd.CombinedOutput()
	if err != nil {
		_ = exec.Command("veritysetup", "close", mapperName).Run()
		return "", false, fmt.Errorf("mount verified erofs failed: %w; output: %s", err, string(mountOut))
	}
	log.Noticef("Mounted extension image via dm-verity at %s", extMount)
	return rootHash, true, nil
}

// loadExtensionRootHash loads the dm-verity root hash and data size from the
// Core Image. The file contains two lines: root hash (hex) and data size in
// bytes. The data size is the --hash-offset for veritysetup open, since the
// Merkle tree is appended directly to the extension image.
//
// The root hash is the trust anchor that binds Core and Extension to the same
// version. It must NOT be loaded from sidecar files on PERSIST, as those could
// be replaced by an attacker alongside the Extension image.
func loadExtensionRootHash() (rootHash string, hashOffset int64, path string, found bool, err error) {
	candidates := []string{
		extRootHashHostPath,
		extRootHashPath,
	}
	for _, p := range candidates {
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			if os.IsNotExist(readErr) {
				continue
			}
			return "", 0, "", false, fmt.Errorf("failed reading root hash from %s: %w", p, readErr)
		}
		lines := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)
		if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
			return "", 0, "", false, fmt.Errorf("empty dm-verity root hash in %s", p)
		}
		rh := strings.TrimSpace(lines[0])
		var offset int64
		if len(lines) >= 2 {
			offset, err = strconv.ParseInt(strings.TrimSpace(lines[1]), 10, 64)
			if err != nil {
				return "", 0, "", false, fmt.Errorf("invalid data size (hash offset) in %s: %w", p, err)
			}
		}
		return rh, offset, p, true, nil
	}
	return "", 0, "", false, nil
}

func extensionVerityMapperName(imgPath string) string {
	base := strings.ToLower(filepath.Base(imgPath))
	base = strings.ReplaceAll(base, ".", "-")
	return extVerityMapperPref + base
}

// startAllServices starts all services found in extension image.
func startAllServices(ctx *externalServicesContext) error {
	log.Functionf("startAllServices: Entry")

	if ctx.containerdClient == nil {
		log.Errorf("startAllServices: containerd client not available!")
		return fmt.Errorf("containerd client not available")
	}

	servicesPath := filepath.Join(extMount, "containers/services")
	log.Functionf("Reading services from: %s", servicesPath)

	entries, err := os.ReadDir(servicesPath)
	if err != nil {
		log.Errorf("Failed to read services directory %s: %v", servicesPath, err)
		return fmt.Errorf("failed to read services directory: %w", err)
	}

	log.Noticef("Found %d entries in services directory", len(entries))

	// Read current HV flavor for filtering HV-specific services
	hvFlavor := ""
	if data, err := os.ReadFile(hvTypePath); err == nil {
		hvFlavor = strings.TrimSpace(string(data))
	}
	log.Noticef("Current HV flavor: %q", hvFlavor)

	serviceCount := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			log.Functionf("Skipping non-directory entry: %s", entry.Name())
			continue
		}

		serviceName := entry.Name()

		// Skip services that require a different HV flavor
		if requiredHV, ok := hvOnlyServices[serviceName]; ok && hvFlavor != requiredHV {
			log.Noticef("Skipping service %s: requires HV %q, current is %q", serviceName, requiredHV, hvFlavor)
			continue
		}

		servicePath := filepath.Join(servicesPath, serviceName)

		log.Noticef("━━━ Starting service: %s ━━━", serviceName)
		log.Functionf("Service path: %s", servicePath)

		// Touch watchdog before starting each service
		ctx.ps.StillRunning(agentName, warningTime, errorTime)

		if err := startService(ctx, serviceName, servicePath); err != nil {
			log.Errorf("Failed to start %s: %v", serviceName, err)
		} else {
			ctx.servicesStarted[serviceName] = true
			serviceCount++
			log.Noticef("✓ %s started successfully (%d/%d)", serviceName, serviceCount, len(entries))
		}
	}

	log.Noticef("Finished starting services: %d successful", serviceCount)
	return nil
}

// isServiceDisabledByConfig checks whether a service should be treated as
// disabled by the current global configuration.
func isServiceDisabledByConfig(ctx *externalServicesContext, serviceName string) bool {
	if override, ok := localServiceOverride(serviceName); ok {
		return override == serviceOverrideDisabled
	}
	gcp := agentlog.GetGlobalConfig(log, ctx.subGlobalConfig)
	if gcp == nil {
		// GlobalConfig not yet received; use spec defaults so services that
		// default to disabled (e.g. memory-monitor) are treated as disabled
		// for pause/restart decisions until config arrives.
		gcp = types.DefaultConfigItemValueMap()
		log.Noticef("GlobalConfig unavailable; using spec defaults for %s check", serviceName)
	}
	for key, name := range disabledServices {
		if name == serviceName && !gcp.GlobalValueBool(key) {
			return true
		}
	}
	return false
}

func localServiceOverride(serviceName string) (string, bool) {
	overridePath := filepath.Join(serviceOverrideDir, serviceName)
	data, err := os.ReadFile(overridePath)
	if err != nil {
		return "", false
	}
	override := strings.TrimSpace(string(data))
	switch override {
	case serviceOverrideEnabled, serviceOverrideDisabled:
		return override, true
	default:
		log.Warnf("[%s] Ignoring invalid local override value %q from %s",
			serviceName, override, overridePath)
		return "", false
	}
}

// startService starts a single service using containerd API
func startService(ctx *externalServicesContext, name, servicePath string) error {
	log.Functionf("[%s] startService: Entry", name)

	// Prepare filesystem (create overlay mount)
	bundleDir := filepath.Join(servicesDir, name)
	rootfsPath := filepath.Join(bundleDir, "rootfs")

	log.Functionf("[%s] Bundle directory: %s", name, bundleDir)
	log.Functionf("[%s] Rootfs path: %s", name, rootfsPath)
	log.Functionf("[%s] Preparing filesystem...", name)

	if err := prepareFilesystem(servicePath, bundleDir); err != nil {
		log.Errorf("[%s] Failed to prepare filesystem: %v", name, err)
		return fmt.Errorf("prepare filesystem: %w", err)
	}
	log.Functionf("[%s] ✓ Filesystem prepared", name)

	// Load OCI spec from config.json
	configPath := filepath.Join(servicePath, "config.json")
	log.Functionf("[%s] Loading OCI spec from: %s", name, configPath)

	spec, err := loadSpec(configPath)
	if err != nil {
		log.Errorf("[%s] Failed to load spec: %v", name, err)
		return fmt.Errorf("load spec: %w", err)
	}
	log.Functionf("[%s] ✓ OCI spec loaded", name)

	// Update rootfs path to absolute
	log.Functionf("[%s] Original rootfs path in spec: %s", name, spec.Root.Path)
	spec.Root.Path = rootfsPath
	log.Functionf("[%s] Updated rootfs path to: %s", name, spec.Root.Path)

	// Delete existing container if any
	log.Functionf("[%s] Checking for existing container...", name)
	loadCtx, loadCancel := context.WithTimeout(ctx.ctx, containerdRPCTimeout)
	container, err := ctx.containerdClient.LoadContainer(loadCtx, name)
	loadCancel()
	if err == nil {
		log.Functionf("[%s] Found existing container, cleaning up...", name)
		taskCtx, taskCancel := context.WithTimeout(ctx.ctx, containerdRPCTimeout)
		task, taskErr := container.Task(taskCtx, nil)
		taskCancel()
		if taskErr == nil {
			log.Functionf("[%s] Killing existing task...", name)
			killCtx, killCancel := context.WithTimeout(ctx.ctx, containerdRPCTimeout)
			if err := task.Kill(killCtx, syscall.SIGKILL); err != nil {
				log.Warnf("[%s] Failed to kill existing task: %v", name, err)
			}
			killCancel()
			deleteTaskCtx, deleteTaskCancel := context.WithTimeout(ctx.ctx, containerdRPCTimeout)
			if _, err := task.Delete(deleteTaskCtx); err != nil {
				log.Warnf("[%s] Failed to delete existing task: %v", name, err)
			}
			deleteTaskCancel()
		}
		deleteCtrCtx, deleteCtrCancel := context.WithTimeout(ctx.ctx, containerdRPCTimeout)
		if err := container.Delete(deleteCtrCtx, containerd.WithSnapshotCleanup); err != nil {
			log.Warnf("[%s] Failed to delete existing container: %v", name, err)
		}
		deleteCtrCancel()
		log.Functionf("[%s] ✓ Existing container cleaned up", name)
	} else {
		log.Functionf("[%s] No existing container found", name)
	}

	// Create container with containerd API
	log.Functionf("[%s] Creating container with containerd API...", name)
	newCtrCtx, newCtrCancel := context.WithTimeout(ctx.ctx, containerdRPCTimeout)
	container, err = ctx.containerdClient.NewContainer(newCtrCtx, name,
		containerd.WithSpec(spec),
	)
	newCtrCancel()
	if err != nil {
		log.Errorf("[%s] Failed to create container: %v", name, err)
		return fmt.Errorf("create container: %w", err)
	}
	log.Functionf("[%s] ✓ Container created", name)

	// Create task
	stdoutSource := name + ".out"
	stderrSource := name + ".err"
	log.Functionf("[%s] Creating task with memlogd log sources stdout=%s stderr=%s",
		name, stdoutSource, stderrSource)

	newTaskCtx, newTaskCancel := context.WithTimeout(ctx.ctx, containerdRPCTimeout)
	task, err := container.NewTask(newTaskCtx, serviceLogCreator(name))
	newTaskCancel()
	if err != nil {
		log.Errorf("[%s] Failed to create task: %v", name, err)
		deleteCtrCtx, deleteCtrCancel := context.WithTimeout(ctx.ctx, containerdRPCTimeout)
		if err := container.Delete(deleteCtrCtx); err != nil {
			log.Warnf("[%s] Failed to cleanup container after task creation error: %v", name, err)
		}
		deleteCtrCancel()
		return fmt.Errorf("create task: %w", err)
	}
	log.Functionf("[%s] ✓ Task created", name)

	// Start task
	log.Functionf("[%s] Starting task...", name)
	startCtx, startCancel := context.WithTimeout(ctx.ctx, containerdRPCTimeout)
	if err := task.Start(startCtx); err != nil {
		startCancel()
		log.Errorf("[%s] Failed to start task: %v", name, err)
		deleteTaskCtx, deleteTaskCancel := context.WithTimeout(ctx.ctx, containerdRPCTimeout)
		if _, err := task.Delete(deleteTaskCtx); err != nil {
			log.Warnf("[%s] Failed to cleanup task after start error: %v", name, err)
		}
		deleteTaskCancel()
		deleteCtrCtx, deleteCtrCancel := context.WithTimeout(ctx.ctx, containerdRPCTimeout)
		if err := container.Delete(deleteCtrCtx); err != nil {
			log.Warnf("[%s] Failed to cleanup container after start error: %v", name, err)
		}
		deleteCtrCancel()
		return fmt.Errorf("start task: %w", err)
	}
	startCancel()

	log.Noticef("[%s] ✓✓✓ Service started successfully! ✓✓✓", name)
	return nil
}

func serviceTaskStatus(ctx *externalServicesContext, name string) (containerd.ProcessStatus, bool, error) {
	loadCtx, loadCancel := context.WithTimeout(ctx.ctx, containerdRPCTimeout)
	container, err := ctx.containerdClient.LoadContainer(loadCtx, name)
	loadCancel()
	if err != nil {
		if errdefs.IsNotFound(err) {
			return "", false, nil
		}
		return "", false, err
	}

	taskCtx, taskCancel := context.WithTimeout(ctx.ctx, containerdRPCTimeout)
	task, err := container.Task(taskCtx, nil)
	taskCancel()
	if err != nil {
		if errdefs.IsNotFound(err) {
			return "", false, nil
		}
		return "", false, err
	}

	statusCtx, statusCancel := context.WithTimeout(ctx.ctx, containerdRPCTimeout)
	status, err := task.Status(statusCtx)
	statusCancel()
	if err != nil {
		return "", false, err
	}
	return status.Status, true, nil
}

func serviceLogCreator(name string) cio.Creator {
	return func(taskID string) (cio.IO, error) {
		logger := evecontainerd.GetLog()
		stdoutName := name + ".out"
		stderrName := name + ".err"

		stdout, err := logger.Open(stdoutName)
		if err != nil {
			return nil, fmt.Errorf("open stdout log stream %q: %w", stdoutName, err)
		}
		stderr, err := logger.Open(stderrName)
		if err != nil {
			_ = stdout.Close()
			return nil, fmt.Errorf("open stderr log stream %q: %w", stderrName, err)
		}

		creator := cio.NewCreator(cio.WithStreams(io.MultiReader(), stdout, stderr))
		taskIO, err := creator(taskID)
		if err != nil {
			_ = stdout.Close()
			_ = stderr.Close()
			return nil, err
		}
		return &serviceTaskLogIO{
			IO:      taskIO,
			closers: []io.Closer{stdout, stderr},
		}, nil
	}
}

// prepareFilesystem creates the overlay mount for a service
func prepareFilesystem(servicePath, bundleDir string) error {
	log.Functionf("prepareFilesystem: servicePath=%s, bundleDir=%s", servicePath, bundleDir)

	rootfsPath := filepath.Join(bundleDir, "rootfs")
	upperDir := filepath.Join(bundleDir, "tmp/upper")
	workDir := filepath.Join(bundleDir, "tmp/work")

	log.Functionf("Creating directories: rootfs=%s, upper=%s, work=%s", rootfsPath, upperDir, workDir)

	for _, dir := range []string{rootfsPath, upperDir, workDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Errorf("Failed to create directory %s: %v", dir, err)
			return err
		}
	}
	log.Functionf("✓ All directories created")

	// Mount overlay
	lowerDir := filepath.Join(servicePath, "lower")
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lowerDir, upperDir, workDir)

	log.Functionf("Mounting overlay: lowerdir=%s", lowerDir)
	log.Functionf("Mount options: %s", opts)
	log.Functionf("Mount target: %s", rootfsPath)

	if err := syscall.Mount("overlay", rootfsPath, "overlay", 0, opts); err != nil {
		log.Errorf("Overlay mount failed: %v", err)
		return fmt.Errorf("mount overlay: %w", err)
	}

	log.Functionf("✓ Overlay mounted successfully")
	return nil
}

// loadSpec loads OCI spec from config.json
func loadSpec(path string) (*specs.Spec, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var spec specs.Spec
	if err := json.NewDecoder(f).Decode(&spec); err != nil {
		return nil, err
	}

	return &spec, nil
}

// verifyServices checks that all services are still running
func verifyServices(ctx *externalServicesContext) {
	log.Functionf("verifyServices: Checking %d services", len(ctx.servicesStarted))

	for serviceName := range ctx.servicesStarted {
		ctx.ps.StillRunning(agentName, warningTime, errorTime)

		// If a previously started service is now disabled, skip verification
		// (watcher will pause it).
		if isServiceDisabledByConfig(ctx, serviceName) {
			log.Functionf("[%s] Service disabled by global config, skipping verification", serviceName)
			continue
		}

		log.Functionf("[%s] Verifying service status...", serviceName)

		loadCtx, loadCancel := context.WithTimeout(ctx.ctx, containerdRPCTimeout)
		container, err := ctx.containerdClient.LoadContainer(loadCtx, serviceName)
		loadCancel()
		if err != nil {
			log.Warnf("[%s] Service container not found, restarting", serviceName)
			servicePath := filepath.Join(extMount, "containers/services", serviceName)
			if err := startService(ctx, serviceName, servicePath); err != nil {
				log.Errorf("[%s] Failed to restart: %v", serviceName, err)
			}
			continue
		}

		// Check if task is running
		taskCtx, taskCancel := context.WithTimeout(ctx.ctx, containerdRPCTimeout)
		task, err := container.Task(taskCtx, nil)
		taskCancel()
		if err != nil {
			log.Warnf("[%s] Task not found, restarting service", serviceName)
			servicePath := filepath.Join(extMount, "containers/services", serviceName)
			if err := startService(ctx, serviceName, servicePath); err != nil {
				log.Errorf("[%s] Failed to restart: %v", serviceName, err)
			}
		} else {
			// Check task status
			statusCtx, statusCancel := context.WithTimeout(ctx.ctx, containerdRPCTimeout)
			status, err := task.Status(statusCtx)
			statusCancel()
			if err != nil {
				log.Warnf("[%s] Failed to query task status, restarting service: %v", serviceName, err)
				servicePath := filepath.Join(extMount, "containers/services", serviceName)
				if err := startService(ctx, serviceName, servicePath); err != nil {
					log.Errorf("[%s] Failed to restart: %v", serviceName, err)
				}
				continue
			}
			if status.Status == containerd.Unknown {
				// Avoid immediate restart loops while runtime state is indeterminate.
				log.Warnf("[%s] Task status is unknown, will recheck on next scan", serviceName)
				continue
			}
			if status.Status == containerd.Paused {
				// Paused is a valid state managed by another agent (e.g., watcher
				// pauses memory-monitor when memory-monitor.enabled is false).
				log.Functionf("[%s] Task paused (managed by another agent), skipping", serviceName)
			} else if status.Status != containerd.Running {
				log.Warnf("[%s] Task not running (status=%v), restarting", serviceName, status.Status)
				servicePath := filepath.Join(extMount, "containers/services", serviceName)
				if err := startService(ctx, serviceName, servicePath); err != nil {
					log.Errorf("[%s] Failed to restart: %v", serviceName, err)
				}
			} else {
				log.Functionf("[%s] ✓ Service running OK", serviceName)
			}
		}
	}

	log.Functionf("verifyServices: Complete")
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, input, 0644)
}

// publishExtsloaderStatus publishes the current extsloader state via pubsub.
// This is consumed by nodeagent during the testing window to determine if
// Extension loaded successfully (update success criteria).
func publishExtsloaderStatus(ctx *externalServicesContext, state types.ExtsloaderState, reason, partition, imagePath string) {
	status := types.ExtsloaderStatus{
		State:      state,
		Reason:     reason,
		Partition:  partition,
		ImagePath:  imagePath,
		MountPoint: extMount,
	}
	if state == types.ExtsloaderStateFailed {
		status.SetErrorNow(reason)
	}
	key := status.Key()
	log.Functionf("publishExtsloaderStatus: state=%s partition=%s reason=%s", state, partition, reason)
	if err := ctx.pubExtsloaderStatus.Publish(key, status); err != nil {
		log.Errorf("publishExtsloaderStatus failed: %v", err)
	}
	// Also write state file for debug/testing (read via console or eden eve ssh).
	// TODO: remove once Eden tests use pubsub-derived checking.
	writeDebugStateFile(state.String(), reason, partition, imagePath)
}

func writeDebugStateFile(state, reason, partition, imagePath string) {
	s := extensionLoaderState{
		State:      state,
		Reason:     reason,
		Partition:  partition,
		ImagePath:  imagePath,
		MountPoint: extMount,
		UpdatedAt:  time.Now().UTC(),
	}
	data, err := json.Marshal(s)
	if err != nil {
		return
	}
	tmp := stateFilePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return
	}
	os.Rename(tmp, stateFilePath)
}

// Global config handlers
func handleGlobalConfigCreate(ctxArg interface{}, key string, statusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigModify(ctxArg interface{}, key string, statusArg interface{}, oldStatusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigImpl(ctxArg interface{}, key string, statusArg interface{}) {
	ctx := ctxArg.(*externalServicesContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s", key)
	agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName, ctx.CLIParams().DebugOverride, logger)

	// Check if any previously skipped service should now be started.
	if ctx.pkgsImgMounted {
		updateDisabledServices(ctx)
	}
}

// updateDisabledServices starts services that were previously skipped but are
// now enabled by global config, and marks running services for skip when they
// become disabled (watcher handles the actual pause).
func updateDisabledServices(ctx *externalServicesContext) {
	for _, serviceName := range disabledServices {
		disabled := isServiceDisabledByConfig(ctx, serviceName)

		// Service was skipped and is now enabled — either let watcher
		// resume the existing paused task or start it if nothing exists.
		if ctx.servicesSkipped[serviceName] && !disabled {
			log.Noticef("[%s] Service now enabled by global config", serviceName)
			delete(ctx.servicesSkipped, serviceName)
			status, exists, err := serviceTaskStatus(ctx, serviceName)
			if err != nil {
				log.Errorf("[%s] Failed to inspect existing task state: %v", serviceName, err)
				continue
			}
			if exists {
				log.Noticef("[%s] Existing task found with status=%v, leaving resume to watcher",
					serviceName, status)
				continue
			}
			log.Noticef("[%s] No existing task found, starting service", serviceName)
			servicePath := filepath.Join(extMount, "containers/services", serviceName)
			if err := startService(ctx, serviceName, servicePath); err != nil {
				log.Errorf("[%s] Failed to start newly enabled service: %v", serviceName, err)
			} else {
				ctx.servicesStarted[serviceName] = true
			}
		}

		// Service is running and is now disabled — mark as skipped so
		// verifyServices won't restart it after watcher pauses it.
		if ctx.servicesStarted[serviceName] && disabled {
			log.Noticef("[%s] Service now disabled by global config", serviceName)
			ctx.servicesSkipped[serviceName] = true
		}
	}
}

func handleGlobalConfigDelete(ctxArg interface{}, key string, statusArg interface{}) {
	ctx := ctxArg.(*externalServicesContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigDelete for %s", key)
	agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName, ctx.CLIParams().DebugOverride, logger)
}
