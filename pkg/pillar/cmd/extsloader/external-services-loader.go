// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// External Services Loader manages services from pkgs.img
// It discovers pkgs.img on available disks, mounts it, and starts
// services using the containerd API so they appear in `eve list`

package extsloader

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/namespaces"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

const (
	agentName           = "extsloader"
	errorTime           = 3 * time.Minute
	warningTime         = 40 * time.Second
	pkgsImgName         = "pkgs.img"
	pkgsMount           = "/persist/pkgs"
	servicesDir         = "/persist/eve-services"
	containerdSock      = "/run/containerd/containerd.sock"
	containerdNamespace = "services.linuxkit"
	scanInterval        = 30 * time.Second
)

type externalServicesContext struct {
	agentbase.AgentBase
	ps               *pubsub.PubSub
	subGlobalConfig  pubsub.Subscription
	pkgsImgPath      string
	pkgsImgMounted   bool
	servicesStarted  map[string]bool
	containerdClient *containerd.Client
	ctx              context.Context
}

var logger *logrus.Logger
var log *base.LogObject

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
	}

	log.Functionf("Initializing agent base")
	agentbase.Init(ctx, logger, log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithWatchdog(ps, warningTime, errorTime),
		agentbase.WithArguments(arguments))

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

	// Start periodic scan for pkgs.img
	log.Noticef("Starting periodic scan for pkgs.img (interval: %s)", scanInterval)
	go scanForPkgsImg(ctx)

	log.Noticef("%s initial setup complete - entering main loop", agentName)

	// Run forever
	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		}
	}
}

// scanForPkgsImg periodically scans for pkgs.img on available disks
func scanForPkgsImg(ctx *externalServicesContext) {
	log.Noticef("scanForPkgsImg goroutine started")
	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()

	// Try immediately on startup
	log.Functionf("Running initial scan for pkgs.img")
	ctx.ps.StillRunning(agentName, warningTime, errorTime)
	tryMountAndStartServices(ctx)

	scanCount := 1
	for range ticker.C {
		scanCount++
		log.Functionf("Periodic scan #%d for pkgs.img", scanCount)
		ctx.ps.StillRunning(agentName, warningTime, errorTime)
		if ctx.pkgsImgMounted {
			log.Functionf("pkgs.img already mounted, verifying services")
			// Already mounted, verify services are running
			verifyServices(ctx)
		} else {
			log.Functionf("pkgs.img not yet mounted, attempting to find and mount")
			// Try to find and mount pkgs.img
			tryMountAndStartServices(ctx)
		}
	}
}

// tryMountAndStartServices searches for pkgs.img and starts services
func tryMountAndStartServices(ctx *externalServicesContext) {
	log.Functionf("tryMountAndStartServices: Checking if already mounted")
	if ctx.pkgsImgMounted {
		log.Functionf("pkgs.img already mounted, skipping")
		return
	}

	// Touch watchdog before starting potentially long operation
	ctx.ps.StillRunning(agentName, warningTime, errorTime)

	// Search for pkgs.img on all block devices
	log.Functionf("Searching for pkgs.img on available disks...")
	pkgsImgPath := findPkgsImg()
	if pkgsImgPath == "" {
		log.Warnf("pkgs.img not found on any disk")
		log.Warnf("Searched locations: /persist/pkgs.img, /mnt/pkgs-disk/pkgs.img, and all /dev/sd* devices")
		log.Warnf("To use external services, ensure pkgs.img is available at /persist/pkgs.img")
		log.Warnf("Will retry in %s...", scanInterval)
		return
	}

	log.Noticef("✓ Found pkgs.img at %s", pkgsImgPath)
	ctx.pkgsImgPath = pkgsImgPath

	// Touch watchdog before mount
	ctx.ps.StillRunning(agentName, warningTime, errorTime)

	// Mount pkgs.img
	log.Functionf("Attempting to mount pkgs.img...")
	if err := mountPkgsImg(pkgsImgPath); err != nil {
		log.Errorf("Failed to mount pkgs.img: %v", err)
		return
	}

	ctx.pkgsImgMounted = true
	log.Noticef("✓ Mounted pkgs.img at %s", pkgsMount)

	// Touch watchdog before starting services
	ctx.ps.StillRunning(agentName, warningTime, errorTime)

	// Start all services
	log.Noticef("Starting all services from pkgs.img...")
	if err := startAllServices(ctx); err != nil {
		log.Errorf("Failed to start services: %v", err)
	} else {
		log.Noticef("✓ All services started successfully")
	}
}

// findPkgsImg searches for pkgs.img on all available block devices
func findPkgsImg() string {
	log.Functionf("findPkgsImg: Starting search")

	// Common locations to search
	searchPaths := []string{
		"/persist/" + pkgsImgName,
		"/mnt/pkgs-disk/" + pkgsImgName,
	}

	log.Functionf("Checking common locations first: %v", searchPaths)

	// Also search on all block devices
	log.Functionf("Scanning block devices...")
	blockDevs, err := filepath.Glob("/dev/sd*[0-9]")
	if err == nil {
		log.Functionf("Found %d block devices to scan", len(blockDevs))
		for _, dev := range blockDevs {
			log.Functionf("Checking device: %s", dev)
			// Try mounting temporarily to check for pkgs.img
			tmpMount := "/tmp/check-pkgs-" + filepath.Base(dev)
			os.MkdirAll(tmpMount, 0755)

			// Use mount command (like install-pkgs-img.sh) instead of syscall.Mount
			// This works with VVFAT and other special filesystems
			cmd := exec.Command("mount", "-o", "ro", dev, tmpMount)
			if err := cmd.Run(); err == nil {
				log.Functionf("Mounted %s to %s, checking for pkgs.img", dev, tmpMount)

				// Check if pkgs.img exists directly in the mount point
				pkgsPath := filepath.Join(tmpMount, pkgsImgName)
				if stat, err := os.Stat(pkgsPath); err == nil && !stat.IsDir() {
					log.Noticef("✓ Found pkgs.img on device %s at %s", dev, pkgsPath)

					// Copy to /persist before unmounting
					destPath := "/persist/" + pkgsImgName
					log.Functionf("Copying pkgs.img from %s to %s...", pkgsPath, destPath)
					if err := copyFile(pkgsPath, destPath); err == nil {
						log.Noticef("✓ Copied pkgs.img from %s to %s", dev, destPath)
						exec.Command("umount", tmpMount).Run()
						os.RemoveAll(tmpMount)
						searchPaths = append([]string{destPath}, searchPaths...)
						break // Found it, no need to check other devices
					} else {
						log.Errorf("Failed to copy pkgs.img: %v", err)
					}
				} else {
					log.Functionf("pkgs.img not found at %s, checking subdirectories...", pkgsPath)

					// List what's actually in the mounted directory
					entries, err := os.ReadDir(tmpMount)
					if err == nil {
						log.Functionf("Contents of %s:", tmpMount)
						for _, entry := range entries {
							log.Functionf("  - %s (dir=%v)", entry.Name(), entry.IsDir())
						}
					}

					log.Functionf("pkgs.img not found on %s", dev)
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

	// Check each path
	log.Functionf("Checking final search paths...")
	for _, path := range searchPaths {
		log.Functionf("Checking: %s", path)
		if _, err := os.Stat(path); err == nil {
			log.Noticef("✓ pkgs.img found at: %s", path)
			return path
		}
	}

	log.Functionf("pkgs.img not found in any location")
	return ""
}

// mountPkgsImg mounts the pkgs.img file
func mountPkgsImg(imgPath string) error {
	// Check if already mounted
	mounts, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return err
	}
	if strings.Contains(string(mounts), pkgsMount) {
		log.Functionf("pkgs.img already mounted")
		return nil
	}

	// Create mount point
	if err := os.MkdirAll(pkgsMount, 0755); err != nil {
		return err
	}

	// Mount using mount command (works better than syscall.Mount for loop devices)
	cmd := exec.Command("mount", "-o", "loop,ro", imgPath, pkgsMount)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("mount failed: %w", err)
	}

	return nil
}

// startAllServices starts all services found in pkgs.img
func startAllServices(ctx *externalServicesContext) error {
	log.Functionf("startAllServices: Entry")

	if ctx.containerdClient == nil {
		log.Errorf("startAllServices: containerd client not available!")
		return fmt.Errorf("containerd client not available")
	}

	servicesPath := filepath.Join(pkgsMount, "containers/services")
	log.Functionf("Reading services from: %s", servicesPath)

	entries, err := os.ReadDir(servicesPath)
	if err != nil {
		log.Errorf("Failed to read services directory %s: %v", servicesPath, err)
		return fmt.Errorf("failed to read services directory: %w", err)
	}

	log.Noticef("Found %d entries in services directory", len(entries))

	serviceCount := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			log.Functionf("Skipping non-directory entry: %s", entry.Name())
			continue
		}

		serviceName := entry.Name()
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
	if container, err := ctx.containerdClient.LoadContainer(ctx.ctx, name); err == nil {
		log.Functionf("[%s] Found existing container, cleaning up...", name)
		if task, err := container.Task(ctx.ctx, nil); err == nil {
			log.Functionf("[%s] Killing existing task...", name)
			task.Kill(ctx.ctx, syscall.SIGKILL)
			task.Delete(ctx.ctx)
		}
		container.Delete(ctx.ctx, containerd.WithSnapshotCleanup)
		log.Functionf("[%s] ✓ Existing container cleaned up", name)
	} else {
		log.Functionf("[%s] No existing container found", name)
	}

	// Create container with containerd API
	log.Functionf("[%s] Creating container with containerd API...", name)
	container, err := ctx.containerdClient.NewContainer(ctx.ctx, name,
		containerd.WithSpec(spec),
	)
	if err != nil {
		log.Errorf("[%s] Failed to create container: %v", name, err)
		return fmt.Errorf("create container: %w", err)
	}
	log.Functionf("[%s] ✓ Container created", name)

	// Create task
	logPath := filepath.Join("/var/log", name+".log")
	log.Functionf("[%s] Creating task with log file: %s", name, logPath)

	task, err := container.NewTask(ctx.ctx, cio.LogFile(logPath))
	if err != nil {
		log.Errorf("[%s] Failed to create task: %v", name, err)
		container.Delete(ctx.ctx)
		return fmt.Errorf("create task: %w", err)
	}
	log.Functionf("[%s] ✓ Task created", name)

	// Start task
	log.Functionf("[%s] Starting task...", name)
	if err := task.Start(ctx.ctx); err != nil {
		log.Errorf("[%s] Failed to start task: %v", name, err)
		task.Delete(ctx.ctx)
		container.Delete(ctx.ctx)
		return fmt.Errorf("start task: %w", err)
	}

	log.Noticef("[%s] ✓✓✓ Service started successfully! ✓✓✓", name)
	return nil
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
		log.Functionf("[%s] Verifying service status...", serviceName)

		container, err := ctx.containerdClient.LoadContainer(ctx.ctx, serviceName)
		if err != nil {
			log.Warnf("[%s] Service container not found, restarting", serviceName)
			servicePath := filepath.Join(pkgsMount, "containers/services", serviceName)
			if err := startService(ctx, serviceName, servicePath); err != nil {
				log.Errorf("[%s] Failed to restart: %v", serviceName, err)
			}
			continue
		}

		// Check if task is running
		task, err := container.Task(ctx.ctx, nil)
		if err != nil {
			log.Warnf("[%s] Task not found, restarting service", serviceName)
			servicePath := filepath.Join(pkgsMount, "containers/services", serviceName)
			if err := startService(ctx, serviceName, servicePath); err != nil {
				log.Errorf("[%s] Failed to restart: %v", serviceName, err)
			}
		} else {
			// Check task status
			status, err := task.Status(ctx.ctx)
			if err != nil || status.Status != containerd.Running {
				log.Warnf("[%s] Task not running (status=%v), restarting", serviceName, status.Status)
				servicePath := filepath.Join(pkgsMount, "containers/services", serviceName)
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
