// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zfsmanager

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/persist"
	"github.com/lf-edge/eve/pkg/pillar/utils/wait"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
	"github.com/sirupsen/logrus"
)

const (
	agentName = "zfsmanager"
	// Time limits for event loop handlers
	errorTime            = 3 * time.Minute
	warningTime          = 40 * time.Second
	stillRunningInterval = 25 * time.Second

	disksProcessingInterval = 60 * time.Second
	zvolsProcessingInterval = 5 * time.Second
)

var (
	logger *logrus.Logger
	log    *base.LogObject
)

type zVolDeviceEvent struct {
	delete bool
}

type zfsContext struct {
	agentbase.AgentBase
	ps                     *pubsub.PubSub
	subGlobalConfig        pubsub.Subscription
	zVolStatusPub          pubsub.Publication
	storageStatusPub       pubsub.Publication
	storageMetricsPub      pubsub.Publication
	subDisksConfig         pubsub.Subscription
	subVolumeStatus        pubsub.Subscription
	disksProcessingTrigger chan interface{}
	zVolDeviceEvents       *base.LockedStringMap // stores device->zVolDeviceEvent mapping to check and publish
	zfsIterLock            sync.Mutex
	globalConfig           *types.ConfigItemValueMap
	GCInitialized          bool
	trimStatus             types.PoolTrimStatus
}

// Run - an zfs run
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int {
	logger = loggerArg
	log = logArg

	ctxPtr := &zfsContext{
		ps:                     ps,
		disksProcessingTrigger: make(chan interface{}, 1),
		zVolDeviceEvents:       base.NewLockedStringMap(),
		globalConfig:           types.DefaultConfigItemValueMap(),
	}
	agentbase.Init(ctxPtr, logger, log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithBaseDir(baseDir),
		agentbase.WithWatchdog(ps, warningTime, errorTime),
		agentbase.WithArguments(arguments))

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(stillRunningInterval)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Wait until we have been onboarded aka know our own UUID, but we don't use the UUID
	_, err := wait.WaitForOnboarded(ps, log, agentName, warningTime, errorTime)
	if err != nil {
		log.Fatal(err)
	}
	log.Functionf("processed onboarded")

	if err := wait.WaitForVault(ps, log, agentName, warningTime, errorTime); err != nil {
		log.Fatal(err)
	}
	log.Functionf("processed Vault Status")

	// Publish ZVolStatus for zvol devices
	zVolStatusPub, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.ZVolStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	ctxPtr.zVolStatusPub = zVolStatusPub

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    false,
		Activate:      false,
		Ctx:           ctxPtr,
		CreateHandler: handleGlobalConfigCreate,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctxPtr.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	// Pick up debug aka log level before we start real work
	for !ctxPtr.GCInitialized {
		log.Functionf("waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Functionf("processed GlobalConfig")

	// Look for disks config
	subDisksConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.EdgeNodeDisks{},
		Activate:      false,
		Ctx:           ctxPtr,
		CreateHandler: handleDisksConfigCreate,
		ModifyHandler: handleDisksConfigModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctxPtr.subDisksConfig = subDisksConfig
	subDisksConfig.Activate()

	// Publish cloud status
	storageStatusPub, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			TopicType:  types.ZFSPoolStatus{},
			Persistent: false,
		})
	if err != nil {
		log.Fatal(err)
	}
	ctxPtr.storageStatusPub = storageStatusPub

	// Publish cloud metrics
	storageMetricsPub, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			TopicType:  types.ZFSPoolMetrics{},
			Persistent: false,
		})
	if err != nil {
		log.Fatal(err)
	}
	ctxPtr.storageMetricsPub = storageMetricsPub

	// Look VolumeStatus from volumemgr to getting zVol metrics
	subVolumeStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "volumemgr",
		MyAgentName: agentName,
		TopicImpl:   types.VolumeStatus{},
		Activate:    false,
		Ctx:         ctxPtr,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctxPtr.subVolumeStatus = subVolumeStatus
	subVolumeStatus.Activate()

	if err := os.MkdirAll(types.ZVolDevicePrefix, os.ModeDir); err != nil {
		log.Fatal(err)
	}

	go processDisksTask(ctxPtr)

	runPoolTrimSchedule(ctxPtr)

	go deviceWatcher(ctxPtr)

	go storageStatusPublisher(ctxPtr)

	go storageMetricsPublisher(ctxPtr)

	max := float64(zvolsProcessingInterval)
	min := max * 0.3
	devicesProcessTicker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case <-devicesProcessTicker.C:
			processZVolDeviceEvents(ctxPtr)
		case change := <-subDisksConfig.MsgChan():
			subDisksConfig.ProcessChange(change)
		case change := <-subVolumeStatus.MsgChan():
			subVolumeStatus.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

// zvolReconcileAction is the outcome decided for a stored zVolDeviceEvent.
type zvolReconcileAction int

const (
	// zvolRetry leaves the event in the map to re-examine on the next tick.
	zvolRetry zvolReconcileAction = iota
	// zvolPublish (re)publishes ZVolStatus and then drops the event.
	zvolPublish
	// zvolUnpublish removes a published ZVolStatus and then drops the event.
	zvolUnpublish
	// zvolDrop discards the event without changing any ZVolStatus.
	zvolDrop
)

// decideZVolAction reconciles a stored device event against reality.
//
// The stored event is only a trigger. fsnotify Create/Remove events are kept
// in a map keyed by device path, so a Remove can overwrite a still-unprocessed
// Create for the same path when a zvol is removed and recreated in quick
// succession (e.g. an app purge that recreates the volume, with mdev churning
// the /dev/zvol symlink). Trusting such a coalesced Remove would leave the
// live device without a ZVolStatus, stranding volumemgr (and the app) forever.
// The actual on-disk presence of the device is therefore authoritative, not
// event.delete: publish whenever the device exists, and only unpublish when it
// is really gone.
func decideZVolAction(event zVolDeviceEvent, devicePresent, statusPublished bool) zvolReconcileAction {
	if devicePresent {
		return zvolPublish
	}
	if !event.delete {
		// Create event but the device has not appeared yet: wait for it.
		return zvolRetry
	}
	if statusPublished {
		return zvolUnpublish
	}
	return zvolDrop
}

// processZVolDeviceEvents iterates over saved zVolDeviceEvent, check for device existence and publish ZVolStatus
func processZVolDeviceEvents(ctxPtr *zfsContext) {
	var processedKeys []string
	checker := func(key string, val interface{}) bool {
		event, ok := val.(zVolDeviceEvent)
		if !ok {
			log.Fatalf("unexpected type for key: %s", key)
		}
		log.Functionf("key %s event %+v", key, event)

		// The device path deterministically maps to its dataset; recompute
		// it because a coalesced Remove event carries an empty dataset and
		// ZVolStatus.Key() (hence publish/unpublish) is derived from it.
		dataset := zfs.GetDatasetByDevice(key)
		if dataset == "" {
			log.Errorf("cannot determine dataset for device: %s", key)
			processedKeys = append(processedKeys, key)
			return true
		}
		zvolStatus := types.ZVolStatus{
			Device:  key,
			Dataset: dataset,
		}

		devicePresent := false
		if l, err := filepath.EvalSymlinks(key); err == nil {
			if _, err := os.Stat(l); err == nil {
				devicePresent = true
			}
		}
		el, _ := ctxPtr.zVolStatusPub.Get(zvolStatus.Key())
		statusPublished := el != nil

		switch decideZVolAction(event, devicePresent, statusPublished) {
		case zvolPublish:
			if err := ctxPtr.zVolStatusPub.Publish(zvolStatus.Key(), zvolStatus); err != nil {
				log.Errorf("cannot publish device: %s", err)
				return true
			}
			log.Functionf("processed add for %s", key)
		case zvolUnpublish:
			if err := ctxPtr.zVolStatusPub.Unpublish(zvolStatus.Key()); err != nil {
				log.Errorf("cannot unpublish device: %s", err)
				return true
			}
			log.Functionf("processed delete for %s", key)
		case zvolRetry:
			log.Warnf("device %s not present yet; will retry", key)
			return true
		case zvolDrop:
			// Nothing to (un)publish; just forget the stale event.
		}
		processedKeys = append(processedKeys, key)
		return true
	}
	ctxPtr.zVolDeviceEvents.Range(checker)
	for _, key := range processedKeys {
		ctxPtr.zVolDeviceEvents.Delete(key)
	}
}

func deviceWatcherLoop(ctxPtr *zfsContext) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("NewWatcher: %s", err)
	}
	defer w.Close()

	processRecursive := func(dir string) error {
		// walk through exist files
		return filepath.Walk(dir, func(walkPath string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.IsDir() {
				return w.Add(walkPath)
			} else {
				// we expect symlinks created by mdev
				if fi.Mode()&os.ModeSymlink != 0 {
					dataset := zfs.GetDatasetByDevice(walkPath)
					if dataset == "" {
						log.Errorf("cannot determine dataset for device: %s", walkPath)
						return nil
					}
					log.Functionf("adding dataset %s", dataset)
					ctxPtr.zVolDeviceEvents.Store(walkPath, zVolDeviceEvent{})
				}
			}
			return nil
		})
	}

	for {
		// Wait for directory to appear if it isn't already there
		waitForDir(types.ZVolDevicePrefix)

		if err := processRecursive(types.ZVolDevicePrefix); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				log.Warnf("Failed to Walk in %s: %s",
					types.ZVolDevicePrefix, err)
				continue
			}
			log.Errorf("Failed to Walk in %s: %s",
				types.ZVolDevicePrefix, err)
		}
		break
	}

	for event := range w.Events {
		log.Functionf("deviceWatcher: %+v", event)
		fileName := event.Name
		s, err := os.Stat(fileName)
		if err == nil && s != nil && s.IsDir() {
			// Make sure we watch recursively if the directory exists
			if event.Op&fsnotify.Create != 0 {
				if err := processRecursive(fileName); err != nil {
					log.Errorf("Failed to Walk in %s: %s", fileName, err)
				}
			}
			// Proceed to handle create and remove
			// Due to timing the Stat might succeed even when
			// processing a remove event.
		}
		if event.Op&fsnotify.Create != 0 {
			dataset := zfs.GetDatasetByDevice(fileName)
			if dataset == "" {
				log.Errorf("cannot determine dataset for device: %s", fileName)
				continue
			}
			ctxPtr.zVolDeviceEvents.Store(fileName, zVolDeviceEvent{})
		} else if event.Op&fsnotify.Remove != 0 {
			if fileName == types.ZVolDevicePrefix {
				// The whole /dev/zvol tree went away; restart the loop to
				// recreate the watcher when it reappears. There is no
				// per-zvol ZVolStatus to reconcile for the root itself.
				break
			}
			ctxPtr.zVolDeviceEvents.Store(fileName, zVolDeviceEvent{delete: true})
		}
	}
}

func deviceWatcher(ctxPtr *zfsContext) {
	for {
		deviceWatcherLoop(ctxPtr)
		log.Noticef("deviceWatcher restarting")
	}
}

// wait for the directory to appear (if it isn't already there) by watching
// for create in the parent dir
func waitForDir(dir string) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("NewWatcher: %s", err)
	}
	defer w.Close()
	// Robust parentdir whether or not dir has a trailing "/"
	parentDir := filepath.Dir(strings.TrimSuffix(dir, "/"))
	if err := w.Add(parentDir); err != nil {
		log.Fatalf("w.Add: %s", err)
	}

	// Does it already exist?
	_, err = os.Stat(dir)
	if err == nil {
		log.Functionf("no need to wait for %s", dir)
		return
	}
	start := time.Now()
	log.Functionf("wait for %s to appear", dir)

	for event := range w.Events {
		if event.Op&fsnotify.Create != 0 {
			log.Functionf("waitForDir: CREATE %s", event.Name)
			if event.Name == dir {
				log.Functionf("waited for %v for %s",
					time.Since(start), dir)
				return
			}
		} else if event.Op&fsnotify.Remove != 0 {
			log.Functionf("waitForDir: REMOVE %s", event.Name)
		}
	}
}

func handleGlobalConfigCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zfsContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s", key)
	gcp := agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	if gcp != nil {
		maybeUpdateConfigItems(ctx, gcp)
		ctx.globalConfig = gcp
		ctx.GCInitialized = true
	}
	log.Functionf("handleGlobalConfigImpl done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zfsContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigDelete for %s", key)
	agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	*ctx.globalConfig = *types.DefaultConfigItemValueMap()
	log.Functionf("handleGlobalConfigDelete done for %s", key)
}

func maybeUpdateConfigItems(ctx *zfsContext, newConfigItemValueMap *types.ConfigItemValueMap) {
	log.Functionf("maybeUpdateConfigItems")
	oldConfigItemValueMap := ctx.globalConfig

	if persist.ReadPersistType() != types.PersistZFS {
		return
	}
	newStorageZfsReserved := newConfigItemValueMap.GlobalValueInt(types.StorageZfsReserved)
	oldStorageZfsReserved := oldConfigItemValueMap.GlobalValueInt(types.StorageZfsReserved)
	if oldStorageZfsReserved != newStorageZfsReserved {
		log.Noticef("StorageZfsReserved changed from %d to %d",
			oldStorageZfsReserved, newStorageZfsReserved)
		err := zfs.SetReserved(types.PersistDataset,
			uint64(newStorageZfsReserved))
		if err != nil {
			log.Errorf("SetReserved failed: %s", err)
		}
	}
}
