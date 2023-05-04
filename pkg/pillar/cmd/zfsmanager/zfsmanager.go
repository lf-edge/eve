// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zfsmanager

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
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
	delete  bool
	dataset string
}

type zfsContext struct {
	agentbase.AgentBase
	ps                     *pubsub.PubSub
	zVolStatusPub          pubsub.Publication
	storageStatusPub       pubsub.Publication
	storageMetricsPub      pubsub.Publication
	subDisksConfig         pubsub.Subscription
	subVolumeStatus        pubsub.Subscription
	disksProcessingTrigger chan interface{}
	zVolDeviceEvents       *base.LockedStringMap // stores device->zVolDeviceEvent mapping to check and publish
	zfsIterLock            sync.Mutex
}

// Run - an zfs run
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string) int {
	logger = loggerArg
	log = logArg

	ctxPtr := zfsContext{
		ps:                     ps,
		disksProcessingTrigger: make(chan interface{}, 1),
		zVolDeviceEvents:       base.NewLockedStringMap(),
	}
	agentbase.Init(&ctxPtr, logger, log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithWatchdog(ps, warningTime, errorTime),
		agentbase.WithArguments(arguments))

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(stillRunningInterval)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Wait until we have been onboarded aka know our own UUID, but we don't use the UUID
	err := utils.WaitForOnboarded(ps, log, agentName, warningTime, errorTime)
	if err != nil {
		log.Fatal(err)
	}
	log.Functionf("processed onboarded")

	if err := utils.WaitForVault(ps, log, agentName, warningTime, errorTime); err != nil {
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

	// Look for disks config
	subDisksConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.EdgeNodeDisks{},
		Activate:      false,
		Ctx:           &ctxPtr,
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
		AgentScope:  types.AppImgObj,
		TopicImpl:   types.VolumeStatus{},
		Activate:    false,
		Ctx:         &ctxPtr,
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

	go processDisksTask(&ctxPtr)

	go deviceWatcher(&ctxPtr)

	go storageStatusPublisher(&ctxPtr)

	go storageMetricsPublisher(&ctxPtr)

	max := float64(zvolsProcessingInterval)
	min := max * 0.3
	devicesProcessTicker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))

	for {
		select {
		case <-devicesProcessTicker.C:
			processZVolDeviceEvents(&ctxPtr)
		case change := <-subDisksConfig.MsgChan():
			subDisksConfig.ProcessChange(change)
		case change := <-subVolumeStatus.MsgChan():
			subVolumeStatus.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

// processZVolDeviceEvents iterates over saved zVolDeviceEvent, check for device existence and publish ZVolStatus
func processZVolDeviceEvents(ctxPtr *zfsContext) {
	var processedKeys []string
	checker := func(key string, val interface{}) bool {
		event, ok := val.(zVolDeviceEvent)
		if !ok {
			log.Fatalf("unexpected type for key: %s", key)
		}
		zvolStatus := types.ZVolStatus{
			Device:  key,
			Dataset: event.dataset,
		}
		if event.delete {
			if el, _ := ctxPtr.zVolStatusPub.Get(zvolStatus.Key()); el == nil {
				processedKeys = append(processedKeys, key)
				return true
			}
			if err := ctxPtr.zVolStatusPub.Unpublish(zvolStatus.Key()); err != nil {
				log.Errorf("cannot unpublish device: %s", err)
				return true
			}
			processedKeys = append(processedKeys, key)
			return true
		}
		l, err := filepath.EvalSymlinks(key)
		if err != nil {
			log.Warnf("failed to EvalSymlinks: %s", err)
			return true
		}
		_, err = os.Stat(l)
		if err != nil {
			log.Warnf("failed to Stat device: %s", err)
			return true
		}

		if err := ctxPtr.zVolStatusPub.Publish(zvolStatus.Key(), zvolStatus); err != nil {
			log.Errorf("cannot publish device: %s", err)
			return true
		}
		processedKeys = append(processedKeys, key)
		return true
	}
	ctxPtr.zVolDeviceEvents.Range(checker)
	for _, key := range processedKeys {
		ctxPtr.zVolDeviceEvents.Delete(key)
	}
}

func deviceWatcher(ctxPtr *zfsContext) {
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
					ctxPtr.zVolDeviceEvents.Store(walkPath, zVolDeviceEvent{
						dataset: dataset,
					})
				}
			}
			return nil
		})
	}

	if err := processRecursive(types.ZVolDevicePrefix); err != nil {
		log.Errorf("Failed to Walk in %s: %s", types.ZVolDevicePrefix, err)
	}

	for event := range w.Events {
		log.Functionf("deviceWatcher: %+v", event)
		fileName := event.Name
		s, err := os.Stat(fileName)
		if err == nil && s != nil && s.IsDir() {
			if event.Op&fsnotify.Create != 0 {
				if err := processRecursive(fileName); err != nil {
					log.Errorf("Failed to Walk in %s: %s", fileName, err)
				}
			}
			continue
		}
		if event.Op&fsnotify.Create != 0 {
			dataset := zfs.GetDatasetByDevice(fileName)
			if dataset == "" {
				log.Errorf("cannot determine dataset for device: %s", fileName)
				continue
			}
			ctxPtr.zVolDeviceEvents.Store(fileName, zVolDeviceEvent{
				dataset: dataset,
			})
		} else if event.Op&fsnotify.Remove != 0 {
			ctxPtr.zVolDeviceEvents.Store(fileName, zVolDeviceEvent{
				delete: true,
			})
		}
	}
}
