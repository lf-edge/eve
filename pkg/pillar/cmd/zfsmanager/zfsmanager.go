// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zfsmanager

import (
	"flag"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
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
)

var (
	debug         bool
	debugOverride bool
	logger        *logrus.Logger
	log           *base.LogObject
)

type zVolDeviceEvent struct {
	delete  bool
	device  string
	dataset string
}

type zfsContext struct {
	ps                     *pubsub.PubSub
	zVolStatusPub          pubsub.Publication
	storageStatusPub       pubsub.Publication
	subDisksConfig         pubsub.Subscription
	subVolumeStatus        pubsub.Subscription
	subAppInstanceStatus   pubsub.Subscription
	subSnapshotConfig      pubsub.Subscription
	pubSnapshotStatus      pubsub.Publication
	disksProcessingTrigger chan interface{}
}

// Run - an zfs run
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject) int {
	logger = loggerArg
	log = logArg
	debugPtr := flag.Bool("d", false, "Debug flag")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
		log.Fatal(err)
	}

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(stillRunningInterval)
	ps.StillRunning(agentName, warningTime, errorTime)

	ctxPtr := zfsContext{ps: ps, disksProcessingTrigger: make(chan interface{}, 1)}

	if err := utils.WaitForVault(ps, log, agentName, warningTime, errorTime); err != nil {
		log.Fatal(err)
	}
	log.Functionf("processed Vault Status")

	// Publish cloud metrics
	zVolStatusPub, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			TopicType:  types.ZVolStatus{},
			Persistent: true,
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

	// Publish cloud metrics
	pubSnapshotStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			TopicType:  types.ZfsSnapshotStatus{},
			Persistent: true,
		})
	if err != nil {
		log.Fatal(err)
	}
	ctxPtr.pubSnapshotStatus = pubSnapshotStatus

	// Look for subSnapshotStatus
	subSnapshotConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ZfsSnapshotConfig{},
		Activate:      false,
		Persistent:    true,
		Ctx:           &ctxPtr,
		CreateHandler: handleSnapshotConfigCreate,
		ModifyHandler: handleSnapshotConfigModify,
		DeleteHandler: handleSnapshotConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctxPtr.subSnapshotConfig = subSnapshotConfig
	subSnapshotConfig.Activate()

	// Look for VolumeStatus from volumemgr
	subVolumeStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "volumemgr",
		MyAgentName:   agentName,
		AgentScope:    types.AppImgObj,
		TopicImpl:     types.VolumeStatus{},
		CreateHandler: handleVolumeStatusCreate,
		ModifyHandler: handleVolumeStatusModify,
		DeleteHandler: handleVolumeStatusDelete,
		Activate:      false,
		Ctx:           &ctxPtr,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctxPtr.subVolumeStatus = subVolumeStatus
	subVolumeStatus.Activate()

	// Look for AppInstanceStatus from zedmanager
	subAppInstanceStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedmanager",
		MyAgentName: agentName,
		TopicImpl:   types.AppInstanceStatus{},
		Activate:    false,
		Ctx:         &ctxPtr,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctxPtr.subAppInstanceStatus = subAppInstanceStatus
	subAppInstanceStatus.Activate()

	// Publish cloud metrics
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

	deviceNotifyChannel := make(chan *zVolDeviceEvent)

	if err := os.MkdirAll(types.ZVolDevicePrefix, os.ModeDir); err != nil {
		log.Fatal(err)
	}

	go processDisksTask(&ctxPtr)

	go deviceWatcher(deviceNotifyChannel)

	go storageStatusPublisher(&ctxPtr)

	for {
		select {
		case event := <-deviceNotifyChannel:
			processEvent(&ctxPtr, event)
		case change := <-subDisksConfig.MsgChan():
			subDisksConfig.ProcessChange(change)
		case change := <-subSnapshotConfig.MsgChan():
			subSnapshotConfig.ProcessChange(change)
		case change := <-subVolumeStatus.MsgChan():
			subVolumeStatus.ProcessChange(change)
		case <-stillRunning.C:
			snapshotPropertiesFill(&ctxPtr)
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

func processEvent(ctxPtr *zfsContext, event *zVolDeviceEvent) {
	if event == nil {
		return
	}
	log.Functionf("processEvent: %+v", event)
	if event.delete {
		ctxPtr.zVolStatusPub.Unpublish(event.device)
		return
	}
	ctxPtr.zVolStatusPub.Publish(event.device,
		types.ZVolStatus{
			Device:  event.device,
			Dataset: event.dataset,
		},
	)
}

func deviceWatcher(notifyChannel chan *zVolDeviceEvent) {
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
					notifyChannel <- &zVolDeviceEvent{
						delete:  false,
						device:  walkPath,
						dataset: dataset,
					}
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
			notifyChannel <- &zVolDeviceEvent{
				delete:  false,
				device:  fileName,
				dataset: dataset,
			}
		} else if event.Op&fsnotify.Remove != 0 {
			_ = w.Remove(fileName)
			notifyChannel <- &zVolDeviceEvent{
				delete: true,
				device: fileName,
			}
		}
	}
}
