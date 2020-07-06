// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"sync"

	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedUpload"
	log "github.com/sirupsen/logrus"
)

type downloaderContext struct {
	decryptCipherContext        cipher.DecryptCipherContext
	dCtx                        *zedUpload.DronaCtx
	subDeviceNetworkStatus      pubsub.Subscription
	subDownloaderConfig         pubsub.Subscription
	pubDownloaderStatus         pubsub.Publication
	subContentTreeResolveConfig pubsub.Subscription
	pubContentTreeResolveStatus pubsub.Publication
	subGlobalDownloadConfig     pubsub.Subscription
	pubGlobalDownloadStatus     pubsub.Publication
	pubCipherBlockStatus        pubsub.Publication
	subDatastoreConfig          pubsub.Subscription
	deviceNetworkStatus         types.DeviceNetworkStatus
	globalConfig                types.GlobalDownloadConfig
	globalStatusLock            sync.Mutex
	globalStatus                types.GlobalDownloadStatus
	subGlobalConfig             pubsub.Subscription
	GCInitialized               bool
}

func (ctx *downloaderContext) registerHandlers(ps *pubsub.PubSub) error {
	// Look for controller certs which will be used for decryption
	subControllerCert, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		TopicImpl:   types.ControllerCert{},
		Activate:    false,
		Ctx:         ctx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
		Persistent:  true,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.decryptCipherContext.SubControllerCert = subControllerCert
	subControllerCert.Activate()

	// Look for edge node certs which will be used for decryption
	subEdgeNodeCert, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "tpmmgr",
		TopicImpl:   types.EdgeNodeCert{},
		Activate:    false,
		Ctx:         ctx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.decryptCipherContext.SubEdgeNodeCert = subEdgeNodeCert
	subEdgeNodeCert.Activate()

	// Look for cipher context which will be used for decryption
	subCipherContext, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		TopicImpl:   types.CipherContext{},
		Activate:    false,
		Ctx:         ctx,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
		Persistent:  true,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.decryptCipherContext.SubCipherContext = subCipherContext
	subCipherContext.Activate()

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler: handleGlobalConfigModify,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		TopicImpl:     types.ConfigItemValueMap{},
		Ctx:           ctx,
	})
	if err != nil {
		return err
	}
	ctx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	subDeviceNetworkStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler: handleDNSModify,
		ModifyHandler: handleDNSModify,
		DeleteHandler: handleDNSDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		TopicImpl:     types.DeviceNetworkStatus{},
		Ctx:           ctx,
		AgentName:     "nim",
	})
	if err != nil {
		return err
	}
	ctx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	subGlobalDownloadConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler: handleGlobalDownloadConfigModify,
		ModifyHandler: handleGlobalDownloadConfigModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		Ctx:           ctx,
		TopicImpl:     types.GlobalDownloadConfig{},
	})
	if err != nil {
		return err
	}
	ctx.subGlobalDownloadConfig = subGlobalDownloadConfig
	subGlobalDownloadConfig.Activate()

	// Look for DatastoreConfig. We should process this
	// before any download config. Without DataStore Config,
	// Image Downloads will run into errors, which requires retries
	subDatastoreConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler: handleDatastoreConfigModify,
		ModifyHandler: handleDatastoreConfigModify,
		DeleteHandler: handleDatastoreConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		AgentName:     "zedagent",
		TopicImpl:     types.DatastoreConfig{},
		Ctx:           ctx,
	})
	if err != nil {
		return err
	}
	ctx.subDatastoreConfig = subDatastoreConfig
	subDatastoreConfig.Activate()

	pubCipherBlockStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.CipherBlockStatus{},
	})
	if err != nil {
		return err
	}
	ctx.pubCipherBlockStatus = pubCipherBlockStatus

	pubGlobalDownloadStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.GlobalDownloadStatus{},
	})
	if err != nil {
		return err
	}
	ctx.pubGlobalDownloadStatus = pubGlobalDownloadStatus

	// Set up our publications before the subscriptions so ctx is set
	pubDownloaderStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.DownloaderStatus{},
	})
	if err != nil {
		return err
	}
	ctx.pubDownloaderStatus = pubDownloaderStatus

	pubContentTreeResolveStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.ResolveStatus{},
	})
	if err != nil {
		return err
	}
	ctx.pubContentTreeResolveStatus = pubContentTreeResolveStatus

	subDownloaderConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler: handleDownloaderConfigCreate,
		ModifyHandler: handleDownloaderConfigModify,
		DeleteHandler: handleDownloaderConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		AgentName:     "volumemgr",
		TopicImpl:     types.DownloaderConfig{},
		Ctx:           ctx,
	})
	if err != nil {
		return err
	}
	ctx.subDownloaderConfig = subDownloaderConfig
	subDownloaderConfig.Activate()

	subContentTreeResolveConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler: handleContentTreeResolveModify,
		ModifyHandler: handleContentTreeResolveModify,
		DeleteHandler: handleContentTreeResolveDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		AgentName:     "volumemgr",
		TopicImpl:     types.ResolveConfig{},
		Ctx:           ctx,
	})
	if err != nil {
		return err
	}
	ctx.subContentTreeResolveConfig = subContentTreeResolveConfig
	subContentTreeResolveConfig.Activate()

	pubDownloaderStatus.SignalRestarted()
	pubContentTreeResolveStatus.SignalRestarted()

	return nil
}
