package downloader

import (
	"sync"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedUpload"
	log "github.com/sirupsen/logrus"
)

type downloaderContext struct {
	dCtx                    *zedUpload.DronaCtx
	subDeviceNetworkStatus  *pubsub.Subscription
	subAppImgConfig         *pubsub.Subscription
	pubAppImgStatus         *pubsub.Publication
	subBaseOsConfig         *pubsub.Subscription
	pubBaseOsStatus         *pubsub.Publication
	subCertObjConfig        *pubsub.Subscription
	pubCertObjStatus        *pubsub.Publication
	subGlobalDownloadConfig *pubsub.Subscription
	pubGlobalDownloadStatus *pubsub.Publication
	subDatastoreConfig      *pubsub.Subscription
	deviceNetworkStatus     types.DeviceNetworkStatus
	globalConfig            types.GlobalDownloadConfig
	globalStatusLock        sync.Mutex
	globalStatus            types.GlobalDownloadStatus
	subGlobalConfig         *pubsub.Subscription
}

func (ctx *downloaderContext) registerHandlers() error {
	// Look for global config such as log levels
	subGlobalConfig, err := pubsub.Subscribe("", types.GlobalConfig{},
		false, &ctx)
	if err != nil {
		return err
	}
	subGlobalConfig.ModifyHandler = handleGlobalConfigModify
	subGlobalConfig.CreateHandler = handleGlobalConfigModify
	subGlobalConfig.DeleteHandler = handleGlobalConfigDelete
	ctx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	subDeviceNetworkStatus, err := pubsub.Subscribe("nim",
		types.DeviceNetworkStatus{}, false, &ctx)
	if err != nil {
		return err
	}
	subDeviceNetworkStatus.ModifyHandler = handleDNSModify
	subDeviceNetworkStatus.CreateHandler = handleDNSModify
	subDeviceNetworkStatus.DeleteHandler = handleDNSDelete
	ctx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	subGlobalDownloadConfig, err := pubsub.Subscribe("",
		types.GlobalDownloadConfig{}, false, &ctx)
	if err != nil {
		return err
	}
	subGlobalDownloadConfig.ModifyHandler = handleGlobalDownloadConfigModify
	subGlobalDownloadConfig.CreateHandler = handleGlobalDownloadConfigModify
	ctx.subGlobalDownloadConfig = subGlobalDownloadConfig
	subGlobalDownloadConfig.Activate()

	// Look for DatastoreConfig. We should process this
	// before any download config ( App/baseos/cert). Without DataStore Config,
	// Image Downloads will run into errors.
	subDatastoreConfig, err := pubsub.Subscribe("zedagent",
		types.DatastoreConfig{}, false, &ctx)
	if err != nil {
		return err
	}
	subDatastoreConfig.ModifyHandler = handleDatastoreConfigModify
	subDatastoreConfig.CreateHandler = handleDatastoreConfigModify
	subDatastoreConfig.DeleteHandler = handleDatastoreConfigDelete
	ctx.subDatastoreConfig = subDatastoreConfig
	subDatastoreConfig.Activate()

	pubGlobalDownloadStatus, err := pubsub.Publish(agentName,
		types.GlobalDownloadStatus{})
	if err != nil {
		return err
	}
	ctx.pubGlobalDownloadStatus = pubGlobalDownloadStatus

	// Set up our publications before the subscriptions so ctx is set
	pubAppImgStatus, err := pubsub.PublishScope(agentName, types.AppImgObj,
		types.DownloaderStatus{})
	if err != nil {
		return err
	}
	ctx.pubAppImgStatus = pubAppImgStatus
	pubAppImgStatus.ClearRestarted()

	pubBaseOsStatus, err := pubsub.PublishScope(agentName, types.BaseOsObj,
		types.DownloaderStatus{})
	if err != nil {
		return err
	}
	ctx.pubBaseOsStatus = pubBaseOsStatus
	pubBaseOsStatus.ClearRestarted()

	pubCertObjStatus, err := pubsub.PublishScope(agentName, types.CertObj,
		types.DownloaderStatus{})
	if err != nil {
		return err
	}
	ctx.pubCertObjStatus = pubCertObjStatus
	pubCertObjStatus.ClearRestarted()

	subAppImgConfig, err := pubsub.SubscribeScope("zedmanager",
		types.AppImgObj, types.DownloaderConfig{}, false, &ctx)
	if err != nil {
		return err
	}
	subAppImgConfig.ModifyHandler = handleAppImgModify
	subAppImgConfig.CreateHandler = handleAppImgCreate
	subAppImgConfig.DeleteHandler = handleAppImgDelete
	ctx.subAppImgConfig = subAppImgConfig
	subAppImgConfig.Activate()

	subBaseOsConfig, err := pubsub.SubscribeScope("baseosmgr",
		types.BaseOsObj, types.DownloaderConfig{}, false, &ctx)
	if err != nil {
		return err
	}
	subBaseOsConfig.ModifyHandler = handleBaseOsModify
	subBaseOsConfig.CreateHandler = handleBaseOsCreate
	subBaseOsConfig.DeleteHandler = handleBaseOsDelete
	ctx.subBaseOsConfig = subBaseOsConfig
	subBaseOsConfig.Activate()

	subCertObjConfig, err := pubsub.SubscribeScope("baseosmgr",
		types.CertObj, types.DownloaderConfig{}, false, &ctx)
	if err != nil {
		return err
	}
	subCertObjConfig.ModifyHandler = handleCertObjModify
	subCertObjConfig.CreateHandler = handleCertObjCreate
	subCertObjConfig.DeleteHandler = handleCertObjDelete
	ctx.subCertObjConfig = subCertObjConfig
	subCertObjConfig.Activate()

	pubAppImgStatus.SignalRestarted()
	pubBaseOsStatus.SignalRestarted()
	pubCertObjStatus.SignalRestarted()

	return nil
}

func (ctx *downloaderContext) subscription(objType string) *pubsub.Subscription {
	var sub *pubsub.Subscription
	switch objType {
	case types.AppImgObj:
		sub = ctx.subAppImgConfig
	case types.BaseOsObj:
		sub = ctx.subBaseOsConfig
	case types.CertObj:
		sub = ctx.subCertObjConfig
	default:
		log.Fatalf("downloaderSubscription: Unknown ObjType %s\n",
			objType)
	}
	return sub
}

func (ctx *downloaderContext) publication(objType string) *pubsub.Publication {
	var pub *pubsub.Publication
	switch objType {
	case types.AppImgObj:
		pub = ctx.pubAppImgStatus
	case types.BaseOsObj:
		pub = ctx.pubBaseOsStatus
	case types.CertObj:
		pub = ctx.pubCertObjStatus
	default:
		log.Fatalf("downloaderPublication: Unknown ObjType %s\n",
			objType)
	}
	return pub
}
