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
	subDeviceNetworkStatus  pubsub.Subscription
	subAppImgConfig         pubsub.Subscription
	pubAppImgStatus         pubsub.Publication
	subBaseOsConfig         pubsub.Subscription
	pubBaseOsStatus         pubsub.Publication
	subCertObjConfig        pubsub.Subscription
	pubCertObjStatus        pubsub.Publication
	subGlobalDownloadConfig pubsub.Subscription
	pubGlobalDownloadStatus pubsub.Publication
	pubCipherBlockStatus    pubsub.Publication
	subDatastoreConfig      pubsub.Subscription
	deviceNetworkStatus     types.DeviceNetworkStatus
	globalConfig            types.GlobalDownloadConfig
	globalStatusLock        sync.Mutex
	globalStatus            types.GlobalDownloadStatus
	subGlobalConfig         pubsub.Subscription
	GCInitialized           bool
}

func (ctx *downloaderContext) registerHandlers(ps *pubsub.PubSub) error {
	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler: handleGlobalConfigModify,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		TopicImpl:     types.GlobalConfig{},
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
	// before any download config ( App/baseos/cert). Without DataStore Config,
	// Image Downloads will run into errors.
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
	pubAppImgStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		AgentScope: types.AppImgObj,
		TopicType:  types.DownloaderStatus{},
	})
	if err != nil {
		return err
	}
	ctx.pubAppImgStatus = pubAppImgStatus
	pubAppImgStatus.ClearRestarted()

	pubBaseOsStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		AgentScope: types.BaseOsObj,
		TopicType:  types.DownloaderStatus{},
	})
	if err != nil {
		return err
	}
	ctx.pubBaseOsStatus = pubBaseOsStatus
	pubBaseOsStatus.ClearRestarted()

	pubCertObjStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		AgentScope: types.CertObj,
		TopicType:  types.DownloaderStatus{},
	})
	if err != nil {
		return err
	}
	ctx.pubCertObjStatus = pubCertObjStatus
	pubCertObjStatus.ClearRestarted()

	subAppImgConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler: handleAppImgCreate,
		ModifyHandler: handleAppImgModify,
		DeleteHandler: handleAppImgDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		AgentName:     "zedmanager",
		AgentScope:    types.AppImgObj,
		TopicImpl:     types.DownloaderConfig{},
		Ctx:           ctx,
	})
	if err != nil {
		return err
	}
	ctx.subAppImgConfig = subAppImgConfig
	subAppImgConfig.Activate()

	subBaseOsConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler: handleBaseOsCreate,
		ModifyHandler: handleBaseOsModify,
		DeleteHandler: handleBaseOsDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		AgentName:     "baseosmgr",
		AgentScope:    types.BaseOsObj,
		TopicImpl:     types.DownloaderConfig{},
		Ctx:           ctx,
	})
	if err != nil {
		return err
	}
	ctx.subBaseOsConfig = subBaseOsConfig
	subBaseOsConfig.Activate()

	subCertObjConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler: handleCertObjCreate,
		ModifyHandler: handleCertObjModify,
		DeleteHandler: handleCertObjDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		AgentName:     "baseosmgr",
		AgentScope:    types.CertObj,
		TopicImpl:     types.DownloaderConfig{},
		Ctx:           ctx,
	})
	if err != nil {
		return err
	}
	ctx.subCertObjConfig = subCertObjConfig
	subCertObjConfig.Activate()

	pubAppImgStatus.SignalRestarted()
	pubBaseOsStatus.SignalRestarted()
	pubCertObjStatus.SignalRestarted()

	return nil
}

func (ctx *downloaderContext) subscription(objType string) pubsub.Subscription {
	var sub pubsub.Subscription
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

func (ctx *downloaderContext) publication(objType string) pubsub.Publication {
	var pub pubsub.Publication
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
