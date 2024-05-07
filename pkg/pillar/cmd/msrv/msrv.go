// Copyright (c) 2020-2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Medatada server (msrv) creates an HTTP handler which is used by Zedrouter
// to create server exposed to App Instances to get information, i.e. network
// parameters and download patch envelopes.
// You can think of metadata server as a translator from pubsub to REST API for
// Application Instances

package msrv

import (
	"bytes"
	"context"
	"encoding/gob"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/persistcache"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	"github.com/sirupsen/logrus"
)

const (
	agentName    = "msrv"
	errorTime    = 60 * time.Second
	warningTime  = 40 * time.Second
	stillRunTime = 25 * time.Second
	// Publish 4X more often than zedagent publishes to controller
	// to reduce effect of quantization errors
	publishTickerDivider = 4
)

// Really a constant
var nilUUID uuid.UUID

// KubeconfigFileSizeLimitInBytes holds the maximum expected size of Kubeconfig file
// received from k3s server appInst.
// Note: KubeconfigFileSizeLimitInBytes should always be < AppInstMetadataResponseSizeLimitInBytes.
const KubeconfigFileSizeLimitInBytes = 32768 // 32KB

// AppInstMetadataResponseSizeLimitInBytes holds the maximum expected size of appInst
// metadata received in the response.
// Note: KubeconfigFileSizeLimitInBytes should always be < AppInstMetadataResponseSizeLimitInBytes.
const AppInstMetadataResponseSizeLimitInBytes = 35840 // 35KB

// SignerMaxSize is how large objects we will sign
const SignerMaxSize = 65535

// DiagMaxSize is the max returned size for diag
const DiagMaxSize = 65535

// MetaDataServerIP is IP of meta data server
const MetaDataServerIP = "169.254.169.254"

// Msrv struct contains all PubSubs which are needed to compose REST APIs
// for App Instances
type Msrv struct {
	agentbase.AgentBase
	Log           *base.LogObject
	PubSub        *pubsub.PubSub
	Logger        *logrus.Logger
	gcInitialized bool

	// Ticker for periodic publishing of metrics
	metricInterval uint32 // In seconds
	publishTicker  *flextimer.FlexTickerHandle

	subGlobalConfig pubsub.Subscription

	deviceNetworkStatus *types.DeviceNetworkStatus

	subNetworkInstanceStatus pubsub.Subscription
	subEdgeNodeInfo          pubsub.Subscription

	// Decryption of cloud-init user data
	pubCipherBlockStatus pubsub.Publication

	subControllerCert    pubsub.Subscription
	subEdgeNodeCert      pubsub.Subscription
	decryptCipherContext cipher.DecryptCipherContext

	cipherMetrics *cipher.AgentMetrics

	// Configuration for application interfaces
	subAppNetworkConfig   pubsub.Subscription
	subAppNetworkConfigAg pubsub.Subscription // From zedagent
	subAppInstanceConfig  pubsub.Subscription // From zedagent to cleanup appInstMetadata

	subLocationInfo pubsub.Subscription
	subWwanStatus   pubsub.Subscription
	subWwanMetrics  pubsub.Subscription

	pubAppInstMetaData pubsub.Publication

	subDomainStatus pubsub.Subscription

	subAppNetworkStatus pubsub.Subscription

	// Subscriptions to gather information about
	// patch envelopes from volumemgr and zedagent
	// external envelopes have to be downloaded via
	// volumemgr, therefore we need to be subscribed
	// to volume status to know filepath and download status
	// patchEnvelopeInfo is list of patchEnvelopes which
	// is coming from EdgeDevConfig containing information
	// about inline patch envelopes and volume uuid as reference
	// for external patch envelopes
	subPatchEnvelopeInfo pubsub.Subscription
	subVolumeStatus      pubsub.Subscription
	subContentTreeStatus pubsub.Subscription

	PatchEnvelopes      *PatchEnvelopes
	patchEnvelopesUsage *generics.LockedMap[string, types.PatchEnvelopeUsage]
	peUsagePersist      *persistcache.PersistCache

	pubPatchEnvelopesUsage pubsub.Publication
}

// Run starts up agent
func Run(ps *pubsub.PubSub, logger *logrus.Logger, log *base.LogObject, arguments []string) int {
	msrv := &Msrv{
		Log:    log,
		PubSub: ps,
		Logger: logger,
	}
	agentbase.Init(msrv, logger, log, agentName,
		agentbase.WithArguments(arguments))

	if err := msrv.Init(types.PersistCachePatchEnvelopesUsage); err != nil {
		log.Fatal(err)
	}
	if err := msrv.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
	return 0
}

// Init initializes metadata server
func (msrv *Msrv) Init(cachePath string) (err error) {
	msrv.patchEnvelopesUsage = generics.NewLockedMap[string, types.PatchEnvelopeUsage]()

	if err = msrv.initPublications(); err != nil {
		return err
	}
	if err = msrv.initSubscriptions(); err != nil {
		return err
	}

	msrv.decryptCipherContext.Log = msrv.Log
	msrv.decryptCipherContext.AgentName = agentName
	msrv.decryptCipherContext.AgentMetrics = msrv.cipherMetrics
	msrv.decryptCipherContext.PubSubControllerCert = msrv.subControllerCert
	msrv.decryptCipherContext.PubSubEdgeNodeCert = msrv.subEdgeNodeCert

	msrv.PatchEnvelopes = NewPatchEnvelopes(msrv.Log, msrv.PubSub)
	msrv.patchEnvelopesUsage = generics.NewLockedMap[string, types.PatchEnvelopeUsage]()

	msrv.peUsagePersist, err = persistcache.New(cachePath)
	if err != nil {
		return err
	}

	// restore cached patchEnvelopeUsage counters
	for _, key := range msrv.peUsagePersist.Objects() {
		cached, err := msrv.peUsagePersist.Get(key)
		if err != nil {
			return err
		}
		buf := bytes.NewBuffer(cached)
		dec := gob.NewDecoder(buf)

		var peUsage types.PatchEnvelopeUsage

		if err := dec.Decode(&peUsage); err != nil {
			return err
		}

		msrv.patchEnvelopesUsage.Store(key, peUsage)
	}

	return nil
}

func (msrv *Msrv) initPublications() (err error) {
	msrv.pubAppInstMetaData, err = msrv.PubSub.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			Persistent: true,
			TopicType:  types.AppInstMetaData{},
		},
	)
	if err != nil {
		return err
	}

	msrv.pubPatchEnvelopesUsage, err = msrv.PubSub.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.PatchEnvelopeUsage{},
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (msrv *Msrv) initSubscriptions() (err error) {
	msrv.subGlobalConfig, err = msrv.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Activate:      false,
		CreateHandler: msrv.handleGlobalConfigCreate,
		ModifyHandler: msrv.handleGlobalConfigModify,
		DeleteHandler: msrv.handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}
	// Look for edge node info
	msrv.subEdgeNodeInfo, err = msrv.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.EdgeNodeInfo{},
		Activate:    false,
		Persistent:  true,
	})
	if err != nil {
		return err
	}

	msrv.subNetworkInstanceStatus, err = msrv.PubSub.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:   "zedrouter",
			MyAgentName: agentName,
			TopicImpl:   types.NetworkInstanceStatus{},
			Activate:    false,
			Persistent:  true,
		},
	)
	if err != nil {
		return err
	}

	// Look for controller certs which will be used for decryption
	msrv.subControllerCert, err = msrv.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.ControllerCert{},
		Activate:    false,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
		Persistent:  true,
	})
	if err != nil {
		return err
	}

	// Look for edge node certs which will be used for decryption
	msrv.subEdgeNodeCert, err = msrv.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "tpmmgr",
		MyAgentName: agentName,
		TopicImpl:   types.EdgeNodeCert{},
		Activate:    false,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
		Persistent:  true,
	})
	if err != nil {
		return err
	}

	// Subscribe to AppNetworkConfig from zedmanager
	msrv.subAppNetworkConfig, err = msrv.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedmanager",
		MyAgentName: agentName,
		TopicImpl:   types.AppNetworkConfig{},
		Activate:    false,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
		Persistent:  true,
	})
	if err != nil {
		return err
	}

	// Subscribe to AppNetworkConfig from zedagent
	msrv.subAppNetworkConfigAg, err = msrv.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.AppNetworkConfig{},
		Activate:    false,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
		Persistent:  true,
	})
	if err != nil {
		return err
	}

	// Subscribe to AppInstConfig from zedagent
	msrv.subAppInstanceConfig, err = msrv.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.AppInstanceConfig{},
		Activate:      false,
		DeleteHandler: msrv.handleAppInstDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}

	// Look for geographic location reports
	msrv.subLocationInfo, err = msrv.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "wwan",
		MyAgentName: agentName,
		TopicImpl:   types.WwanLocationInfo{},
		Activate:    false,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
		Persistent:  true,
	})
	if err != nil {
		return err
	}

	// Look for cellular status
	msrv.subWwanStatus, err = msrv.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "wwan",
		MyAgentName: agentName,
		TopicImpl:   types.WwanStatus{},
		Activate:    false,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
		Persistent:  true,
	})
	if err != nil {
		return err
	}

	// Look for cellular metrics
	msrv.subWwanMetrics, err = msrv.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "wwan",
		MyAgentName: agentName,
		TopicImpl:   types.WwanMetrics{},
		Activate:    false,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
		Persistent:  true,
	})
	if err != nil {
		return err
	}

	msrv.subDomainStatus, err = msrv.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "domainmgr",
		MyAgentName: agentName,
		TopicImpl:   types.DomainStatus{},
		Activate:    false,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
		Persistent:  true,
	})
	if err != nil {
		return err
	}

	msrv.subAppNetworkStatus, err = msrv.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedrouter",
		MyAgentName: agentName,
		TopicImpl:   types.AppNetworkStatus{},
		Activate:    false,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
		Persistent:  true,
	})
	if err != nil {
		return err
	}

	// Information about patch envelopes
	msrv.subPatchEnvelopeInfo, err = msrv.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.PatchEnvelopeInfoList{},
		Activate:      false,
		CreateHandler: msrv.handlePatchEnvelopeCreate,
		ModifyHandler: msrv.handlePatchEnvelopeModify,
		DeleteHandler: msrv.handlePatchEnvelopeDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		Persistent:    true,
	})
	if err != nil {
		return err
	}

	// Information about volumes referred in external patch envelopes
	msrv.subVolumeStatus, err = msrv.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "volumemgr",
		MyAgentName:   agentName,
		TopicImpl:     types.VolumeStatus{},
		Activate:      false,
		CreateHandler: msrv.handleVolumeStatusCreate,
		ModifyHandler: msrv.handleVolumeStatusModify,
		DeleteHandler: msrv.handleVolumeStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		Persistent:    true,
	})
	if err != nil {
		return err
	}

	// Information about volumes referred in external patch envelopes
	msrv.subContentTreeStatus, err = msrv.PubSub.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "volumemgr",
		MyAgentName:   agentName,
		TopicImpl:     types.ContentTreeStatus{},
		Activate:      false,
		CreateHandler: msrv.handleContentTreeStatusCreate,
		ModifyHandler: msrv.handleContentTreeStatusModify,
		DeleteHandler: msrv.handleContentTreeStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		Persistent:    true,
	})
	if err != nil {
		return err
	}

	return nil
}

// Activate all subscriptions.
func (msrv *Msrv) Activate() error {
	inactiveSubs := []pubsub.Subscription{
		msrv.subNetworkInstanceStatus,
		msrv.subEdgeNodeInfo,
		msrv.subControllerCert,
		msrv.subEdgeNodeCert,
		msrv.subAppNetworkConfig,
		msrv.subAppNetworkConfigAg,
		msrv.subAppInstanceConfig,
		msrv.subLocationInfo,
		msrv.subWwanStatus,
		msrv.subWwanMetrics,
		msrv.subDomainStatus,
		msrv.subAppNetworkStatus,
		msrv.subPatchEnvelopeInfo,
		msrv.subVolumeStatus,
		msrv.subContentTreeStatus,
	}

	for _, sub := range inactiveSubs {
		if err := sub.Activate(); err != nil {
			return err
		}
	}
	return nil
}

// Run starts Metadata service
func (msrv *Msrv) Run(ctx context.Context) (err error) {
	if err = pidfile.CheckAndCreatePidfile(msrv.Log, agentName); err != nil {
		return err
	}
	msrv.Log.Noticef("Starting %s", agentName)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(stillRunTime)
	msrv.PubSub.StillRunning(agentName, warningTime, errorTime)

	if err = msrv.subGlobalConfig.Activate(); err != nil {
		return err
	}
	for !msrv.gcInitialized {
		msrv.Log.Noticef("Waiting for GCInitialized")
		select {
		case change := <-msrv.subGlobalConfig.MsgChan():
			msrv.subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		msrv.PubSub.StillRunning(agentName, warningTime, errorTime)
	}
	msrv.Log.Noticef("Processed GlobalConfig")

	// Publish network metrics (interface counters, etc.)
	interval := time.Duration(msrv.metricInterval) * time.Second
	max := float64(interval) / publishTickerDivider
	min := max * 0.3
	publishTicker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))
	msrv.publishTicker = &publishTicker

	if err = msrv.Activate(); err != nil {
		return err
	}

	for {
		select {

		case change := <-msrv.subNetworkInstanceStatus.MsgChan():
			msrv.subNetworkInstanceStatus.ProcessChange(change)

		case change := <-msrv.subEdgeNodeInfo.MsgChan():
			msrv.subEdgeNodeInfo.ProcessChange(change)

		case change := <-msrv.subControllerCert.MsgChan():
			msrv.subControllerCert.ProcessChange(change)

		case change := <-msrv.subEdgeNodeCert.MsgChan():
			msrv.subEdgeNodeCert.ProcessChange(change)

		case change := <-msrv.subAppNetworkConfig.MsgChan():
			msrv.subAppNetworkConfig.ProcessChange(change)

		case change := <-msrv.subAppNetworkConfigAg.MsgChan():
			msrv.subAppNetworkConfigAg.ProcessChange(change)

		case change := <-msrv.subLocationInfo.MsgChan():
			msrv.subLocationInfo.ProcessChange(change)

		case change := <-msrv.subWwanStatus.MsgChan():
			msrv.subWwanStatus.ProcessChange(change)

		case change := <-msrv.subWwanMetrics.MsgChan():
			msrv.subWwanMetrics.ProcessChange(change)

		case change := <-msrv.subDomainStatus.MsgChan():
			msrv.subDomainStatus.ProcessChange(change)

		case change := <-msrv.subAppNetworkStatus.MsgChan():
			msrv.subAppNetworkStatus.ProcessChange(change)

		case change := <-msrv.subPatchEnvelopeInfo.MsgChan():
			msrv.subPatchEnvelopeInfo.ProcessChange(change)

		case change := <-msrv.subVolumeStatus.MsgChan():
			msrv.subVolumeStatus.ProcessChange(change)

		case change := <-msrv.subContentTreeStatus.MsgChan():
			msrv.subContentTreeStatus.ProcessChange(change)

		case <-ctx.Done():
			return nil

		case <-msrv.publishTicker.C:
			start := time.Now()
			msrv.Log.Traceln("publishTicker at", time.Now())

			msrv.PublishPatchEnvelopesUsage()

			msrv.PubSub.CheckMaxTimeTopic(agentName, "publishMetrics", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		msrv.PubSub.StillRunning(agentName, warningTime, errorTime)
	}
}

// MakeMetadataHandler creates http.Handler to be used by LinuxNIReconciler
func (msrv *Msrv) MakeMetadataHandler() http.Handler {
	r := chi.NewRouter()
	zedcloudCtx := zedcloud.NewContext(msrv.Log, zedcloud.ContextOptions{})

	r.Route("/eve/v1", func(r chi.Router) {
		r.Get("/network.json", msrv.handleNetwork())
		r.Get("/external_ipv4", msrv.handleExternalIP())
		r.Get("/hostname", msrv.handleHostname())
		r.Post("/kubeconfig", msrv.handleAppInstMeta(
			KubeconfigFileSizeLimitInBytes,
			types.AppInstMetaDataTypeKubeConfig))
		r.Post("/app/appCustomStatus", msrv.handleAppInstMeta(
			KubeconfigFileSizeLimitInBytes,
			types.AppInstMetaDataCustomStatus))
		r.Get("/location.json", msrv.handleLocationInfo())
		r.Get("/diag", msrv.handleDiag())

		r.Get("/wwan/status.json", msrv.handleWWANStatus())
		r.Get("/wwan/metrics.json", msrv.handleWWANMeterics())

		r.Get("/app/info.json", msrv.handleAppInfo())

		r.Post("/tpm/signer", msrv.handleSigner(&zedcloudCtx))

		r.Route("/patch", func(r chi.Router) {
			r.Use(msrv.withPatchEnvelopesByIP())

			r.Get("/description.json", msrv.handlePatchDescription())
			r.Get("/download/{patch}", msrv.handlePatchDownload())
			r.Get("/download/{patch}/{file}", msrv.handlePatchFileDownload())
		})
	})

	r.Get("/eve/app-custom-blobs", msrv.handleAppCustomBlobs())

	r.Get("/openstack", msrv.handleOpenStack())
	r.Get("/openstack/", msrv.handleOpenStack())

	return r
}
