// Copyright (c) 2018-2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Utility to dump diagnostic information about connectivity

package diag

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/eriknordmark/ipinfo"
	"github.com/google/go-cmp/cmp"
	eveuuid "github.com/lf-edge/eve-api/go/eveuuid"
	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

const (
	agentName  = "diag"
	maxRetries = 5
	// Time limits for event loop handlers
	errorTime      = 3 * time.Minute
	warningTime    = 40 * time.Second
	withNetTracing = false
)

// State passed to handlers
type diagContext struct {
	agentbase.AgentBase
	DeviceNetworkStatus     *types.DeviceNetworkStatus
	DevicePortConfigList    *types.DevicePortConfigList
	usableAddressCount      int
	forever                 bool // Keep on reporting until ^C
	pacContents             bool // Print PAC file contents
	radioSilence            bool
	ledCounter              types.LedBlinkCount
	derivedLedCounter       types.LedBlinkCount // Based on ledCounter + usableAddressCount
	subGlobalConfig         pubsub.Subscription
	globalConfig            *types.ConfigItemValueMap
	GCInitialized           bool // Received initial GlobalConfig
	subLedBlinkCounter      pubsub.Subscription
	subDeviceNetworkStatus  pubsub.Subscription
	subDevicePortConfigList pubsub.Subscription
	subZedAgentStatus       pubsub.Subscription
	zedagentStatus          types.ZedAgentStatus
	subAppInstanceSummary   pubsub.Subscription
	appInstanceSummary      types.AppInstanceSummary
	subAppInstanceStatus    pubsub.Subscription
	subDownloaderStatus     pubsub.Subscription
	zedcloudMetrics         *zedcloud.AgentMetrics
	gotBC                   bool
	gotDNS                  bool
	gotDPCList              bool
	serverNameAndPort       string
	serverName              string // Without port number
	zedcloudCtx             *zedcloud.ZedCloudContext
	cert                    *tls.Certificate
	usingOnboardCert        bool
	devUUID                 uuid.UUID
	// cli options
	foreverPtr             *bool
	pacContentsPtr         *bool
	simulateDNSFailurePtr  *bool
	simulatePingFailurePtr *bool
	outFilenamePtr         *string
	stateFilenamePtr       *string
	rowPtr                 *int
	columnPtr              *int
	triggerPrintChan       chan<- string
	ph                     *PrintHandle
}

// AddAgentSpecificCLIFlags adds CLI options
func (ctxPtr *diagContext) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	ctxPtr.foreverPtr = flagSet.Bool("f", false, "Forever flag")
	ctxPtr.pacContentsPtr = flagSet.Bool("p", false, "Print PAC file contents")
	ctxPtr.simulateDNSFailurePtr = flagSet.Bool("D", false, "simulateDnsFailure flag")
	ctxPtr.simulatePingFailurePtr = flagSet.Bool("P", false, "simulatePingFailure flag")
	ctxPtr.outFilenamePtr = flagSet.String("o", "", "file or device for output")
	ctxPtr.stateFilenamePtr = flagSet.String("s", "", "file for last state dump")
	ctxPtr.rowPtr = flagSet.Int("r", 40, "Max number of rows")
	ctxPtr.columnPtr = flagSet.Int("c", 80, "Max number of columns")
}

var simulateDnsFailure = false
var simulatePingFailure = false
var outfile = os.Stdout
var nilUUID uuid.UUID
var logger *logrus.Logger
var log *base.LogObject

func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int { //nolint:gocyclo
	logger = loggerArg
	log = logArg
	triggerPrintChan := make(chan string, 1)
	ctx := diagContext{
		globalConfig:     types.DefaultConfigItemValueMap(),
		zedcloudMetrics:  zedcloud.NewAgentMetrics(),
		triggerPrintChan: triggerPrintChan,
	}
	agentbase.Init(&ctx, logger, log, agentName,
		agentbase.WithBaseDir(baseDir),
		agentbase.WithArguments(arguments))

	ctx.forever = *ctx.foreverPtr
	ctx.pacContents = *ctx.pacContentsPtr

	var err error

	simulateDnsFailure = *ctx.simulateDNSFailurePtr
	simulatePingFailure = *ctx.simulatePingFailurePtr
	outFilename := *ctx.outFilenamePtr
	if outFilename != "" {
		outfile, err = os.OpenFile(outFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_NONBLOCK, 0644)
		if err != nil {
			log.Fatal(err)
		}
	}
	log.Noticef("diag starting with max rows %d columns %d",
		*ctx.rowPtr, *ctx.columnPtr)
	ctx.ph = PrintIfSpaceInit(outfile, *ctx.stateFilenamePtr,
		*ctx.rowPtr, *ctx.columnPtr)
	ctx.DeviceNetworkStatus = &types.DeviceNetworkStatus{}
	ctx.DevicePortConfigList = &types.DevicePortConfigList{}

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "zedagent",
			MyAgentName:   agentName,
			TopicImpl:     types.ConfigItemValueMap{},
			Persistent:    true,
			Activate:      false,
			Ctx:           &ctx,
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
	subGlobalConfig.Activate()

	// Wait for initial GlobalConfig
	for !ctx.GCInitialized {
		log.Functionf("Waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		}
	}
	log.Functionf("processed GlobalConfig")

	server, err := os.ReadFile(types.ServerFileName)
	if err != nil {
		log.Fatal(err)
	}
	ctx.serverNameAndPort = strings.TrimSpace(string(server))
	ctx.serverName = strings.Split(ctx.serverNameAndPort, ":")[0]

	zedcloudCtx := zedcloud.NewContext(log, zedcloud.ContextOptions{
		DevNetworkStatus: ctx.DeviceNetworkStatus,
		SendTimeout:      ctx.globalConfig.GlobalValueInt(types.NetworkSendTimeout),
		DialTimeout:      ctx.globalConfig.GlobalValueInt(types.NetworkDialTimeout),
		AgentMetrics:     ctx.zedcloudMetrics,
		Serial:           hardware.GetProductSerial(log),
		SoftSerial:       hardware.GetSoftSerial(log),
		AgentName:        agentName,
	})
	// As we ping the cloud or other URLs, don't affect the LEDs
	zedcloudCtx.NoLedManager = true
	log.Functionf("Diag Get Device Serial %s, Soft Serial %s", zedcloudCtx.DevSerial,
		zedcloudCtx.DevSoftSerial)

	// XXX move to later for Get UUID if available

	log.Functionf("diag Run: Use V2 API %v", zedcloudCtx.V2API)

	if fileutils.FileExists(log, types.DeviceCertName) {
		// Load device cert
		cert, err := zedcloud.GetClientCert()
		if err != nil {
			log.Fatal(err)
		}
		ctx.cert = &cert
	} else if fileutils.FileExists(log, types.OnboardCertName) &&
		fileutils.FileExists(log, types.OnboardKeyName) {
		cert, err := tls.LoadX509KeyPair(types.OnboardCertName,
			types.OnboardKeyName)
		if err != nil {
			log.Fatal(err)
		}
		ctx.cert = &cert
		ctx.ph.Print("WARNING: no device cert; using onboarding cert at %v\n",
			time.Now().Format(time.RFC3339Nano))
		ctx.usingOnboardCert = true
	} else {
		ctx.ph.Print("ERROR: no device cert and no onboarding cert at %v\n",
			time.Now().Format(time.RFC3339Nano))
		return 1
	}
	ctx.zedcloudCtx = &zedcloudCtx

	subLedBlinkCounter, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "",
			MyAgentName:   agentName,
			TopicImpl:     types.LedBlinkCounter{},
			Activate:      false,
			Ctx:           &ctx,
			CreateHandler: handleLedBlinkCreate,
			ModifyHandler: handleLedBlinkModify,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		errStr := fmt.Sprintf("ERROR: internal Subscribe failed %s\n", err)
		panic(errStr)
	}
	ctx.subLedBlinkCounter = subLedBlinkCounter
	subLedBlinkCounter.Activate()

	subDeviceNetworkStatus, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "nim",
			MyAgentName:   agentName,
			TopicImpl:     types.DeviceNetworkStatus{},
			Activate:      false,
			Ctx:           &ctx,
			CreateHandler: handleDNSCreate,
			ModifyHandler: handleDNSModify,
			DeleteHandler: handleDNSDelete,
			WarningTime:   warningTime,
			ErrorTime:     errorTime,
		})
	if err != nil {
		errStr := fmt.Sprintf("ERROR: internal Subscribe failed %s\n", err)
		panic(errStr)
	}
	ctx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	subDevicePortConfigList, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "nim",
			MyAgentName:   agentName,
			Persistent:    true,
			TopicImpl:     types.DevicePortConfigList{},
			Activate:      false,
			Ctx:           &ctx,
			CreateHandler: handleDPCCreate,
			ModifyHandler: handleDPCModify,
		})
	if err != nil {
		errStr := fmt.Sprintf("ERROR: internal Subscribe failed %s\n", err)
		panic(errStr)
	}
	ctx.subDevicePortConfigList = subDevicePortConfigList
	subDevicePortConfigList.Activate()

	subOnboardStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedclient",
		MyAgentName:   agentName,
		CreateHandler: handleOnboardStatusCreate,
		ModifyHandler: handleOnboardStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		TopicImpl:     types.OnboardingStatus{},
		Activate:      true,
		Persistent:    true,
		Ctx:           &ctx,
	})
	if err != nil {
		log.Fatal(err)
	}

	// subscribe to zedagent status events
	subZedAgentStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ZedAgentStatus{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleZedAgentStatusCreate,
		ModifyHandler: handleZedAgentStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subZedAgentStatus = subZedAgentStatus
	subZedAgentStatus.Activate()

	// Look for AppInstanceSummary from zedmanager
	subAppInstanceSummary, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedmanager",
		MyAgentName:   agentName,
		TopicImpl:     types.AppInstanceSummary{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleAppInstanceSummaryCreate,
		ModifyHandler: handleAppInstanceSummaryModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subAppInstanceSummary = subAppInstanceSummary
	subAppInstanceSummary.Activate()

	// Look for AppInstanceStatus from zedmanager
	subAppInstanceStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedmanager",
		MyAgentName:   agentName,
		TopicImpl:     types.AppInstanceStatus{},
		Activate:      true,
		Ctx:           &ctx,
		CreateHandler: handleAppInstanceStatusCreate,
		ModifyHandler: handleAppInstanceStatusModify,
		DeleteHandler: handleAppInstanceStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subAppInstanceStatus = subAppInstanceStatus
	subAppInstanceStatus.Activate()

	// Look for DownloaderStatus from downloader
	subDownloaderStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "downloader",
		MyAgentName:   agentName,
		TopicImpl:     types.DownloaderStatus{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleDownloaderStatusCreate,
		ModifyHandler: handleDownloaderStatusModify,
		DeleteHandler: handleDownloaderStatusDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subDownloaderStatus = subDownloaderStatus
	subDownloaderStatus.Activate()

	cloudPingMetricPub, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.MetricsMap{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubTimer := time.NewTimer(30 * time.Second)

	go printTask(&ctx, triggerPrintChan)

	for {
		gotAll := ctx.gotBC && ctx.gotDNS && ctx.gotDPCList
		select {
		case <-pubTimer.C:
			ctx.zedcloudMetrics.Publish(log, cloudPingMetricPub, "global")
			pubTimer = time.NewTimer(30 * time.Second)

		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subLedBlinkCounter.MsgChan():
			subLedBlinkCounter.ProcessChange(change)
			ctx.gotBC = true

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)
			ctx.gotDNS = true

		case change := <-subOnboardStatus.MsgChan():
			subOnboardStatus.ProcessChange(change)

		case change := <-subDevicePortConfigList.MsgChan():
			subDevicePortConfigList.ProcessChange(change)
			ctx.gotDPCList = true

		case change := <-subZedAgentStatus.MsgChan():
			subZedAgentStatus.ProcessChange(change)

		case change := <-subAppInstanceSummary.MsgChan():
			subAppInstanceSummary.ProcessChange(change)

		case change := <-subAppInstanceStatus.MsgChan():
			subAppInstanceStatus.ProcessChange(change)

		case change := <-subDownloaderStatus.MsgChan():
			subDownloaderStatus.ProcessChange(change)
		}
		// Is this the first time we have all the info to print?
		if !gotAll && ctx.gotBC && ctx.gotDNS && ctx.gotDPCList {
			triggerPrintOutput(&ctx, "first")
		}

		if !ctx.forever && ctx.gotDNS && ctx.gotBC && ctx.gotDPCList {
			break
		}
		if ctx.usingOnboardCert && fileutils.FileExists(log, types.DeviceCertName) {
			ctx.ph.Print("WARNING: Switching from onboard to device cert\n")
			// Load device cert
			cert, err := zedcloud.GetClientCert()
			if err != nil {
				log.Fatal(err)
			}
			ctx.cert = &cert
			ctx.usingOnboardCert = false
		}
		// Check in case /config/server changes while running
		nserver, err := os.ReadFile(types.ServerFileName)
		if err != nil {
			log.Error(err)
		} else if len(nserver) != 0 && string(server) != string(nserver) {
			log.Warnf("/config/server changed from %s to %s",
				server, nserver)
			server = nserver
			ctx.serverNameAndPort = strings.TrimSpace(string(server))
			ctx.serverName = strings.Split(ctx.serverNameAndPort, ":")[0]
		}
	}
	return 0
}

func handleLedBlinkCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	handleLedBlinkImpl(ctxArg, key, configArg)
}

func handleLedBlinkModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	handleLedBlinkImpl(ctxArg, key, configArg)
}

func handleLedBlinkImpl(ctxArg interface{}, key string,
	configArg interface{}) {

	config := configArg.(types.LedBlinkCounter)
	ctx := ctxArg.(*diagContext)

	if key != "ledconfig" {
		log.Errorf("handleLedBlinkImpl: ignoring %s", key)
		return
	}
	// Suppress work and logging if no change
	if config.BlinkCounter == ctx.ledCounter {
		return
	}
	ctx.ledCounter = config.BlinkCounter
	ctx.derivedLedCounter = types.DeriveLedCounter(ctx.ledCounter,
		ctx.usableAddressCount, ctx.radioSilence)
	log.Functionf("counter %d usableAddr %d, derived %d",
		ctx.ledCounter, ctx.usableAddressCount, ctx.derivedLedCounter)
	triggerPrintOutput(ctx, "LED")
}

// handle zedagent status events, for cloud connectivity
func handleZedAgentStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleZedAgentStatusImpl(ctxArg, key, statusArg)
}

func handleZedAgentStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleZedAgentStatusImpl(ctxArg, key, statusArg)
}

func handleZedAgentStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*diagContext)
	status := statusArg.(types.ZedAgentStatus)
	// trigger print if anything changed and we're only called if create
	// or modify
	triggerPrintOutput(ctx, "DeviceState")
	ctx.zedagentStatus = status
}

func handleAppInstanceSummaryCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleAppInstanceSummaryImpl(ctxArg, key, statusArg)
}

func handleAppInstanceSummaryModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleAppInstanceSummaryImpl(ctxArg, key, statusArg)
}

func handleAppInstanceSummaryImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*diagContext)
	ctx.appInstanceSummary = statusArg.(types.AppInstanceSummary)
	triggerPrintOutput(ctx, "App")
}

func handleAppInstanceStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleAppInstanceStatusImpl(ctxArg, key, statusArg)
}

func handleAppInstanceStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleAppInstanceStatusImpl(ctxArg, key, statusArg)
}

func handleAppInstanceStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*diagContext)
	// Should we rate limit to not print every update of progress?
	triggerPrintOutput(ctx, "Appinstance")
}

func handleAppInstanceStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*diagContext)
	triggerPrintOutput(ctx, "Appinstance")
}

func handleDownloaderStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleDownloaderStatusImpl(ctxArg, key, statusArg)
}

func handleDownloaderStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleDownloaderStatusImpl(ctxArg, key, statusArg)
}

func handleDownloaderStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*diagContext)
	// Should we rate limit to not print every update of progress?
	triggerPrintOutput(ctx, "Download")
}

func handleDownloaderStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*diagContext)
	triggerPrintOutput(ctx, "Download")
}

func handleDNSCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleDNSImpl(ctxArg, key, statusArg)
}

func handleDNSModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleDNSImpl(ctxArg, key, statusArg)
}

func handleDNSImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.DeviceNetworkStatus)
	ctx := ctxArg.(*diagContext)
	if key != "global" {
		log.Functionf("handleDNSImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleDNSImpl for %s", key)
	// Since we report test status we compare all fields
	if cmp.Equal(ctx.DeviceNetworkStatus, status) {
		log.Functionf("handleDNSImpl unchanged")
		return
	}

	mostlyEqual := status.MostlyEqualStatus(*ctx.DeviceNetworkStatus)
	if !mostlyEqual {
		log.Noticef("handleDNSImpl: important change %v",
			cmp.Diff(*ctx.DeviceNetworkStatus, status))
	}
	*ctx.DeviceNetworkStatus = status
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctx.DeviceNetworkStatus)
	log.Functionf("handleDNSImpl %d usable addresses", newAddrCount)
	if (ctx.usableAddressCount == 0 && newAddrCount != 0) ||
		(ctx.usableAddressCount != 0 && newAddrCount == 0) ||
		updateRadioSilence(ctx, ctx.DeviceNetworkStatus) {
		ctx.usableAddressCount = newAddrCount
		ctx.derivedLedCounter = types.DeriveLedCounter(ctx.ledCounter,
			ctx.usableAddressCount, ctx.radioSilence)
		log.Functionf("counter %d, usableAddr %d, radioSilence %t, derived %d",
			ctx.ledCounter, ctx.usableAddressCount, ctx.radioSilence, ctx.derivedLedCounter)
	}

	// update proxy certs if configured
	if ctx.zedcloudCtx != nil && ctx.zedcloudCtx.V2API && ctx.zedcloudCtx.TlsConfig != nil {
		zedcloud.UpdateTLSProxyCerts(ctx.zedcloudCtx)
	}
	if mostlyEqual {
		log.Functionf("handleDNSImpl done - no important change for %s",
			key)
		return
	}
	triggerPrintOutput(ctx, "Network")
	log.Functionf("handleDNSImpl done for %s", key)
}

func handleDNSDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleDNSDelete for %s", key)
	ctx := ctxArg.(*diagContext)

	if key != "global" {
		log.Functionf("handleDNSDelete: ignoring %s", key)
		return
	}
	*ctx.DeviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctx.DeviceNetworkStatus)
	log.Functionf("handleDNSDelete %d usable addresses", newAddrCount)
	if (ctx.usableAddressCount == 0 && newAddrCount != 0) ||
		(ctx.usableAddressCount != 0 && newAddrCount == 0) ||
		updateRadioSilence(ctx, ctx.DeviceNetworkStatus) {
		ctx.usableAddressCount = newAddrCount
		ctx.derivedLedCounter = types.DeriveLedCounter(ctx.ledCounter,
			ctx.usableAddressCount, ctx.radioSilence)
		log.Functionf("counter %d, usableAddr %d, radioSilence %t, derived %d",
			ctx.ledCounter, ctx.usableAddressCount, ctx.radioSilence, ctx.derivedLedCounter)
	}
	triggerPrintOutput(ctx, "Network")
	log.Functionf("handleDNSDelete done for %s", key)
}

func updateRadioSilence(ctx *diagContext, status *types.DeviceNetworkStatus) (update bool) {
	if status == nil {
		// by default radio-silence is turned off
		update = ctx.radioSilence != false
		ctx.radioSilence = false
	} else if !status.RadioSilence.ChangeInProgress {
		update = ctx.radioSilence != status.RadioSilence.Imposed
		ctx.radioSilence = status.RadioSilence.Imposed
	}
	return
}

func handleDPCCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleDPCImpl(ctxArg, key, statusArg)
}

func handleDPCModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleDPCImpl(ctxArg, key, statusArg)
}

func handleDPCImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.DevicePortConfigList)
	ctx := ctxArg.(*diagContext)
	if key != "global" {
		log.Functionf("handleDPCImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleDPCImpl for %s", key)
	if ctx.DevicePortConfigList.MostlyEqual(status) {
		return
	}
	log.Functionf("handleDPCImpl: changed %v",
		cmp.Diff(*ctx.DevicePortConfigList, status))
	*ctx.DevicePortConfigList = status
	triggerPrintOutput(ctx, "DPC")
	log.Functionf("handleDPCImpl done for %s", key)
}

// Handles UUID change from process client
func handleOnboardStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleOnboardStatusImpl(ctxArg, key, statusArg)
}

func handleOnboardStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleOnboardStatusImpl(ctxArg, key, statusArg)
}

func handleOnboardStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.OnboardingStatus)
	ctx := ctxArg.(*diagContext)
	if cmp.Equal(ctx.devUUID, status.DeviceUUID) {
		log.Functionf("handleOnboardStatusImpl no change to %v", ctx.devUUID)
		return
	}
	ctx.devUUID = status.DeviceUUID
	log.Functionf("handleOnboardStatusImpl changed to %v", ctx.devUUID)
	triggerPrintOutput(ctx, "Onboard")
}

// Conditional send to ensure that one gets printed but multiple triggers
// can collapse into one print
func triggerPrintOutput(ctx *diagContext, caller string) {
	select {
	case ctx.triggerPrintChan <- caller:
		// Do nothing more
	default:
	}
}

// printTask waits for 5 seconds after each print to limit the rate
func printTask(ctx *diagContext, triggerPrintChan <-chan string) {
	for {
		select {
		case caller := <-triggerPrintChan:
			printOutput(ctx, caller)
			time.Sleep(5 * time.Second)
		}
	}
}

// Print output for all interfaces
func printOutput(ctx *diagContext, caller string) {
	ctx.ph.Print("\nINFO: updated diag information at %v due to %s\n",
		time.Now().Format(time.RFC3339Nano), caller)
	// Determine what to print for the device line
	level := "INFO"

	if ctx.zedagentStatus.VaultStatus == info.DataSecAtRestStatus_DATASEC_AT_REST_DISABLED {
		level = "WARNING" // Can be overridden below
	}
	if ctx.zedagentStatus.DeviceState == types.DEVICE_STATE_MAINTENANCE_MODE {
		level = "ERROR"
	}
	// Shorten output and add errors if present
	attestStatus := strings.TrimPrefix(ctx.zedagentStatus.AttestState.String(),
		"State")
	if ctx.zedagentStatus.AttestError != "" {
		level = "ERROR"
		attestStatus += " error " + ctx.zedagentStatus.AttestError
	}
	vaultStatus := strings.TrimPrefix(ctx.zedagentStatus.VaultStatus.String(),
		"DATASEC_AT_REST_")
	if ctx.zedagentStatus.VaultErr != "" &&
		ctx.zedagentStatus.VaultStatus != info.DataSecAtRestStatus_DATASEC_AT_REST_DISABLED {
		level = "ERROR"
		vaultStatus += " error " + ctx.zedagentStatus.VaultErr
	}
	pcrStatus := strings.TrimPrefix(ctx.zedagentStatus.PCRStatus.String(),
		"PCR_")

	ctx.ph.Print("%s: device: %s attest: %s vault: %s pcr: %s\n",
		level, ctx.zedagentStatus.DeviceState.String(),
		attestStatus, vaultStatus, pcrStatus)

	// Determine what we print for app summary
	summary := ctx.appInstanceSummary
	if ctx.appInstanceSummary.TotalError > 0 {
		ctx.ph.Print("ERROR: applications: %d with error, %d starting, %d running, %d stopping\n",
			summary.TotalError, summary.TotalStarting,
			summary.TotalRunning, summary.TotalStopping)
	} else if summary.TotalStopping > 0 {
		ctx.ph.Print("WARNING: applications: %d stopping, %d starting, %d running\n",
			summary.TotalStopping, summary.TotalStarting,
			summary.TotalRunning)
	} else {
		ctx.ph.Print("INFO: applications: %d starting, %d running\n",
			summary.TotalStarting, summary.TotalRunning)
	}

	// Defer until we have an initial BlinkCounter and DeviceNetworkStatus
	if !ctx.gotDNS || !ctx.gotBC || !ctx.gotDPCList {
		ctx.ph.Flush()
		return
	}

	// XXX certificate fingerprints? What does zedcloud use?

	switch ctx.derivedLedCounter {
	case types.LedBlinkOnboarded:
		ctx.ph.Print("INFO: Summary: %s\n", ctx.derivedLedCounter)
	case types.LedBlinkConnectedToController, types.LedBlinkRadioSilence:
		ctx.ph.Print("WARNING: Summary: %s\n", ctx.derivedLedCounter)
	default:
		ctx.ph.Print("ERROR: Summary: %s\n", ctx.derivedLedCounter)
	}

	testing := ctx.DeviceNetworkStatus.Testing
	var upcase, downcase string
	if testing {
		upcase = "Testing"
		downcase = "testing"
	} else {
		upcase = "Using"
		downcase = "using"
	}
	// Print info about fallback
	DPCLen := len(ctx.DevicePortConfigList.PortConfigList)
	if DPCLen > 0 {
		first := ctx.DevicePortConfigList.PortConfigList[0]
		if ctx.DevicePortConfigList.CurrentIndex == -1 {
			ctx.ph.Print("WARNING: Have no currently working DevicePortConfig\n")
		} else if ctx.DevicePortConfigList.CurrentIndex != 0 {
			ctx.ph.Print("WARNING: Not %s highest priority DevicePortConfig key %s due to %s\n",
				downcase, first.Key, first.LastError)
			for i, dpc := range ctx.DevicePortConfigList.PortConfigList {
				if i == 0 {
					continue
				}
				if i != ctx.DevicePortConfigList.CurrentIndex {
					ctx.ph.Print("WARNING: Not %s priority %d DevicePortConfig key %s due to %s\n",
						downcase, i, dpc.Key, dpc.LastError)
				} else {
					ctx.ph.Print("INFO: %s priority %d DevicePortConfig key %s\n",
						upcase, i, dpc.Key)
					break
				}
			}
			if DPCLen-1 > ctx.DevicePortConfigList.CurrentIndex {
				ctx.ph.Print("INFO: Have %d backup DevicePortConfig\n",
					DPCLen-1-ctx.DevicePortConfigList.CurrentIndex)
			}
		} else {
			ctx.ph.Print("INFO: %s highest priority DevicePortConfig key %s\n",
				upcase, first.Key)
			if DPCLen > 1 {
				ctx.ph.Print("INFO: Have %d backup DevicePortConfig\n",
					DPCLen-1)
			}
		}
	}
	if testing {
		ctx.ph.Print("WARNING: The configuration below is under test hence might report failures\n")
	}
	dpcSuccess := ctx.DeviceNetworkStatus.State == types.DPCStateSuccess
	if !dpcSuccess {
		ctx.ph.Print("WARNING: state %s not SUCCESS\n",
			ctx.DeviceNetworkStatus.State.String())
	}

	numPorts := len(types.GetAllPortsSortedCost(*ctx.DeviceNetworkStatus, true, 0))
	mgmtPorts := 0
	passPorts := 0

	numMgmtPorts := len(types.GetMgmtPortsAny(*ctx.DeviceNetworkStatus, 0))
	ctx.ph.Print("INFO: Have %d total ports. %d ports should be connected to EV controller\n", numPorts, numMgmtPorts)
	for _, port := range ctx.DeviceNetworkStatus.Ports {
		if !port.IsL3Port {
			continue
		}
		// Print usefully formatted info based on which
		// fields are set and Dhcp type; proxy info order
		ifname := port.IfName
		isMgmt := types.IsMgmtPort(*ctx.DeviceNetworkStatus, ifname)
		priority := types.GetPortCost(*ctx.DeviceNetworkStatus,
			ifname)
		if isMgmt {
			mgmtPorts++
		}

		var isValidStr string
		if port.InvalidConfig {
			isValidStr = " (invalid config)"
		}
		typeStr := "use: app-shared "
		if isMgmt {
			if priority == types.PortCostMin {
				typeStr = "use: mgmt "
			} else {
				typeStr = fmt.Sprintf("use: mgmt (cost %d) ",
					priority)
			}
		}
		macStr := ""
		if len(port.MacAddr) != 0 {
			macStr = fmt.Sprintf("Mac: %s ", port.MacAddr.String())
		}
		var linkStr string
		if port.Up {
			linkStr = "link: up "
		} else {
			linkStr = "link: down "
		}
		ipCount := 0
		for _, ai := range port.AddrInfoList {
			if ai.Addr.IsLinkLocalUnicast() {
				continue
			}
			ipCount++
			noGeo := ipinfo.IPInfo{}
			if dpcSuccess {
				ctx.ph.Print("INFO: Port %s%s: %s%s%s%s\n",
					ifname, isValidStr, macStr, linkStr, typeStr, ai.Addr)
			} else if ai.Geo == noGeo {
				ctx.ph.Print("INFO: %s: IP address %s not geolocated\n",
					ifname, ai.Addr)
			} else {
				ctx.ph.Print("INFO: %s: IP address %s geolocated to %+v\n",
					ifname, ai.Addr, ai.Geo)
			}
		}
		if ipCount == 0 {
			ctx.ph.Print("INFO: Port %s%s: %s%s%sNo IP address\n",
				ifname, isValidStr, macStr, linkStr, typeStr)
		}

		// Skip details if we are connected to controller. Count
		// all as connected
		if dpcSuccess {
			if isMgmt {
				passPorts++
			}
			continue
		}
		ctx.ph.Print("INFO: %s: DNS servers: ", ifname)
		for _, ds := range port.DNSServers {
			ctx.ph.Print("%s, ", ds.String())
		}
		ctx.ph.Print("\n")
		// If static print static config
		if port.Dhcp == types.DhcpTypeStatic {
			ctx.ph.Print("INFO: %s: Static IP subnet: %s\n",
				ifname, port.Subnet.String())
			for _, r := range port.DefaultRouters {
				ctx.ph.Print("INFO: %s: Static IP router: %s\n",
					ifname, r.String())
			}
			ctx.ph.Print("INFO: %s: Static Domain Name: %s\n",
				ifname, port.DomainName)
			ctx.ph.Print("INFO: %s: Static NTP server: %s\n",
				ifname, port.NtpServer.String())
		}
		printProxy(ctx, port, ifname)
		if port.HasError() {
			if port.InvalidConfig {
				ctx.ph.Print("ERROR: %s: invalid config: %s\n", ifname, port.LastError)
			} else {
				ctx.ph.Print("ERROR: %s: has error: %s\n", ifname, port.LastError)
			}
		}

		if !isMgmt {
			ctx.ph.Print("INFO: %s: not intended for EV controller; skipping those tests\n",
				ifname)
			continue
		}
		if ipCount == 0 {
			ctx.ph.Print("WARNING: %s: No IP address to connect to EV controller\n",
				ifname)
			continue
		}
		// DNS lookup - skip if an explicit (i.e. not transparent) proxy is configured.
		// In that case it is the proxy which is responsible for domain name resolution.
		if !devicenetwork.IsExplicitProxyConfigured(port.ProxyConfig) {
			if !tryLookupIP(ctx, ifname) {
				continue
			}
		}
		// ping and getUuid calls
		if !tryPing(ctx, ifname, "") {
			ctx.ph.Print("ERROR: %s: ping failed to %s; trying google\n",
				ifname, ctx.serverNameAndPort)
			origServerName := ctx.serverName
			origServerNameAndPort := ctx.serverNameAndPort
			ctx.serverName = "www.google.com"
			ctx.serverNameAndPort = ctx.serverName
			if tryPing(ctx, ifname, "http://www.google.com") {
				ctx.ph.Print("WARNING: %s: Can reach http://google.com but not https://%s\n",
					ifname, origServerNameAndPort)
			} else {
				ctx.ph.Print("ERROR: %s: Can't reach http://google.com; likely lack of Internet connectivity\n",
					ifname)
			}
			if tryPing(ctx, ifname, "https://www.google.com") {
				ctx.ph.Print("WARNING: %s: Can reach https://google.com but not https://%s\n",
					ifname, origServerNameAndPort)
			} else {
				ctx.ph.Print("ERROR: %s: Can't reach https://google.com; likely lack of Internet connectivity\n",
					ifname)
			}
			ctx.serverName = origServerName
			ctx.serverNameAndPort = origServerNameAndPort
			continue
		}
		if !tryPostUUID(ctx, ifname) {
			continue
		}
		if isMgmt {
			passPorts++
		}
		ctx.ph.Print("PASS: port %s fully connected to EV controller %s\n",
			ifname, ctx.serverName)
	}
	if dpcSuccess {
		// Do nothing
	} else if mgmtPorts == 0 {
		ctx.ph.Print("ERROR: No management ports passed test\n")
	} else if passPorts == mgmtPorts {
		ctx.ph.Print("PASS: All management ports passed test\n")
	} else {
		ctx.ph.Print("WARNING: %d out of %d management ports passed test\n",
			passPorts, mgmtPorts)
	}

	// Print info about app instances
	items := ctx.subAppInstanceStatus.GetAll()
	for _, item := range items {
		ais := item.(types.AppInstanceStatus)
		if ais.HasError() {
			ctx.ph.Print("ERROR: App %s uuid %s state %s error: %s\n",
				ais.DisplayName, ais.UUIDandVersion.UUID, ais.State.String(),
				ais.Error)
		} else {
			ctx.ph.Print("INFO: App %s uuid %s state %s\n",
				ais.DisplayName, ais.UUIDandVersion.UUID, ais.State.String())
		}
	}

	// Print info about downloads
	items = ctx.subDownloaderStatus.GetAll()
	for _, item := range items {
		ds := item.(types.DownloaderStatus)
		if ds.HasError() {
			ctx.ph.Print("WARNING: download %s sha %s at %d%% retried %d error: %s\n",
				ds.Name, ds.ImageSha256, ds.Progress, ds.RetryCount,
				ds.Error)
		} else {
			ctx.ph.Print("INFO: download %s sha %s progress %d%% out of %d bytes\n",
				ds.Name, ds.ImageSha256, ds.Progress, ds.TotalSize)
		}
	}
	ctx.ph.Flush()
}

func printProxy(ctx *diagContext, port types.NetworkPortStatus,
	ifname string) {

	if devicenetwork.IsProxyConfigEmpty(port.ProxyConfig) {
		ctx.ph.Print("INFO: %s: no http(s) proxy\n", ifname)
		return
	}
	if port.ProxyConfig.Exceptions != "" {
		ctx.ph.Print("INFO: %s: proxy exceptions %s\n",
			ifname, port.ProxyConfig.Exceptions)
	}
	if port.HasError() {
		ctx.ph.Print("ERROR: %s: from WPAD? %s\n",
			ifname, port.LastError)
	}
	if port.ProxyConfig.NetworkProxyEnable {
		if port.ProxyConfig.NetworkProxyURL == "" {
			if port.ProxyConfig.WpadURL == "" {
				ctx.ph.Print("WARNING: %s: WPAD enabled but found no URL\n",
					ifname)
			} else {
				ctx.ph.Print("INFO: %s: WPAD enabled found URL %s\n",
					ifname, port.ProxyConfig.WpadURL)
			}
		} else {
			ctx.ph.Print("INFO: %s: WPAD fetched from %s\n",
				ifname, port.ProxyConfig.NetworkProxyURL)
		}
	}
	pacLen := len(port.ProxyConfig.Pacfile)
	if pacLen > 0 {
		ctx.ph.Print("INFO: %s: Have PAC file len %d\n",
			ifname, pacLen)
		if ctx.pacContents {
			pacFile, err := base64.StdEncoding.DecodeString(port.ProxyConfig.Pacfile)
			if err != nil {
				errStr := fmt.Sprintf("Decoding proxy file failed: %s", err)
				log.Errorf(errStr)
			} else {
				ctx.ph.Print("INFO: %s: PAC file:\n%s\n",
					ifname, pacFile)
			}
		}
	} else {
		for _, proxy := range port.ProxyConfig.Proxies {
			switch proxy.Type {
			case types.NetworkProxyTypeHTTP:
				var httpProxy string
				if proxy.Port > 0 {
					httpProxy = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
				} else {
					httpProxy = fmt.Sprintf("%s", proxy.Server)
				}
				ctx.ph.Print("INFO: %s: http proxy %s\n",
					ifname, httpProxy)
			case types.NetworkProxyTypeHTTPS:
				var httpsProxy string
				if proxy.Port > 0 {
					httpsProxy = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
				} else {
					httpsProxy = fmt.Sprintf("%s", proxy.Server)
				}
				ctx.ph.Print("INFO: %s: https proxy %s\n",
					ifname, httpsProxy)
			}
		}

		if len(port.ProxyCertPEM) > 0 {
			ctx.ph.Print("INFO: %d proxy certificate(s)",
				len(port.ProxyCertPEM))
		}
	}
}

func tryLookupIP(ctx *diagContext, ifname string) bool {

	addrCount, _ := types.CountLocalAddrAnyNoLinkLocalIf(*ctx.DeviceNetworkStatus, ifname)
	if addrCount == 0 {
		ctx.ph.Print("ERROR: %s: DNS lookup of %s not possible since no IP address\n",
			ifname, ctx.serverName)
		return false
	}
	for retryCount := 0; retryCount < addrCount; retryCount++ {
		localAddr, err := types.GetLocalAddrAnyNoLinkLocal(*ctx.DeviceNetworkStatus,
			retryCount, ifname)
		if err != nil {
			ctx.ph.Print("ERROR: %s: DNS lookup of %s: internal error: %s address\n",
				ifname, ctx.serverName, err)
			return false
		}
		dnsServers := types.GetDNSServers(*ctx.DeviceNetworkStatus, ifname)
		if len(dnsServers) == 0 {
			ctx.ph.Print("ERROR: %s: DNS lookup of %s not possible: no DNS servers available\n",
				ifname, ctx.serverName)
			return false
		}
		localUDPAddr := net.UDPAddr{IP: localAddr}
		log.Tracef("tryLookupIP: using intf %s source %v", ifname, localUDPAddr)
		resolverDial := func(ctx context.Context, network, address string) (net.Conn, error) {
			log.Tracef("resolverDial %v %v", network, address)
			// Try only DNS servers associated with this interface.
			ip := net.ParseIP(strings.Split(address, ":")[0])
			for _, dnsServer := range dnsServers {
				if dnsServer != nil && dnsServer.Equal(ip) {
					d := net.Dialer{LocalAddr: &localUDPAddr}
					return d.Dial(network, address)
				}
			}
			return nil, fmt.Errorf("DNS server %s is from a different network, skipping",
				ip.String())
		}
		r := net.Resolver{Dial: resolverDial, PreferGo: true,
			StrictErrors: false}
		ips, err := r.LookupIPAddr(context.Background(), ctx.serverName)
		if err != nil {
			ctx.ph.Print("ERROR: %s: DNS lookup of %s failed: %s\n",
				ifname, ctx.serverName, err)
			continue
		}
		log.Tracef("tryLookupIP: got %d addresses", len(ips))
		if len(ips) == 0 {
			ctx.ph.Print("ERROR: %s: DNS lookup of %s returned no answers\n",
				ifname, ctx.serverName)
			return false
		}
		for _, ip := range ips {
			ctx.ph.Print("INFO: %s: DNS lookup of %s returned %s\n",
				ifname, ctx.serverName, ip.String())
		}
		if simulateDnsFailure {
			ctx.ph.Print("INFO: %s: Simulate DNS lookup failure\n", ifname)
			return false
		}
		return true
	}
	// Tried all in loop
	return false
}

func tryPing(ctx *diagContext, ifname string, reqURL string) bool {

	zedcloudCtx := ctx.zedcloudCtx
	if zedcloudCtx.TlsConfig == nil {
		err := zedcloud.UpdateTLSConfig(zedcloudCtx, ctx.cert)
		if err != nil {
			log.Errorf("internal UpdateTLSConfig failed %v", err)
			return false
		}
		zedcloudCtx.TlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(0)
	}
	if reqURL == "" {
		reqURL = zedcloud.URLPathString(ctx.serverNameAndPort, zedcloudCtx.V2API, nilUUID, "ping")
	} else {
		// Temporarily change TLS config for the non-controller destination.
		origSkipVerify := zedcloudCtx.TlsConfig.InsecureSkipVerify
		zedcloudCtx.TlsConfig.InsecureSkipVerify = true
		defer func() {
			// Revert back the original TLS config.
			zedcloudCtx.TlsConfig.InsecureSkipVerify = origSkipVerify
		}()
	}

	retryCount := 0
	done := false
	var delay time.Duration
	for !done {
		time.Sleep(delay)
		done, _, _ = myGet(ctx, reqURL, ifname, retryCount)
		if done {
			break
		}
		retryCount++
		if maxRetries != 0 && retryCount > maxRetries {
			ctx.ph.Print("ERROR: %s: Exceeded %d retries for ping\n",
				ifname, maxRetries)
			return false
		}
		delay = time.Second
	}
	if simulatePingFailure {
		ctx.ph.Print("INFO: %s: Simulate ping failure\n", ifname)
		return false
	}
	return true
}

// The most recent uuid we received
var prevUUID string

func tryPostUUID(ctx *diagContext, ifname string) bool {

	uuidRequest := &eveuuid.UuidRequest{}
	b, err := proto.Marshal(uuidRequest)
	if err != nil {
		log.Errorln(err)
		return false
	}
	zedcloudCtx := ctx.zedcloudCtx

	retryCount := 0
	done := false
	senderStatus := types.SenderStatusNone
	var delay time.Duration
	for !done {
		time.Sleep(delay)
		var resp *http.Response
		var buf []byte
		reqURL := zedcloud.URLPathString(ctx.serverNameAndPort, zedcloudCtx.V2API,
			nilUUID, "uuid")
		done, resp, senderStatus, buf = myPost(ctx, reqURL, ifname, retryCount,
			int64(len(b)), bytes.NewBuffer(b))
		if done {
			parsePrint(reqURL, resp, buf)
			break
		}
		if senderStatus == types.SenderStatusCertMiss {
			// currently only three places we need to verify envelope data
			// 1) client
			// 2) zedagent
			// 3) diag here for getting /config
			// 1) is the initial getting cloud certs, 2) rely on zedagent to refetch the cloud certs
			// if zedcloud has cert change. 3) only need to zero out the cache in zedcloudCtx and
			// it will reacquire from the updated cert file. zedagent is the only one responsible for refetching certs.
			zedcloud.ClearCloudCert(zedcloudCtx)
			return false
		}
		retryCount++
		if maxRetries != 0 && retryCount > maxRetries {
			ctx.ph.Print("ERROR: %s: Exceeded %d retries for get config\n",
				ifname, maxRetries)
			return false
		}
		delay = time.Second
	}
	return true
}

func parsePrint(reqURL string, resp *http.Response, contents []byte) {
	if resp.StatusCode == http.StatusNotModified {
		log.Tracef("StatusNotModified len %d", len(contents))
		return
	}

	if err := zedcloud.ValidateProtoContentType(reqURL, resp); err != nil {
		log.Errorln("ValidateProtoContentType: ", err)
		return
	}

	uuidResponse, err := readUUIDResponseProtoMessage(contents)
	if err != nil {
		log.Errorln("readUUIDResponseProtoMessage: ", err)
		return
	}
	newUUID := uuidResponse.GetUuid()
	if prevUUID != newUUID {
		prevUUID = newUUID
		log.Functionf("Changed UUIDResponse with uuid %s", newUUID)
	}
}

func readUUIDResponseProtoMessage(contents []byte) (*eveuuid.UuidResponse, error) {
	var uuidResponse = &eveuuid.UuidResponse{}

	err := proto.Unmarshal(contents, uuidResponse)
	if err != nil {
		log.Errorf("Unmarshalling failed: %v", err)
		return nil, err
	}
	return uuidResponse, nil
}

// Get something without a return type; used by ping
// Returns true when done; false when retry.
// Returns the response when done. Caller can not use resp.Body but
// can use the contents []byte
func myGet(ctx *diagContext, reqURL string, ifname string,
	retryCount int) (bool, *http.Response, []byte) {

	zedcloudCtx := ctx.zedcloudCtx
	var preqURL string
	if strings.HasPrefix(reqURL, "http:") {
		preqURL = reqURL
	} else if strings.HasPrefix(reqURL, "https:") {
		preqURL = reqURL
	} else {
		preqURL = "https://" + reqURL
	}
	proxyURL, err := zedcloud.LookupProxy(log, zedcloudCtx.DeviceNetworkStatus,
		ifname, preqURL)
	if err != nil {
		ctx.ph.Print("ERROR: %s: LookupProxy failed: %s\n", ifname, err)
	} else if proxyURL != nil {
		ctx.ph.Print("INFO: %s: Proxy %s to reach %s\n",
			ifname, proxyURL.String(), reqURL)
	}
	const allowProxy = true
	// No verification of AuthContainer for this GET
	rv, err := zedcloud.SendOnIntf(context.Background(), zedcloudCtx, reqURL, ifname,
		0, nil, allowProxy, ctx.usingOnboardCert, withNetTracing, false)
	if err != nil {
		switch rv.Status {
		case types.SenderStatusUpgrade:
			ctx.ph.Print("ERROR: %s: get %s Controller upgrade in progress\n",
				ifname, reqURL)
		case types.SenderStatusRefused:
			ctx.ph.Print("ERROR: %s: get %s Controller returned ECONNREFUSED\n",
				ifname, reqURL)
		case types.SenderStatusCertInvalid:
			ctx.ph.Print("ERROR: %s: get %s Controller certificate invalid time\n",
				ifname, reqURL)
		case types.SenderStatusCertMiss:
			ctx.ph.Print("ERROR: %s: get %s Controller certificate miss\n",
				ifname, reqURL)
		case types.SenderStatusNotFound:
			ctx.ph.Print("ERROR: %s: get %s Did controller delete the device?\n",
				ifname, reqURL)
		default:
			ctx.ph.Print("ERROR: %s: get %s failed: %s\n",
				ifname, reqURL, err)
		}
		return false, nil, nil
	}

	switch rv.HTTPResp.StatusCode {
	case http.StatusOK:
		ctx.ph.Print("INFO: %s: %s StatusOK\n", ifname, reqURL)
		return true, rv.HTTPResp, rv.RespContents
	case http.StatusNotModified:
		ctx.ph.Print("INFO: %s: %s StatusNotModified\n", ifname, reqURL)
		return true, rv.HTTPResp, rv.RespContents
	default:
		ctx.ph.Print("ERROR: %s: %s statuscode %d %s\n",
			ifname, reqURL, rv.HTTPResp.StatusCode,
			http.StatusText(rv.HTTPResp.StatusCode))
		ctx.ph.Print("ERROR: %s: Received %s\n",
			ifname, string(rv.RespContents))
		return false, nil, nil
	}
}

func myPost(ctx *diagContext, reqURL string, ifname string,
	retryCount int, reqlen int64, b *bytes.Buffer) (bool, *http.Response, types.SenderStatus, []byte) {

	zedcloudCtx := ctx.zedcloudCtx
	var preqURL string
	if strings.HasPrefix(reqURL, "http:") {
		preqURL = reqURL
	} else if strings.HasPrefix(reqURL, "https:") {
		preqURL = reqURL
	} else {
		preqURL = "https://" + reqURL
	}
	proxyURL, err := zedcloud.LookupProxy(log, zedcloudCtx.DeviceNetworkStatus,
		ifname, preqURL)
	if err != nil {
		ctx.ph.Print("ERROR: %s: LookupProxy failed: %s\n", ifname, err)
	} else if proxyURL != nil {
		ctx.ph.Print("INFO: %s: Proxy %s to reach %s\n",
			ifname, proxyURL.String(), reqURL)
	}
	const allowProxy = true
	rv, err := zedcloud.SendOnIntf(context.Background(), zedcloudCtx,
		reqURL, ifname, reqlen, b, allowProxy, ctx.usingOnboardCert, withNetTracing, false)
	if err != nil {
		switch rv.Status {
		case types.SenderStatusUpgrade:
			ctx.ph.Print("ERROR: %s: post %s Controller upgrade in progress\n",
				ifname, reqURL)
		case types.SenderStatusRefused:
			ctx.ph.Print("ERROR: %s: post %s Controller returned ECONNREFUSED\n",
				ifname, reqURL)
		case types.SenderStatusCertInvalid:
			ctx.ph.Print("ERROR: %s: post %s Controller certificate invalid time\n",
				ifname, reqURL)
		case types.SenderStatusCertMiss:
			ctx.ph.Print("ERROR: %s: post %s Controller certificate miss\n",
				ifname, reqURL)
		default:
			ctx.ph.Print("ERROR: %s: post %s failed: %s\n",
				ifname, reqURL, err)
		}
		return false, nil, rv.Status, nil
	}

	switch rv.HTTPResp.StatusCode {
	case http.StatusOK:
		ctx.ph.Print("INFO: %s: %s StatusOK\n", ifname, reqURL)
	case http.StatusCreated:
		ctx.ph.Print("INFO: %s: %s StatusCreated\n", ifname, reqURL)
	case http.StatusNotModified:
		ctx.ph.Print("INFO: %s: %s StatusNotModified\n", ifname, reqURL)
	default:
		ctx.ph.Print("ERROR: %s: %s statuscode %d %s\n",
			ifname, reqURL, rv.HTTPResp.StatusCode,
			http.StatusText(rv.HTTPResp.StatusCode))
		ctx.ph.Print("ERROR: %s: Received %s\n",
			ifname, string(rv.RespContents))
		return false, nil, rv.Status, nil
	}
	if len(rv.RespContents) > 0 {
		err = zedcloud.RemoveAndVerifyAuthContainer(zedcloudCtx, &rv, false)
		if err != nil {
			ctx.ph.Print("ERROR: %s: %s RemoveAndVerifyAuthContainer  %s\n",
				ifname, reqURL, err)
			return false, nil, rv.Status, nil
		}
	}
	return true, rv.HTTPResp, rv.Status, rv.RespContents
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

	ctx := ctxArg.(*diagContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s", key)
	gcp := agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	if gcp != nil {
		ctx.globalConfig = gcp
	}
	ctx.GCInitialized = true
	log.Functionf("handleGlobalConfigImpl done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*diagContext)
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
