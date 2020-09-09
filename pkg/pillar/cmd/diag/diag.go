// Copyright (c) 2018,2019 Zededa, Inc.
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
	"io/ioutil"
	"mime"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/eriknordmark/ipinfo"
	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	"github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const (
	agentName  = "diag"
	maxRetries = 5
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

// State passed to handlers
type diagContext struct {
	devicenetwork.DeviceNetworkContext
	DevicePortConfigList    *types.DevicePortConfigList
	forever                 bool // Keep on reporting until ^C
	pacContents             bool // Print PAC file contents
	ledCounter              int
	derivedLedCounter       int // Based on ledCounter + usableAddressCount
	subGlobalConfig         pubsub.Subscription
	globalConfig            *types.ConfigItemValueMap
	subLedBlinkCounter      pubsub.Subscription
	subDeviceNetworkStatus  pubsub.Subscription
	subDevicePortConfigList pubsub.Subscription
	gotBC                   bool
	gotDNS                  bool
	gotDPCList              bool
	serverNameAndPort       string
	serverName              string // Without port number
	zedcloudCtx             *zedcloud.ZedCloudContext
	cert                    *tls.Certificate
	usingOnboardCert        bool
	devUUID                 uuid.UUID
}

// Set from Makefile
var Version = "No version specified"

var debug = false
var debugOverride bool // From command line arg
var simulateDnsFailure = false
var simulatePingFailure = false
var outfile = os.Stdout
var nilUUID uuid.UUID
var logger *logrus.Logger
var log *base.LogObject

func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject) int {
	logger = loggerArg
	log = logArg
	var err error
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	foreverPtr := flag.Bool("f", false, "Forever flag")
	pacContentsPtr := flag.Bool("p", false, "Print PAC file contents")
	simulateDnsFailurePtr := flag.Bool("D", false, "simulateDnsFailure flag")
	simulatePingFailurePtr := flag.Bool("P", false, "simulatePingFailure flag")
	outputFilePtr := flag.String("o", "", "file or device for output")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		logger.SetLevel(logrus.TraceLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	simulateDnsFailure = *simulateDnsFailurePtr
	simulatePingFailure = *simulatePingFailurePtr
	outputFile := *outputFilePtr
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return 0
	}
	if outputFile != "" {
		outfile, err = os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
	}
	log.Infof("Starting %s", agentName)
	ctx := diagContext{
		forever:      *foreverPtr,
		pacContents:  *pacContentsPtr,
		globalConfig: types.DefaultConfigItemValueMap(),
	}
	ctx.AgentName = agentName
	ctx.DeviceNetworkStatus = &types.DeviceNetworkStatus{}
	ctx.DevicePortConfigList = &types.DevicePortConfigList{}

	// Make sure we have a GlobalConfig file with defaults
	utils.EnsureGCFile(log)

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(
		pubsub.SubscriptionOptions{
			AgentName:     "",
			MyAgentName:   agentName,
			TopicImpl:     types.ConfigItemValueMap{},
			Activate:      false,
			Ctx:           &ctx,
			CreateHandler: handleGlobalConfigModify,
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

	server, err := ioutil.ReadFile(types.ServerFileName)
	if err != nil {
		log.Fatal(err)
	}
	ctx.serverNameAndPort = strings.TrimSpace(string(server))
	ctx.serverName = strings.Split(ctx.serverNameAndPort, ":")[0]

	zedcloudCtx := zedcloud.NewContext(log, zedcloud.ContextOptions{
		DevNetworkStatus: ctx.DeviceNetworkStatus,
		Timeout:          ctx.globalConfig.GlobalValueInt(types.NetworkSendTimeout),
		NeedStatsFunc:    true,
		Serial:           hardware.GetProductSerial(log),
		SoftSerial:       hardware.GetSoftSerial(log),
		AgentName:        agentName,
	})
	log.Infof("Diag Get Device Serial %s, Soft Serial %s", zedcloudCtx.DevSerial,
		zedcloudCtx.DevSoftSerial)

	// XXX move to later for Get UUID if available

	log.Infof("diag Run: Use V2 API %v", zedcloudCtx.V2API)

	if fileExists(types.DeviceCertName) {
		// Load device cert
		cert, err := zedcloud.GetClientCert()
		if err != nil {
			log.Fatal(err)
		}
		ctx.cert = &cert
	} else if fileExists(types.OnboardCertName) &&
		fileExists(types.OnboardKeyName) {
		cert, err := tls.LoadX509KeyPair(types.OnboardCertName,
			types.OnboardKeyName)
		if err != nil {
			log.Fatal(err)
		}
		ctx.cert = &cert
		fmt.Fprintf(outfile, "WARNING: no device cert; using onboarding cert at %v\n",
			time.Now().Format(time.RFC3339Nano))
		ctx.usingOnboardCert = true
	} else {
		fmt.Fprintf(outfile, "ERROR: no device cert and no onboarding cert at %v\n",
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
			CreateHandler: handleLedBlinkModify,
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
			CreateHandler: handleDNSModify,
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
			CreateHandler: handleDPCModify,
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
		CreateHandler: handleOnboardStatusModify,
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

	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subLedBlinkCounter.MsgChan():
			ctx.gotBC = true
			subLedBlinkCounter.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			ctx.gotDNS = true
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subOnboardStatus.MsgChan():
			subOnboardStatus.ProcessChange(change)

		case change := <-subDevicePortConfigList.MsgChan():
			ctx.gotDPCList = true
			subDevicePortConfigList.ProcessChange(change)
		}
		if !ctx.forever && ctx.gotDNS && ctx.gotBC && ctx.gotDPCList {
			break
		}
		if ctx.usingOnboardCert && fileExists(types.DeviceCertName) {
			fmt.Fprintf(outfile, "WARNING: Switching from onboard to device cert\n")
			// Load device cert
			cert, err := zedcloud.GetClientCert()
			if err != nil {
				log.Fatal(err)
			}
			ctx.cert = &cert
			ctx.usingOnboardCert = false
		}
	}
	return 0
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

// Handles both create and modify events
func handleLedBlinkModify(ctxArg interface{}, key string,
	configArg interface{}) {

	config := configArg.(types.LedBlinkCounter)
	ctx := ctxArg.(*diagContext)

	if key != "ledconfig" {
		log.Errorf("handleLedBlinkModify: ignoring %s", key)
		return
	}
	// Supress work and logging if no change
	if config.BlinkCounter == ctx.ledCounter {
		return
	}
	ctx.ledCounter = config.BlinkCounter
	ctx.derivedLedCounter = types.DeriveLedCounter(ctx.ledCounter,
		ctx.UsableAddressCount)
	log.Infof("counter %d usableAddr %d, derived %d",
		ctx.ledCounter, ctx.UsableAddressCount, ctx.derivedLedCounter)
	// XXX wait in case we get another handle call?
	// XXX set output sched in ctx; print one second later?
	printOutput(ctx)
}

// Handles both create and modify events
func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := statusArg.(types.DeviceNetworkStatus)
	ctx := ctxArg.(*diagContext)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s", key)
		return
	}
	log.Infof("handleDNSModify for %s", key)
	// Since we report test status we compare all fields
	if cmp.Equal(ctx.DeviceNetworkStatus, status) {
		log.Infof("handleDNSModify unchanged")
		return
	}
	log.Infof("handleDNSModify: changed %v",
		cmp.Diff(ctx.DeviceNetworkStatus, status))
	*ctx.DeviceNetworkStatus = status
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctx.DeviceNetworkStatus)
	log.Infof("handleDNSModify %d usable addresses", newAddrCount)
	if (ctx.UsableAddressCount == 0 && newAddrCount != 0) ||
		(ctx.UsableAddressCount != 0 && newAddrCount == 0) {
		ctx.UsableAddressCount = newAddrCount
		ctx.derivedLedCounter = types.DeriveLedCounter(ctx.ledCounter,
			ctx.UsableAddressCount)
		log.Infof("counter %d usableAddr %d, derived %d",
			ctx.ledCounter, ctx.UsableAddressCount, ctx.derivedLedCounter)
	}

	// update proxy certs if configured
	if ctx.zedcloudCtx != nil && ctx.zedcloudCtx.V2API {
		zedcloud.UpdateTLSProxyCerts(ctx.zedcloudCtx)
	}
	// XXX can we limit to interfaces which changed?
	// XXX wait in case we get another handle call?
	// XXX set output sched in ctx; print one second later?
	printOutput(ctx)
	log.Infof("handleDNSModify done for %s", key)
}

func handleDNSDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleDNSDelete for %s", key)
	ctx := ctxArg.(*diagContext)

	if key != "global" {
		log.Infof("handleDNSDelete: ignoring %s", key)
		return
	}
	*ctx.DeviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctx.DeviceNetworkStatus)
	log.Infof("handleDNSDelete %d usable addresses", newAddrCount)
	if (ctx.UsableAddressCount == 0 && newAddrCount != 0) ||
		(ctx.UsableAddressCount != 0 && newAddrCount == 0) {
		ctx.UsableAddressCount = newAddrCount
		ctx.derivedLedCounter = types.DeriveLedCounter(ctx.ledCounter,
			ctx.UsableAddressCount)
		log.Infof("counter %d usableAddr %d, derived %d",
			ctx.ledCounter, ctx.UsableAddressCount, ctx.derivedLedCounter)
	}
	// XXX wait in case we get another handle call?
	// XXX set output sched in ctx; print one second later?
	printOutput(ctx)
	log.Infof("handleDNSDelete done for %s", key)
}

// Handles both create and modify events
func handleDPCModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := statusArg.(types.DevicePortConfigList)
	ctx := ctxArg.(*diagContext)
	if key != "global" {
		log.Infof("handleDPCModify: ignoring %s", key)
		return
	}
	log.Infof("handleDPCModify for %s", key)
	if cmp.Equal(ctx.DevicePortConfigList, status) {
		return
	}
	log.Infof("handleDPCModify: changed %v",
		cmp.Diff(ctx.DevicePortConfigList, status))
	*ctx.DevicePortConfigList = status
	// XXX can we limit to interfaces which changed?
	// XXX exclude if only timestamps changed?
	// XXX wait in case we get another handle call?
	// XXX set output sched in ctx; print one second later?
	printOutput(ctx)
	log.Infof("handleDPCModify done for %s", key)
}

// Handles UUID change from process client
func handleOnboardStatusModify(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.OnboardingStatus)
	ctx := ctxArg.(*diagContext)
	if cmp.Equal(ctx.devUUID, status.DeviceUUID) {
		log.Infof("handleOnboardStatusModify no change to %v", ctx.devUUID)
		return
	}
	ctx.devUUID = status.DeviceUUID
	log.Infof("handleOnboardStatusModify changed to %v", ctx.devUUID)
	printOutput(ctx)
}

// Print output for all interfaces
// XXX can we limit to interfaces which changed?
func printOutput(ctx *diagContext) {

	// Defer until we have an initial BlinkCounter and DeviceNetworkStatus
	if !ctx.gotDNS || !ctx.gotBC || !ctx.gotDPCList {
		return
	}

	fmt.Fprintf(outfile, "\nINFO: updated diag information at %v\n",
		time.Now().Format(time.RFC3339Nano))
	// XXX certificate fingerprints? What does zedcloud use?
	if fileExists(types.SelfRegFile) {
		fmt.Fprintf(outfile, "INFO: selfRegister is still in progress\n")
		// XXX print onboarding cert
	}

	switch ctx.derivedLedCounter {
	case 0:
		fmt.Fprintf(outfile, "ERROR: Summary: Unknown LED counter 0\n")
	case 1:
		fmt.Fprintf(outfile, "ERROR: Summary: Waiting for DHCP IP address(es)\n")
	case 2:
		fmt.Fprintf(outfile, "ERROR: Summary: Trying to connect to EV Controller\n")
	case 3:
		fmt.Fprintf(outfile, "WARNING: Summary: Connected to EV Controller but not onboarded\n")
	case 4:
		fmt.Fprintf(outfile, "INFO: Summary: Connected to EV Controller and onboarded\n")
	case 10:
		fmt.Fprintf(outfile, "ERROR: Summary: Onboarding failure or conflict\n")
	case 12:
		fmt.Fprintf(outfile, "ERROR: Summary: Response without TLS - ignored\n")
	case 13:
		fmt.Fprintf(outfile, "ERROR: Summary: Response without OSCP or bad OSCP - ignored\n")
	default:
		fmt.Fprintf(outfile, "ERROR: Summary: Unsupported LED counter %d\n",
			ctx.derivedLedCounter)
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
			fmt.Fprintf(outfile, "WARNING: Have no currently working DevicePortConfig\n")
		} else if ctx.DevicePortConfigList.CurrentIndex != 0 {
			fmt.Fprintf(outfile, "WARNING: Not %s highest priority DevicePortConfig key %s due to %s\n",
				downcase, first.Key, first.LastError)
			for i, dpc := range ctx.DevicePortConfigList.PortConfigList {
				if i == 0 {
					continue
				}
				if i != ctx.DevicePortConfigList.CurrentIndex {
					fmt.Fprintf(outfile, "WARNING: Not %s priority %d DevicePortConfig key %s due to %s\n",
						downcase, i, dpc.Key, dpc.LastError)
				} else {
					fmt.Fprintf(outfile, "INFO: %s priority %d DevicePortConfig key %s\n",
						upcase, i, dpc.Key)
					break
				}
			}
			if DPCLen-1 > ctx.DevicePortConfigList.CurrentIndex {
				fmt.Fprintf(outfile, "INFO: Have %d backup DevicePortConfig\n",
					DPCLen-1-ctx.DevicePortConfigList.CurrentIndex)
			}
		} else {
			fmt.Fprintf(outfile, "INFO: %s highest priority DevicePortConfig key %s\n",
				upcase, first.Key)
			if DPCLen > 1 {
				fmt.Fprintf(outfile, "INFO: Have %d backup DevicePortConfig\n",
					DPCLen-1)
			}
		}
	}
	if testing {
		fmt.Fprintf(outfile, "WARNING: The configuration below is under test hence might report failures\n")
	}
	if ctx.DeviceNetworkStatus.State != types.DPC_SUCCESS {
		fmt.Fprintf(outfile, "WARNING: state %s not SUCCESS\n",
			ctx.DeviceNetworkStatus.State.String())
	}

	numPorts := len(ctx.DeviceNetworkStatus.Ports)
	mgmtPorts := 0
	passPorts := 0
	passOtherPorts := 0

	numMgmtPorts := len(types.GetMgmtPortsAny(*ctx.DeviceNetworkStatus, 0))
	fmt.Fprintf(outfile, "INFO: Have %d total ports. %d ports should be connected to EV controller\n", numPorts, numMgmtPorts)
	for _, port := range ctx.DeviceNetworkStatus.Ports {
		// Print usefully formatted info based on which
		// fields are set and Dhcp type; proxy info order
		ifname := port.IfName
		isMgmt := false
		isFree := false
		if types.IsFreeMgmtPort(*ctx.DeviceNetworkStatus, ifname) {
			isMgmt = true
			isFree = true
		} else if types.IsMgmtPort(*ctx.DeviceNetworkStatus, ifname) {
			isMgmt = true
		}
		if isMgmt {
			mgmtPorts += 1
		}

		typeStr := "for application use"
		if isFree {
			typeStr = "for EV Controller without usage-based charging"
		} else if isMgmt {
			typeStr = "for EV Controller"
		}
		fmt.Fprintf(outfile, "INFO: Port %s: %s\n", ifname, typeStr)
		ipCount := 0
		for _, ai := range port.AddrInfoList {
			if ai.Addr.IsLinkLocalUnicast() {
				continue
			}
			ipCount += 1
			noGeo := ipinfo.IPInfo{}
			if ai.Geo == noGeo {
				fmt.Fprintf(outfile, "INFO: %s: IP address %s not geolocated\n",
					ifname, ai.Addr)
			} else {
				fmt.Fprintf(outfile, "INFO: %s: IP address %s geolocated to %+v\n",
					ifname, ai.Addr, ai.Geo)
			}
		}
		if ipCount == 0 {
			fmt.Fprintf(outfile, "INFO: %s: No IP address\n",
				ifname)
		}

		fmt.Fprintf(outfile, "INFO: %s: DNS servers: ", ifname)
		for _, ds := range port.DNSServers {
			fmt.Fprintf(outfile, "%s, ", ds.String())
		}
		fmt.Fprintf(outfile, "\n")
		// If static print static config
		if port.Dhcp == types.DT_STATIC {
			fmt.Fprintf(outfile, "INFO: %s: Static IP subnet: %s\n",
				ifname, port.Subnet.String())
			for _, r := range port.DefaultRouters {
				fmt.Fprintf(outfile, "INFO: %s: Static IP router: %s\n",
					ifname, r.String())
			}
			fmt.Fprintf(outfile, "INFO: %s: Static Domain Name: %s\n",
				ifname, port.DomainName)
			fmt.Fprintf(outfile, "INFO: %s: Static NTP server: %s\n",
				ifname, port.NtpServer.String())
		}
		printProxy(ctx, port, ifname)

		if !isMgmt {
			fmt.Fprintf(outfile, "INFO: %s: not intended for EV controller; skipping those tests\n",
				ifname)
			continue
		}
		if ipCount == 0 {
			fmt.Fprintf(outfile, "WARNING: %s: No IP address to connect to EV controller\n",
				ifname)
			continue
		}
		// DNS lookup, ping and getUuid calls
		if !tryLookupIP(ctx, ifname) {
			continue
		}
		if !tryPing(ctx, ifname, "") {
			fmt.Fprintf(outfile, "ERROR: %s: ping failed to %s; trying google\n",
				ifname, ctx.serverNameAndPort)
			origServerName := ctx.serverName
			origServerNameAndPort := ctx.serverNameAndPort
			ctx.serverName = "www.google.com"
			ctx.serverNameAndPort = ctx.serverName
			res := tryPing(ctx, ifname, "http://www.google.com")
			if res {
				fmt.Fprintf(outfile, "WARNING: %s: Can reach http://google.com but not https://%s\n",
					ifname, origServerNameAndPort)
			} else {
				fmt.Fprintf(outfile, "ERROR: %s: Can't reach http://google.com; likely lack of Internet connectivity\n",
					ifname)
			}
			res = tryPing(ctx, ifname, "https://www.google.com")
			if res {
				fmt.Fprintf(outfile, "WARNING: %s: Can reach https://google.com but not https://%s\n",
					ifname, origServerNameAndPort)
			} else {
				fmt.Fprintf(outfile, "ERROR: %s: Can't reach https://google.com; likely lack of Internet connectivity\n",
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
			passPorts += 1
		} else {
			passOtherPorts += 1
		}
		fmt.Fprintf(outfile, "PASS: port %s fully connected to EV controller %s\n",
			ifname, ctx.serverName)
	}
	if passOtherPorts > 0 {
		fmt.Fprintf(outfile, "WARNING: %d non-management ports have connectivity to the EV controller. Is that intentional?\n", passOtherPorts)
	}
	if mgmtPorts == 0 {
		fmt.Fprintf(outfile, "ERROR: No ports specified to have EV controller connectivity\n")
	} else if passPorts == mgmtPorts {
		fmt.Fprintf(outfile, "PASS: All ports specified to have EV controller connectivity passed test\n")
	} else {
		fmt.Fprintf(outfile, "WARNING: %d out of %d ports specified to have EV controller connectivity passed test\n",
			passPorts, mgmtPorts)
	}
}

func printProxy(ctx *diagContext, port types.NetworkPortStatus,
	ifname string) {

	if devicenetwork.IsProxyConfigEmpty(port.ProxyConfig) {
		fmt.Fprintf(outfile, "INFO: %s: no http(s) proxy\n", ifname)
		return
	}
	if port.ProxyConfig.Exceptions != "" {
		fmt.Fprintf(outfile, "INFO: %s: proxy exceptions %s\n",
			ifname, port.ProxyConfig.Exceptions)
	}
	if port.HasError() {
		fmt.Fprintf(outfile, "ERROR: %s: from WPAD? %s\n",
			ifname, port.LastError)
	}
	if port.ProxyConfig.NetworkProxyEnable {
		if port.ProxyConfig.NetworkProxyURL == "" {
			if port.ProxyConfig.WpadURL == "" {
				fmt.Fprintf(outfile, "WARNING: %s: WPAD enabled but found no URL\n",
					ifname)
			} else {
				fmt.Fprintf(outfile, "INFO: %s: WPAD enabled found URL %s\n",
					ifname, port.ProxyConfig.WpadURL)
			}
		} else {
			fmt.Fprintf(outfile, "INFO: %s: WPAD fetched from %s\n",
				ifname, port.ProxyConfig.NetworkProxyURL)
		}
	}
	pacLen := len(port.ProxyConfig.Pacfile)
	if pacLen > 0 {
		fmt.Fprintf(outfile, "INFO: %s: Have PAC file len %d\n",
			ifname, pacLen)
		if ctx.pacContents {
			pacFile, err := base64.StdEncoding.DecodeString(port.ProxyConfig.Pacfile)
			if err != nil {
				errStr := fmt.Sprintf("Decoding proxy file failed: %s", err)
				log.Errorf(errStr)
			} else {
				fmt.Fprintf(outfile, "INFO: %s: PAC file:\n%s\n",
					ifname, pacFile)
			}
		}
	} else {
		for _, proxy := range port.ProxyConfig.Proxies {
			switch proxy.Type {
			case types.NPT_HTTP:
				var httpProxy string
				if proxy.Port > 0 {
					httpProxy = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
				} else {
					httpProxy = fmt.Sprintf("%s", proxy.Server)
				}
				fmt.Fprintf(outfile, "INFO: %s: http proxy %s\n",
					ifname, httpProxy)
			case types.NPT_HTTPS:
				var httpsProxy string
				if proxy.Port > 0 {
					httpsProxy = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
				} else {
					httpsProxy = fmt.Sprintf("%s", proxy.Server)
				}
				fmt.Fprintf(outfile, "INFO: %s: https proxy %s\n",
					ifname, httpsProxy)
			}
		}

		if len(port.ProxyCertPEM) > 0 {
			fmt.Fprintf(outfile, "INFO: %d proxy certificate(s)", len(port.ProxyCertPEM))
		}
	}
}

func tryLookupIP(ctx *diagContext, ifname string) bool {

	addrCount := types.CountLocalAddrAnyNoLinkLocalIf(*ctx.DeviceNetworkStatus, ifname)
	if addrCount == 0 {
		fmt.Fprintf(outfile, "ERROR: %s: DNS lookup of %s not possible since no IP address\n",
			ifname, ctx.serverName)
		return false
	}
	for retryCount := 0; retryCount < addrCount; retryCount++ {
		localAddr, err := types.GetLocalAddrAnyNoLinkLocal(*ctx.DeviceNetworkStatus,
			retryCount, ifname)
		if err != nil {
			fmt.Fprintf(outfile, "ERROR: %s: DNS lookup of %s: internal error: %s address\n",
				ifname, ctx.serverName, err)
			return false
		}
		localUDPAddr := net.UDPAddr{IP: localAddr}
		log.Debugf("tryLookupIP: using intf %s source %v", ifname, localUDPAddr)
		resolverDial := func(ctx context.Context, network, address string) (net.Conn, error) {
			log.Debugf("resolverDial %v %v", network, address)
			d := net.Dialer{LocalAddr: &localUDPAddr}
			return d.Dial(network, address)
		}
		r := net.Resolver{Dial: resolverDial, PreferGo: true,
			StrictErrors: false}
		ips, err := r.LookupIPAddr(context.Background(), ctx.serverName)
		if err != nil {
			fmt.Fprintf(outfile, "ERROR: %s: DNS lookup of %s failed: %s\n",
				ifname, ctx.serverName, err)
			continue
		}
		log.Debugf("tryLookupIP: got %d addresses", len(ips))
		if len(ips) == 0 {
			fmt.Fprintf(outfile, "ERROR: %s: DNS lookup of %s returned no answers\n",
				ifname, ctx.serverName)
			return false
		}
		for _, ip := range ips {
			fmt.Fprintf(outfile, "INFO: %s: DNS lookup of %s returned %s\n",
				ifname, ctx.serverName, ip.String())
		}
		if simulateDnsFailure {
			fmt.Fprintf(outfile, "INFO: %s: Simulate DNS lookup failure\n", ifname)
			return false
		}
		return true
	}
	// Tried all in loop
	return false
}

func tryPing(ctx *diagContext, ifname string, reqURL string) bool {

	zedcloudCtx := ctx.zedcloudCtx
	// Set the TLS config on each attempt in case it has changed due to proxies etc
	if reqURL == "" {
		reqURL = zedcloud.URLPathString(ctx.serverNameAndPort, zedcloudCtx.V2API, nilUUID, "ping")
		err := zedcloud.UpdateTLSConfig(zedcloudCtx, ctx.serverName, ctx.cert)
		if err != nil {
			errStr := fmt.Sprintf("ERROR: %s: internal UpdateTLSConfig failed %s\n",
				ifname, err)
			panic(errStr)
		}
	} else {
		err := zedcloud.UpdateTLSConfig(zedcloudCtx, ctx.serverName, ctx.cert)
		if err != nil {
			errStr := fmt.Sprintf("ERROR: %s: internal UpdateTLSConfig failed %s\n",
				ifname, err)
			panic(errStr)
		}
		zedcloudCtx.TlsConfig.InsecureSkipVerify = true
	}

	// As we ping the cloud or other URLs, don't affect the LEDs
	zedcloudCtx.NoLedManager = true

	retryCount := 0
	done := false
	var delay time.Duration
	for !done {
		time.Sleep(delay)
		done, _, _ = myGet(zedcloudCtx, reqURL, ifname, retryCount)
		if done {
			break
		}
		retryCount += 1
		if maxRetries != 0 && retryCount > maxRetries {
			fmt.Fprintf(outfile, "ERROR: %s: Exceeded %d retries for ping\n",
				ifname, maxRetries)
			return false
		}
		delay = time.Second
	}
	if simulatePingFailure {
		fmt.Fprintf(outfile, "INFO: %s: Simulate ping failure\n", ifname)
		return false
	}
	return true
}

// The most recent config hash we received
var prevConfigHash string

func tryPostUUID(ctx *diagContext, ifname string) bool {

	log.Debugf("tryPostUUID() sending hash %s", prevConfigHash)
	configRequest := &zconfig.ConfigRequest{
		ConfigHash: prevConfigHash,
	}
	b, err := proto.Marshal(configRequest)
	if err != nil {
		log.Errorln(err)
		return false
	}
	zedcloudCtx := ctx.zedcloudCtx

	reqURL := zedcloud.URLPathString(ctx.serverNameAndPort, zedcloudCtx.V2API, ctx.devUUID, "config")
	// Set the TLS config on each attempt in case it has changed due to proxies etc
	err = zedcloud.UpdateTLSConfig(zedcloudCtx, ctx.serverName, ctx.cert)
	if err != nil {
		errStr := fmt.Sprintf("ERROR: %s: internal UpdateTLSConfig failed %s\n",
			ifname, err)
		panic(errStr)
	}
	// As we ping the cloud or other URLs, don't affect the LEDs
	zedcloudCtx.NoLedManager = true
	retryCount := 0
	done := false
	rtf := types.SenderStatusNone
	var delay time.Duration
	for !done {
		time.Sleep(delay)
		var resp *http.Response
		var buf []byte
		done, resp, rtf, buf = myPost(zedcloudCtx, reqURL, ifname, retryCount,
			int64(len(b)), bytes.NewBuffer(b))
		if done {
			parsePrint(reqURL, resp, buf)
			break
		}
		if rtf == types.SenderStatusCertMiss {
			// currently only three places we need to verify envelope data
			// 1) client
			// 2) zedagent
			// 3) diag here for getting /config
			// 1) is the initial getting cloud certs, 2) rely on zedagent to refetch the cloud certs
			// if zedcloud has cert change. 3) only need to zero out the cache in zedcloudCtx and
			// it will reacquire from the updated cert file. zedagent is the only one resposible for refetching certs.
			zedcloud.ClearCloudCert(zedcloudCtx)
			return false
		}
		retryCount += 1
		if maxRetries != 0 && retryCount > maxRetries {
			fmt.Fprintf(outfile, "ERROR: %s: Exceeded %d retries for get config\n",
				ifname, maxRetries)
			return false
		}
		delay = time.Second
	}
	return true
}

func parsePrint(configURL string, resp *http.Response, contents []byte) {
	if resp.StatusCode == http.StatusNotModified {
		log.Debugf("StatusNotModified len %d", len(contents))
		return
	}

	if err := validateConfigMessage(configURL, resp); err != nil {
		log.Errorln("validateConfigMessage: ", err)
		return
	}

	configResponse, err := readConfigResponseProtoMessage(contents)
	if err != nil {
		log.Errorln("readConfigResponseProtoMessage: ", err)
		return
	}
	hash := configResponse.GetConfigHash()
	if hash == prevConfigHash {
		log.Debugf("Same ConfigHash len %d", len(contents))
		return
	}
	log.Infof("Change in ConfigHash from %s to %s", prevConfigHash, hash)
	prevConfigHash = hash
	config := configResponse.GetConfig()
	uuidStr := strings.TrimSpace(config.GetId().Uuid)
	log.Infof("Changed ConfigResponse with uuid %s", uuidStr)
}

// From zedagent/handleconfig.go
func validateConfigMessage(configURL string, r *http.Response) error {

	var ctTypeStr = "Content-Type"
	var ctTypeProtoStr = "application/x-proto-binary"

	ct := r.Header.Get(ctTypeStr)
	if ct == "" {
		return fmt.Errorf("No content-type")
	}
	mimeType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return fmt.Errorf("Get Content-type error")
	}
	switch mimeType {
	case ctTypeProtoStr:
		return nil
	default:
		return fmt.Errorf("Content-type %s not supported",
			mimeType)
	}
}

func readConfigResponseProtoMessage(contents []byte) (*zconfig.ConfigResponse, error) {
	var configResponse = &zconfig.ConfigResponse{}

	err := proto.Unmarshal(contents, configResponse)
	if err != nil {
		log.Errorf("Unmarshalling failed: %v", err)
		return nil, err
	}
	return configResponse, nil
}

// Get something without a return type; used by ping
// Returns true when done; false when retry.
// Returns the response when done. Caller can not use resp.Body but
// can use the contents []byte
func myGet(zedcloudCtx *zedcloud.ZedCloudContext, reqURL string, ifname string,
	retryCount int) (bool, *http.Response, []byte) {

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
		fmt.Fprintf(outfile, "ERROR: %s: LookupProxy failed: %s\n", ifname, err)
	} else if proxyURL != nil {
		fmt.Fprintf(outfile, "INFO: %s: Proxy %s to reach %s\n",
			ifname, proxyURL.String(), reqURL)
	}
	const allowProxy = true
	resp, contents, rtf, err := zedcloud.SendOnIntf(zedcloudCtx,
		reqURL, ifname, 0, nil, allowProxy)
	if err != nil {
		switch rtf {
		case types.SenderStatusUpgrade:
			fmt.Fprintf(outfile, "ERROR: %s: get %s Controller upgrade in progress\n",
				ifname, reqURL)
		case types.SenderStatusRefused:
			fmt.Fprintf(outfile, "ERROR: %s: get %s Controller returned ECONNREFUSED\n",
				ifname, reqURL)
		case types.SenderStatusCertInvalid:
			fmt.Fprintf(outfile, "ERROR: %s: get %s Controller certificate invalid time\n",
				ifname, reqURL)
		case types.SenderStatusCertMiss:
			fmt.Fprintf(outfile, "ERROR: %s: get %s Controller certificate miss\n",
				ifname, reqURL)
		default:
			fmt.Fprintf(outfile, "ERROR: %s: get %s failed: %s\n",
				ifname, reqURL, err)
		}
		return false, nil, nil
	}

	switch resp.StatusCode {
	case http.StatusOK:
		fmt.Fprintf(outfile, "INFO: %s: %s StatusOK\n", ifname, reqURL)
		return true, resp, contents
	case http.StatusNotModified:
		fmt.Fprintf(outfile, "INFO: %s: %s StatusNotModified\n", ifname, reqURL)
		return true, resp, contents
	default:
		fmt.Fprintf(outfile, "ERROR: %s: %s statuscode %d %s\n",
			ifname, reqURL, resp.StatusCode,
			http.StatusText(resp.StatusCode))
		fmt.Fprintf(outfile, "ERRROR: %s: Received %s\n",
			ifname, string(contents))
		return false, nil, nil
	}
}

func myPost(zedcloudCtx *zedcloud.ZedCloudContext, reqURL string, ifname string,
	retryCount int, reqlen int64, b *bytes.Buffer) (bool, *http.Response, types.SenderResult, []byte) {

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
		fmt.Fprintf(outfile, "ERROR: %s: LookupProxy failed: %s\n", ifname, err)
	} else if proxyURL != nil {
		fmt.Fprintf(outfile, "INFO: %s: Proxy %s to reach %s\n",
			ifname, proxyURL.String(), reqURL)
	}
	const allowProxy = true
	resp, contents, rtf, err := zedcloud.SendOnIntf(zedcloudCtx,
		reqURL, ifname, reqlen, b, allowProxy)
	if err != nil {
		switch rtf {
		case types.SenderStatusUpgrade:
			fmt.Fprintf(outfile, "ERROR: %s: post %s Controller upgrade in progress\n",
				ifname, reqURL)
		case types.SenderStatusRefused:
			fmt.Fprintf(outfile, "ERROR: %s: post %s Controller returned ECONNREFUSED\n",
				ifname, reqURL)
		case types.SenderStatusCertInvalid:
			fmt.Fprintf(outfile, "ERROR: %s: post %s Controller certificate invalid time\n",
				ifname, reqURL)
		case types.SenderStatusCertMiss:
			fmt.Fprintf(outfile, "ERROR: %s: post %s Controller certificate miss\n",
				ifname, reqURL)
		default:
			fmt.Fprintf(outfile, "ERROR: %s: post %s failed: %s\n",
				ifname, reqURL, err)
		}
		return false, nil, rtf, nil
	}

	switch resp.StatusCode {
	case http.StatusOK:
		fmt.Fprintf(outfile, "INFO: %s: %s StatusOK\n", ifname, reqURL)
		return true, resp, rtf, contents
	case http.StatusNotModified:
		fmt.Fprintf(outfile, "INFO: %s: %s StatusNotModified\n", ifname, reqURL)
		return true, resp, rtf, contents
	default:
		fmt.Fprintf(outfile, "ERROR: %s: %s statuscode %d %s\n",
			ifname, reqURL, resp.StatusCode,
			http.StatusText(resp.StatusCode))
		fmt.Fprintf(outfile, "ERRROR: %s: Received %s\n",
			ifname, string(contents))
		return false, nil, rtf, nil
	}
}

// Handles both create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*diagContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s", key)
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride, logger)
	if gcp != nil {
		ctx.globalConfig = gcp
	}
	log.Infof("handleGlobalConfigModify done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*diagContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s", key)
	debug, _ = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride, logger)
	*ctx.globalConfig = *types.DefaultConfigItemValueMap()
	log.Infof("handleGlobalConfigDelete done for %s", key)
}
