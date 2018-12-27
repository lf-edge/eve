// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Utility to dump diagnostic information about connectivity

package diag

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/eriknordmark/ipinfo"
	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/devicenetwork"
	"github.com/zededa/go-provision/hardware"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/zedcloud"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	agentName       = "diag"
	tmpDirname      = "/var/tmp/zededa"
	AADirname       = tmpDirname + "/AssignableAdapters"
	DNCDirname      = tmpDirname + "/DeviceNetworkConfig"
	identityDirname = "/config"
	selfRegFile     = identityDirname + "/self-register-failed"
	serverFileName  = identityDirname + "/server"
	deviceCertName  = identityDirname + "/device.cert.pem"
	deviceKeyName   = identityDirname + "/device.key.pem"
	maxRetries      = 5
)

// State passed to handlers
type diagContext struct {
	devicenetwork.DeviceNetworkContext
	forever                bool // Keep on reporting until ^C
	ledCounter             int  // Supress work and output
	subGlobalConfig        *pubsub.Subscription
	subLedBlinkCounter     *pubsub.Subscription
	subDeviceNetworkStatus *pubsub.Subscription
	gotBC                  bool
	gotDNS                 bool
	serverNameAndPort      string
	serverName             string // Without port number
	zedcloudCtx            *zedcloud.ZedCloudContext
}

// Set from Makefile
var Version = "No version specified"

var debug = false
var debugOverride bool // From command line arg

func Run() {
	logf, err := agentlog.Init(agentName)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	stdoutPtr := flag.Bool("s", false, "Use stdout")
	foreverPtr := flag.Bool("f", false, "Forever flag")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	useStdout := *stdoutPtr
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	if useStdout {
		multi := io.MultiWriter(logf, os.Stdout)
		log.SetOutput(multi)
	}

	ctx := diagContext{forever: *foreverPtr}
	ctx.DeviceNetworkStatus = &types.DeviceNetworkStatus{}

	// XXX should we subscribe to and get GlobalConfig for debug??

	server, err := ioutil.ReadFile(serverFileName)
	if err != nil {
		log.Fatal(err)
	}
	ctx.serverNameAndPort = strings.TrimSpace(string(server))
	ctx.serverName = strings.Split(ctx.serverNameAndPort, ":")[0]

	zedcloudCtx := zedcloud.ZedCloudContext{
		DeviceNetworkStatus: ctx.DeviceNetworkStatus,
		FailureFunc:         zedcloud.ZedCloudFailure,
		SuccessFunc:         zedcloud.ZedCloudSuccess,
	}
	deviceCert, err := tls.LoadX509KeyPair(deviceCertName, deviceKeyName)
	if err != nil {
		log.Fatal(err)
	}
	tlsConfig, err := zedcloud.GetTlsConfig(ctx.serverName, &deviceCert)
	if err != nil {
		log.Fatal(err)
	}
	zedcloudCtx.TlsConfig = tlsConfig
	ctx.zedcloudCtx = &zedcloudCtx

	savedHardwareModel := hardware.GetHardwareModelOverride()
	hardwareModel := hardware.GetHardwareModelNoOverride()
	if savedHardwareModel != hardwareModel {
		fmt.Printf("INFO: dmidecode model string %s overridden as %s\n",
			hardwareModel, savedHardwareModel)
	}
	if !DNCExists(savedHardwareModel) {
		fmt.Printf("ERROR: /config/hardwaremodel %s does not exist in /var/tmp/zededa/DeviceNetworkConfig\n",
			savedHardwareModel)
		fmt.Printf("NOTE: Device is using /var/tmp/zededa/DeviceNetworkConfig/default.json\n")
	}
	if !AAExists(savedHardwareModel) {
		fmt.Printf("ERROR: /config/hardwaremodel %s does not exist in /var/tmp/zededa/AssignableAdapters\n",
			savedHardwareModel)
		fmt.Printf("NOTE: Device is using /var/tmp/zededa/AssignableAdapters/default.json\n")
	}
	if !DNCExists(hardwareModel) {
		fmt.Printf("INFO: dmidecode model %s does not exist in /var/tmp/zededa/DeviceNetworkConfig\n",
			hardwareModel)
	}
	if !AAExists(hardwareModel) {
		fmt.Printf("INFO: dmidecode model %s does not exist in /var/tmp/zededa/AssignableAdapters\n",
			hardwareModel)
	}
	// XXX certificate fingerprints? What does zedcloud use?
	if fileExists(selfRegFile) {
		fmt.Printf("INFO: selfRegister is still in progress\n")
		// XXX print onboarding cert
	}

	// XXX print any override.json; subscribe and wait for sync??
	// XXX print all DevicePortConfig's? Changes?

	subLedBlinkCounter, err := pubsub.Subscribe("", types.LedBlinkCounter{},
		false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subLedBlinkCounter.ModifyHandler = handleLedBlinkModify
	ctx.subLedBlinkCounter = subLedBlinkCounter
	subLedBlinkCounter.Activate()

	subDeviceNetworkStatus, err := pubsub.Subscribe("nim",
		types.DeviceNetworkStatus{}, false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkStatus.ModifyHandler = handleDNSModify
	subDeviceNetworkStatus.DeleteHandler = handleDNSDelete
	ctx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	for {
		select {
		case change := <-subLedBlinkCounter.C:
			ctx.gotBC = true
			subLedBlinkCounter.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.C:
			ctx.gotDNS = true
			subDeviceNetworkStatus.ProcessChange(change)
		}
		if !ctx.forever && ctx.gotDNS && ctx.gotBC {
			break
		}
	}
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func DNCExists(model string) bool {
	DNCFilename := fmt.Sprintf("%s/%s.json", DNCDirname, model)
	return fileExists(DNCFilename)
}

func AAExists(model string) bool {
	AAFilename := fmt.Sprintf("%s/%s.json", AADirname, model)
	return fileExists(AAFilename)
}

func handleLedBlinkModify(ctxArg interface{}, key string,
	configArg interface{}) {

	config := cast.CastLedBlinkCounter(configArg)
	ctx := ctxArg.(*diagContext)

	if key != "ledconfig" {
		log.Errorf("handleLedBlinkModify: ignoring %s\n", key)
		return
	}
	// Supress work and logging if no change
	if config.BlinkCounter == ctx.ledCounter {
		return
	}
	ctx.ledCounter = config.BlinkCounter
	printOutput(ctx)
}

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := cast.CastDeviceNetworkStatus(statusArg)
	ctx := ctxArg.(*diagContext)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleDNSModify for %s\n", key)
	if cmp.Equal(ctx.DeviceNetworkStatus, status) {
		return
	}
	log.Infof("handleDNSModify: changed %v",
		cmp.Diff(ctx.DeviceNetworkStatus, status))
	*ctx.DeviceNetworkStatus = status
	// XXX can we limit to interfaces which changed?
	printOutput(ctx)
	log.Infof("handleDNSModify done for %s\n", key)
}

func handleDNSDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleDNSDelete for %s\n", key)
	ctx := ctxArg.(*diagContext)

	if key != "global" {
		log.Infof("handleDNSDelete: ignoring %s\n", key)
		return
	}
	*ctx.DeviceNetworkStatus = types.DeviceNetworkStatus{}
	printOutput(ctx)
	log.Infof("handleDNSDelete done for %s\n", key)
}

// Print output for all interfaces
// XXX can we limit to interfaces which changed?
func printOutput(ctx *diagContext) {

	// Defer until we have an initial BlinkCounter and DeviceNetworkStatus
	if !ctx.gotDNS || !ctx.gotBC {
		return
	}
	switch ctx.ledCounter {
	case 0:
		fmt.Printf("ERROR: Unknown LED counter 0\n")
	case 1:
		fmt.Printf("ERROR: Running but DHCP client not yet started\n")
	case 2:
		fmt.Printf("ERROR: Waiting for DHCP IP address(es)\n")
	case 3:
		fmt.Printf("WARNING: Connected to EV Controller but not onboarded\n")
	case 4:
		fmt.Printf("INFO: Connected to EV Controller and onboarded\n")
	case 10:
		fmt.Printf("ERROR: Onboarding failure or conflict\n")
	case 11:
		fmt.Printf("ERROR: Missing /var/tmp/zededa/DeviceNetworkConfig/ model file\n")
	case 12:
		fmt.Printf("ERROR: Response without TLS - ignored\n")
	case 13:
		fmt.Printf("ERROR: Response without OSCP or bad OSCP - ignored\n")
	default:
		fmt.Printf("ERROR: Unsupported LED counter %d\n",
			ctx.ledCounter)
	}

	fmt.Printf("INFO: Have %d ports\n", len(ctx.DeviceNetworkStatus.Ports))
	for _, port := range ctx.DeviceNetworkStatus.Ports {
		// Print usefully formatted info based on which
		// fields are set and Dhcp type; proxy info order
		if false {
			fmt.Printf("Port status XXX %+v\n", port)
		}
		ifname := port.IfName
		isMgmt := false
		isFree := false
		if types.IsFreeMgmtPort(*ctx.DeviceNetworkStatus, ifname) {
			isMgmt = true
			isFree = true
		} else if types.IsMgmtPort(*ctx.DeviceNetworkStatus, ifname) {
			isMgmt = true
		}
		typeStr := "Port for application use"
		if isFree {
			typeStr = "Port for EV Controller without charging"
		} else if isMgmt {
			typeStr = "Port for EV Controller"
		}
		fmt.Printf("Interface %s: %s\n", ifname, typeStr)
		for _, ai := range port.AddrInfoList {
			if ai.Addr.IsLinkLocalUnicast() {
				continue
			}
			noGeo := ipinfo.IPInfo{}
			if ai.Geo == noGeo {
				fmt.Printf("IP address %s not geolocated\n",
					ai.Addr)
			} else {
				fmt.Printf("IP address %s geolocated to %+v\n",
					ai.Addr, ai.Geo)
			}
		}
		fmt.Printf("DNS servers: ")
		for _, ds := range port.DnsServers {
			fmt.Printf("%s, ", ds.String())
		}
		fmt.Printf("\n")
		// If static print static config
		if port.Dhcp == types.DT_STATIC {
			fmt.Printf("Static IP config: %s\n",
				port.Subnet.String())
			fmt.Printf("Static IP router: %s\n",
				port.Gateway.String())
			fmt.Printf("Static Domain Name: %s\n",
				port.DomainName)
			fmt.Printf("Static NTP server: %s\n",
				port.NtpServer.String())
		}
		printProxy(port, ifname)

		// DNS lookup, ping and getUuid calls
		if !tryLookupIP(ctx, ifname) {
			continue
		}
		if !tryPing(ctx, ifname) {
			continue
		}
		if !tryGetUuid(ctx, ifname) {
			continue
		}
		fmt.Printf("INFO: port %s fully connected to EV controller\n",
			ifname)
	}
}

func printProxy(port types.NetworkPortStatus, ifname string) {

	if devicenetwork.IsProxyConfigEmpty(port.ProxyConfig) {
		log.Printf("INFO: no http(s) proxy on %s\n", ifname)
		return
	}
	if port.ProxyConfig.Exceptions != "" {
		log.Printf("INFO: proxy exceptions %s on %s\n",
			port.ProxyConfig.Exceptions, ifname)
	}
	// XXX any errors from retrieving pacfile?
	if port.ProxyConfig.NetworkProxyEnable {
		if port.ProxyConfig.NetworkProxyURL == "" {
			// XXX save the successful WPAD url in status and
			log.Printf("INFO: WPAD enabled on %s\n", ifname)
		} else {
			log.Printf("INFO: WPAD fetched from %s  on %s\n",
				port.ProxyConfig.NetworkProxyURL, ifname)
		}
	}
	pacLen := len(port.ProxyConfig.Pacfile)
	if pacLen > 0 {
		log.Printf("INFO: Have PAC file len %d on %s\n",
			pacLen, ifname)
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
				fmt.Printf("INFO: http proxy %s on %s\n",
					httpProxy, ifname)
			case types.NPT_HTTPS:
				var httpsProxy string
				if proxy.Port > 0 {
					httpsProxy = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
				} else {
					httpsProxy = fmt.Sprintf("%s", proxy.Server)
				}
				fmt.Printf("INFO: https proxy %s on %s\n",
					httpsProxy, ifname)
			}
		}
	}
}

// XXX should we make this and send.go use DNS on one interface?
func tryLookupIP(ctx *diagContext, ifname string) bool {

	ips, err := net.LookupIP(ctx.serverName)
	if err != nil {
		fmt.Printf("ERROR: DNS lookup of %s failed: %s\n",
			ctx.serverName, err)
		return false
	}
	if len(ips) == 0 {
		fmt.Printf("ERROR: DNS lookup of %s returned no answers\n",
			ctx.serverName)
		return false
	}
	for _, ip := range ips {
		fmt.Printf("INFO: DNS lookup of %s returned %s\n",
			ctx.serverName, ip.String())
	}
	return true
}

func tryPing(ctx *diagContext, ifname string) bool {

	zedcloudCtx := ctx.zedcloudCtx
	requrl := ctx.serverNameAndPort + "/api/v1/edgedevice/ping"
	// As we ping the cloud or other URLs, don't affect the LEDs
	zedcloudCtx.NoLedManager = true

	retryCount := 0
	done := false
	var delay time.Duration
	for !done {
		time.Sleep(delay)
		done, _, _ = myGet(zedcloudCtx, requrl, ifname, retryCount)
		if done {
			fmt.Printf("INFO: Get of config succeeded on %s\n",
				ifname)
			break
		}
		retryCount += 1
		if maxRetries != 0 && retryCount > maxRetries {
			fmt.Printf("ERROR: Exceeded %d retries for ping\n",
				maxRetries)
			return false
		}
		delay = time.Second
	}
	return true
}

func tryGetUuid(ctx *diagContext, ifname string) bool {

	zedcloudCtx := ctx.zedcloudCtx
	requrl := ctx.serverNameAndPort + "/api/v1/edgedevice/config"
	// As we ping the cloud or other URLs, don't affect the LEDs
	zedcloudCtx.NoLedManager = true
	retryCount := 0
	done := false
	var delay time.Duration
	for !done {
		time.Sleep(delay)
		done, _, _ = myGet(zedcloudCtx, requrl, ifname, retryCount)
		if done {
			fmt.Printf("INFO: Get of config succeeded on %s\n",
				ifname)
			break
		}
		retryCount += 1
		if maxRetries != 0 && retryCount > maxRetries {
			fmt.Printf("ERROR: Exceeded %d retries for ping\n",
				maxRetries)
			return false
		}
		delay = time.Second
	}
	return true
}

// Get something without a return type; used by ping
// Returns true when done; false when retry.
// Returns the response when done. Caller can not use resp.Body but
// can use the contents []byte
func myGet(zedcloudCtx *zedcloud.ZedCloudContext, requrl string, ifname string,
	retryCount int) (bool, *http.Response, []byte) {

	proxyUrl, err := zedcloud.LookupProxy(zedcloudCtx.DeviceNetworkStatus,
		ifname, requrl)
	if err == nil && proxyUrl != nil {
		fmt.Printf("INFO: Using proxy %s to reach %s on %s\n",
			proxyUrl.String(), requrl, ifname)
	}
	resp, contents, err := zedcloud.SendOnIntf(*zedcloudCtx,
		requrl, ifname, 0, nil, true)
	if err != nil {
		log.Errorln(err)
		return false, nil, nil
	}

	switch resp.StatusCode {
	case http.StatusOK:
		log.Infof("%s StatusOK\n", requrl)
		return true, resp, contents
	default:
		log.Errorf("%s statuscode %d %s\n",
			requrl, resp.StatusCode,
			http.StatusText(resp.StatusCode))
		log.Errorf("Received %s\n", string(contents))
		return false, nil, nil
	}
}
