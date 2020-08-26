// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/api/go/register"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	"github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const (
	agentName   = "zedclient"
	maxDelay    = time.Second * 600 // 10 minutes
	uuidMaxWait = time.Second * 60  // 1 minute
	// Time limits for event loop handlers
	errorTime     = 3 * time.Minute
	warningTime   = 40 * time.Second
	bailOnHTTPErr = false // For 4xx and 5xx HTTP errors we try other interfaces
)

// Really a constant
var nilUUID uuid.UUID

// Set from Makefile
var Version = "No version specified"

// Assumes the config files are in IdentityDirname, which is /config
// by default. The files are
//  root-certificate.pem	Root CA cert(s) for object signing
//  server			Fixed? Written if redirected. factory-root-cert?
//  onboard.cert.pem, onboard.key.pem	Per device onboarding certificate/key
//  		   		for selfRegister operation
//  device.cert.pem,
//  device.key.pem		Device certificate/key created before this
//  		     		client is started.
//  uuid			Written by getUuid operation
//  hardwaremodel		Written by getUuid if server returns a hardwaremodel
//  enterprise			Written by getUuid if server returns an enterprise
//  name			Written by getUuid if server returns a name
//
//

type clientContext struct {
	subDeviceNetworkStatus pubsub.Subscription
	deviceNetworkStatus    *types.DeviceNetworkStatus
	usableAddressCount     int
	networkState           types.PendDPCStatus
	subGlobalConfig        pubsub.Subscription
	globalConfig           *types.ConfigItemValueMap
	zedcloudCtx            *zedcloud.ZedCloudContext
	getCertsTimer          *time.Timer
}

var (
	debug             = false
	debugOverride     bool // From command line arg
	serverNameAndPort string
	onboardTLSConfig  *tls.Config
	devtlsConfig      *tls.Config
	log               *base.LogObject
)

func Run(ps *pubsub.PubSub) int { //nolint:gocyclo
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	noPidPtr := flag.Bool("p", false, "Do not check for running client")
	maxRetriesPtr := flag.Int("r", 0, "Max retries")
	flag.Parse()

	versionFlag := *versionPtr
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
	noPidFlag := *noPidPtr
	maxRetries := *maxRetriesPtr
	args := flag.Args()
	if versionFlag {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return 0
	}
	// Sending json log format to stdout
	// XXX Make logrus record a noticable global source
	agentlog.Init("xyzzy-" + agentName)

	log = agentlog.Init("client")
	if !noPidFlag {
		if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
			log.Fatal(err)
		}
	}
	log.Infof("Starting %s", agentName)
	operations := map[string]bool{
		"selfRegister": false,
		"getUuid":      false,
	}
	for _, op := range args {
		if _, ok := operations[op]; ok {
			operations[op] = true
		} else {
			log.Errorf("Unknown arg %s", op)
			log.Fatal("Usage: " + os.Args[0] +
				"[-o] [<operations>...]")
		}
	}

	hardwaremodelFileName := types.IdentityDirname + "/hardwaremodel"
	enterpriseFileName := types.IdentityDirname + "/enterprise"
	nameFileName := types.IdentityDirname + "/name"

	cms := zedcloud.GetCloudMetrics(log) // Need type of data
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: cms,
	})
	if err != nil {
		log.Fatal(err)
	}

	pubOnboardStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		TopicType:  types.OnboardingStatus{},
		Persistent: true,
	})

	var oldUUID uuid.UUID
	b, err := ioutil.ReadFile(types.UUIDFileName)
	if err == nil {
		uuidStr := strings.TrimSpace(string(b))
		oldUUID, err = uuid.FromString(uuidStr)
		if err != nil {
			log.Warningf("Malformed UUID file ignored: %s", err)
		}
	}
	// Check if we have a /config/hardwaremodel file
	oldHardwaremodel := hardware.GetHardwareModelOverride(log)

	clientCtx := clientContext{
		deviceNetworkStatus: &types.DeviceNetworkStatus{},
		globalConfig:        types.DefaultConfigItemValueMap(),
	}

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "",
		CreateHandler: handleGlobalConfigModify,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		Activate:      false,
		TopicImpl:     types.ConfigItemValueMap{},
		Ctx:           &clientCtx,
	})
	if err != nil {
		log.Fatal(err)
	}
	clientCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	subDeviceNetworkStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler: handleDNSModify,
		ModifyHandler: handleDNSModify,
		DeleteHandler: handleDNSDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		AgentName:     "nim",
		TopicImpl:     types.DeviceNetworkStatus{},
		Ctx:           &clientCtx,
	})
	if err != nil {
		log.Fatal(err)
	}
	clientCtx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()
	zedcloudCtx := zedcloud.NewContext(log, zedcloud.ContextOptions{
		DevNetworkStatus: clientCtx.deviceNetworkStatus,
		Timeout:          clientCtx.globalConfig.GlobalValueInt(types.NetworkSendTimeout),
		NeedStatsFunc:    true,
		Serial:           hardware.GetProductSerial(log),
		SoftSerial:       hardware.GetSoftSerial(log),
		AgentName:        agentName,
	})

	clientCtx.zedcloudCtx = &zedcloudCtx
	log.Infof("Client Get Device Serial %s, Soft Serial %s", zedcloudCtx.DevSerial,
		zedcloudCtx.DevSoftSerial)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Wait for a usable IP address.
	// After 5 seconds we check; if we already have a UUID we proceed.
	// That ensures that we will start zedagent and it will check
	// the cloudGoneTime if we are doing an imake update.
	t1 := time.NewTimer(5 * time.Second)

	ticker := flextimer.NewExpTicker(time.Second, maxDelay, 0.0)

	// XXX redo in ticker case to handle change to servername?
	server, err := ioutil.ReadFile(types.ServerFileName)
	if err != nil {
		log.Fatal(err)
	}
	serverNameAndPort = strings.TrimSpace(string(server))
	serverName := strings.Split(serverNameAndPort, ":")[0]

	var onboardCert tls.Certificate
	var deviceCertPem []byte
	var gotServerCerts bool

	if operations["selfRegister"] {
		var err error
		onboardCert, err = tls.LoadX509KeyPair(types.OnboardCertName,
			types.OnboardKeyName)
		if err != nil {
			log.Fatal(err)
		}
		onboardTLSConfig, err = zedcloud.GetTlsConfig(zedcloudCtx.DeviceNetworkStatus,
			serverName, &onboardCert, &zedcloudCtx)
		if err != nil {
			log.Fatal(err)
		}
		// Load device text cert for upload
		deviceCertPem, err = ioutil.ReadFile(types.DeviceCertName)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Load device cert
	deviceCert, err := zedcloud.GetClientCert()
	if err != nil {
		log.Fatal(err)
	}
	devtlsConfig, err = zedcloud.GetTlsConfig(zedcloudCtx.DeviceNetworkStatus,
		serverName, &deviceCert, &zedcloudCtx)
	if err != nil {
		log.Fatal(err)
	}

	done := false
	var devUUID uuid.UUID
	var hardwaremodel string
	var enterprise string
	var name string
	gotUUID := false
	gotRegister := false
	retryCount := 0
	clientCtx.getCertsTimer = time.NewTimer(1 * time.Second)
	clientCtx.getCertsTimer.Stop()

	for !done {
		log.Infof("Waiting for usableAddressCount %d networkState %s and done %v",
			clientCtx.usableAddressCount, clientCtx.networkState.String(), done)
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case <-ticker.C:
			if clientCtx.networkState != types.DPC_SUCCESS &&
				clientCtx.networkState != types.DPC_FAIL_WITH_IPANDDNS {
				log.Infof("ticker and networkState %s usableAddressCount %d",
					clientCtx.networkState.String(),
					clientCtx.usableAddressCount)
				// We keep exponential unchanged
				break
			}

			// try to fetch the server certs chain first, if it's V2
			if !gotServerCerts && zedcloudCtx.V2API {
				gotServerCerts = fetchCertChain(&zedcloudCtx, devtlsConfig, retryCount, true) // XXX always get certs from cloud for now
				log.Infof("client fetchCertChain, gotServerCerts %v", gotServerCerts)
				if !gotServerCerts {
					break
				}
			}

			if !gotRegister && operations["selfRegister"] {
				done = selfRegister(&zedcloudCtx, onboardTLSConfig, deviceCertPem, retryCount)
				if done {
					gotRegister = true
				}
				if !done && operations["getUuid"] {
					// Check if getUUid succeeds
					done, devUUID, hardwaremodel, enterprise, name = doGetUUID(&clientCtx, devtlsConfig, retryCount)
					if done {
						log.Infof("getUUID succeeded; selfRegister no longer needed")
						gotUUID = true
					}
				}
			}
			if !gotUUID && operations["getUuid"] {
				done, devUUID, hardwaremodel, enterprise, name = doGetUUID(&clientCtx, devtlsConfig, retryCount)
				if done {
					log.Infof("getUUID succeeded; selfRegister no longer needed")
					gotUUID = true
				}
				if oldUUID != nilUUID && retryCount > 2 {
					log.Infof("Sticking with old UUID")
					devUUID = oldUUID
					done = true
					break
				}
			}
			retryCount++
			if maxRetries != 0 && retryCount > maxRetries {
				log.Errorf("Exceeded %d retries",
					maxRetries)
				return 1
			}

		case <-t1.C:
			// If we already know a uuid we can skip waiting
			// but if the network is working we do wait
			// This might not set hardwaremodel when upgrading
			// an onboarded system without /config/hardwaremodel.
			// Unlikely to have a network outage during that
			// upgrade *and* require an override.
			if clientCtx.networkState != types.DPC_SUCCESS &&
				operations["getUuid"] && oldUUID != nilUUID {

				log.Infof("Already have a UUID %s; declaring success",
					oldUUID.String())
				done = true
			}

		case <-clientCtx.getCertsTimer.C:
			// triggered by cert miss error in doGetUUID, so the TLS is device TLSConfig
			ok := fetchCertChain(&zedcloudCtx, devtlsConfig, retryCount, true)
			log.Infof("client timer get cert chain %v", ok)

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}

	// Post loop code
	if devUUID != nilUUID {
		var trigOnboardStatus types.OnboardingStatus
		doWrite := true
		if oldUUID != nilUUID {
			if oldUUID != devUUID {
				log.Infof("Replacing existing UUID %s",
					oldUUID.String())
			} else {
				log.Infof("No change to UUID %s",
					devUUID)
				doWrite = false
			}
		} else {
			log.Infof("Got config with UUID %s", devUUID)
		}

		if doWrite {
			b := []byte(fmt.Sprintf("%s\n", devUUID))
			err = ioutil.WriteFile(types.UUIDFileName, b, 0644)
			if err != nil {
				log.Fatal("WriteFile", err, types.UUIDFileName)
			}
			log.Debugf("Wrote UUID %s", devUUID)
		}

		// always publish the latest UUID
		trigOnboardStatus.DeviceUUID = devUUID
		pubOnboardStatus.Publish("global", trigOnboardStatus)
		log.Infof("client pub OnboardStatus")

		doWrite = true
		if hardwaremodel != "" {
			if oldHardwaremodel != hardwaremodel {
				log.Infof("Replacing existing hardwaremodel %s with %s",
					oldHardwaremodel, hardwaremodel)
			} else {
				log.Infof("No change to hardwaremodel %s",
					hardwaremodel)
				doWrite = false
			}
		} else {
			log.Infof("Got config with no hardwaremodel")
			doWrite = false
		}

		if doWrite {
			// Note that no CRLF
			b := []byte(hardwaremodel)
			err = ioutil.WriteFile(hardwaremodelFileName, b, 0644)
			if err != nil {
				log.Fatal("WriteFile", err,
					hardwaremodelFileName)
			}
			log.Debugf("Wrote hardwaremodel %s", hardwaremodel)
		}
		// We write the strings even if empty to make sure we have the most
		// recents. Since this is for debug use we are less careful
		// than for the hardwaremodel.
		b = []byte(enterprise) // Note that no CRLF
		err = ioutil.WriteFile(enterpriseFileName, b, 0644)
		if err != nil {
			log.Fatal("WriteFile", err, enterpriseFileName)
		}
		log.Debugf("Wrote enterprise %s", enterprise)
		b = []byte(name) // Note that no CRLF
		err = ioutil.WriteFile(nameFileName, b, 0644)
		if err != nil {
			log.Fatal("WriteFile", err, nameFileName)
		}
		log.Debugf("Wrote name %s", name)
	}

	err = pub.Publish("global", zedcloud.GetCloudMetrics(log))
	if err != nil {
		log.Errorln(err)
	}
	return 0
}

// Post something without a return type.
// Returns true when done; false when retry
// the third return value is the extra send status, for Cert Miss status for example
func myPost(zedcloudCtx *zedcloud.ZedCloudContext, tlsConfig *tls.Config,
	requrl string, retryCount int, reqlen int64, b *bytes.Buffer) (bool, *http.Response, types.SenderResult, []byte) {

	senderStatus := types.SenderStatusNone
	zedcloudCtx.TlsConfig = tlsConfig
	resp, contents, rtf, err := zedcloud.SendOnAllIntf(zedcloudCtx,
		requrl, reqlen, b, retryCount, bailOnHTTPErr)
	if err != nil {
		switch rtf {
		case types.SenderStatusUpgrade:
			log.Infof("Controller upgrade in progress")
		case types.SenderStatusRefused:
			log.Infof("Controller returned ECONNREFUSED")
		case types.SenderStatusCertInvalid:
			log.Warnf("Controller certificate invalid time")
		case types.SenderStatusCertMiss:
			log.Infof("Controller certificate miss")
		default:
			log.Error(err)
		}
		return false, resp, rtf, contents
	}

	if !zedcloudCtx.NoLedManager {
		// Inform ledmanager about cloud connectivity
		utils.UpdateLedManagerConfig(log, 3)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		if !zedcloudCtx.NoLedManager {
			// Inform ledmanager about existence in cloud
			utils.UpdateLedManagerConfig(log, 4)
		}
		log.Infof("%s StatusOK", requrl)
	case http.StatusCreated:
		if !zedcloudCtx.NoLedManager {
			// Inform ledmanager about existence in cloud
			utils.UpdateLedManagerConfig(log, 4)
		}
		log.Infof("%s StatusCreated", requrl)
	case http.StatusConflict:
		if !zedcloudCtx.NoLedManager {
			// Inform ledmanager about brokenness
			utils.UpdateLedManagerConfig(log, 10)
		}
		log.Errorf("%s StatusConflict", requrl)
		// Retry until fixed
		log.Errorf("%s", string(contents))
		return false, resp, senderStatus, contents
	case http.StatusNotFound, http.StatusUnauthorized, http.StatusNotModified:
		// Caller needs to handle
		return false, resp, senderStatus, contents
	default:
		log.Errorf("%s statuscode %d %s",
			requrl, resp.StatusCode,
			http.StatusText(resp.StatusCode))
		log.Errorf("%s", string(contents))
		return false, resp, senderStatus, contents
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		log.Errorf("%s no content-type", requrl)
		return false, resp, senderStatus, contents
	}
	mimeType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		log.Errorf("%s ParseMediaType failed %v", requrl, err)
		return false, resp, senderStatus, contents
	}
	switch mimeType {
	case "application/x-proto-binary", "application/json", "text/plain":
		log.Debugf("Received reply %s", string(contents))
	default:
		log.Errorln("Incorrect Content-Type " + mimeType)
		return false, resp, senderStatus, contents
	}
	return true, resp, senderStatus, contents
}

// Returns true when done; false when retry
func selfRegister(zedcloudCtx *zedcloud.ZedCloudContext, tlsConfig *tls.Config, deviceCertPem []byte, retryCount int) bool {
	// XXX add option to get this from a file in /config + override
	// logic
	productSerial := hardware.GetProductSerial(log)
	productSerial = strings.TrimSpace(productSerial)
	softSerial := hardware.GetSoftSerial(log)
	softSerial = strings.TrimSpace(softSerial)
	log.Infof("ProductSerial %s, SoftwareSerial %s", productSerial, softSerial)

	registerCreate := &register.ZRegisterMsg{
		PemCert:    []byte(base64.StdEncoding.EncodeToString(deviceCertPem)),
		Serial:     productSerial,
		SoftSerial: softSerial,
	}
	b, err := proto.Marshal(registerCreate)
	if err != nil {
		log.Errorln(err)
		return false
	}
	// in V2 API, register does not send UUID string
	requrl := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API, nilUUID, "register")
	done, resp, _, contents := myPost(zedcloudCtx, tlsConfig,
		requrl, retryCount,
		int64(len(b)), bytes.NewBuffer(b))
	if resp != nil && resp.StatusCode == http.StatusNotModified {
		if !zedcloudCtx.NoLedManager {
			// Inform ledmanager about brokenness
			utils.UpdateLedManagerConfig(log, 10)
		}
		log.Errorf("%s StatusNotModified", requrl)
		// Retry until fixed
		log.Errorf("%s", string(contents))
		done = false
	}

	return done
}

// fetch V2 certs from cloud, return GotCloudCerts and ServerIsV1 boolean
// if got certs, the leaf is saved to types.ServerSigningCertFileName file
func fetchCertChain(zedcloudCtx *zedcloud.ZedCloudContext, tlsConfig *tls.Config, retryCount int, force bool) bool {
	var resp *http.Response
	var contents []byte
	var done bool

	if !force {
		_, err := os.Stat(types.ServerSigningCertFileName)
		if err == nil {
			return true
		}
	}

	// certs API is always V2, and without UUID, use https
	requrl := zedcloud.URLPathString(serverNameAndPort, true, nilUUID, "certs")
	// currently there is no data included for the request, same as myGet()
	done, resp, _, contents = myPost(zedcloudCtx, tlsConfig, requrl, retryCount, 0, nil)
	if resp != nil {
		log.Infof("client fetchCertChain done %v, resp-code %d, content len %d", done, resp.StatusCode, len(contents))
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized ||
			resp.StatusCode == http.StatusNotImplemented || resp.StatusCode == http.StatusBadRequest {
			// cloud server does not support V2 API
			log.Infof("client fetchCertChain: server %s does not support V2 API", serverNameAndPort)
			return false
		}
		// catch default return status, if not done, will return false later
		log.Infof("client fetchCertChain: server %s return status %s, done %v", serverNameAndPort, resp.Status, done)
	} else {
		log.Infof("client fetchCertChain done %v, resp null, content len %d", done, len(contents))
	}
	if !done {
		return false
	}

	zedcloudCtx.TlsConfig = tlsConfig
	// verify the certificate chain
	certBytes, err := zedcloud.VerifySigningCertChain(zedcloudCtx, contents)
	if err != nil {
		errStr := fmt.Sprintf("controller certificate signature verify fail, %v", err)
		log.Errorln("fetchCertChain: " + errStr)
		return false
	}

	// write the signing cert to file
	if err := zedcloud.UpdateServerCert(zedcloudCtx, certBytes); err != nil {
		errStr := fmt.Sprintf("%v", err)
		log.Errorln("fetchCertChain: " + errStr)
		return false
	}

	log.Infof("client fetchCertChain: ok")
	return true
}

func doGetUUID(ctx *clientContext, tlsConfig *tls.Config,
	retryCount int) (bool, uuid.UUID, string, string, string) {

	var resp *http.Response
	var contents []byte
	var rtf types.SenderResult
	zedcloudCtx := ctx.zedcloudCtx

	// get UUID does not have UUID string in V2 API
	requrl := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API, nilUUID, "config")
	b, err := generateConfigRequest()
	if err != nil {
		log.Errorln(err)
		return false, nilUUID, "", "", ""
	}
	var done bool
	done, resp, rtf, contents = myPost(zedcloudCtx, tlsConfig, requrl, retryCount,
		int64(len(b)), bytes.NewBuffer(b))
	if resp != nil && resp.StatusCode == http.StatusNotModified {
		// Acceptable response for a ConfigRequest POST
		done = true
	}
	if !done {
		// This may be due to the cloud cert file is stale, since the hash does not match.
		// acquire new cert chain.
		if rtf == types.SenderStatusCertMiss {
			interval := time.Duration(1)
			ctx.getCertsTimer = time.NewTimer(interval * time.Second)
			log.Infof("doGetUUID: Cert miss. Setup timer to acquire")
		}
		return false, nilUUID, "", "", ""
	}
	log.Infof("doGetUUID: client getUUID ok")
	devUUID, hardwaremodel, enterprise, name, err := parseConfig(requrl, resp, contents)
	if err == nil {
		// Inform ledmanager about config received from cloud
		if !zedcloudCtx.NoLedManager {
			utils.UpdateLedManagerConfig(log, 4)
		}
		return true, devUUID, hardwaremodel, enterprise, name
	}
	// Keep on trying until it parses
	log.Errorf("Failed parsing uuid: %s", err)
	return false, nilUUID, "", "", ""
}

// Handles both create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*clientContext)
	if key != "global" {
		log.Debugf("handleGlobalConfigModify: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s", key)
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride)
	if gcp != nil {
		ctx.globalConfig = gcp
	}
	log.Infof("handleGlobalConfigModify done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*clientContext)
	if key != "global" {
		log.Debugf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s", key)
	debug, _ = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride)
	*ctx.globalConfig = *types.DefaultConfigItemValueMap()
	log.Infof("handleGlobalConfigDelete done for %s", key)
}

// Handles both create and modify events
func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := statusArg.(types.DeviceNetworkStatus)
	ctx := ctxArg.(*clientContext)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s", key)
		return
	}
	log.Infof("handleDNSModify for %s", key)
	// Ignore test status and timestamps
	if ctx.deviceNetworkStatus.Equal(status) {
		log.Infof("handleDNSModify no change")
		return
	}

	log.Infof("handleDNSModify: changed %v",
		cmp.Diff(ctx.deviceNetworkStatus, status))
	*ctx.deviceNetworkStatus = status
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctx.deviceNetworkStatus)

	if newAddrCount != ctx.usableAddressCount {
		log.Infof("DeviceNetworkStatus from %d to %d addresses",
			ctx.usableAddressCount, newAddrCount)
		// ledmanager subscribes to DeviceNetworkStatus to see changes
		ctx.usableAddressCount = newAddrCount
	}
	if ctx.deviceNetworkStatus.State != ctx.networkState {
		log.Infof("DeviceNetworkStatus state from %s to %s",
			ctx.deviceNetworkStatus.State.String(), ctx.networkState.String())
		ctx.networkState = ctx.deviceNetworkStatus.State
	}

	// update proxy certs if configured
	ctx.zedcloudCtx.DeviceNetworkStatus = &status
	// if there is proxy certs change, needs to update both
	// onboard and device tlsconfig
	cloudCtx := zedcloud.NewContext(log, zedcloud.ContextOptions{
		DevNetworkStatus: ctx.zedcloudCtx.DeviceNetworkStatus,
		TLSConfig:        devtlsConfig,
		AgentName:        agentName,
	})
	cloudCtx.PrevCertPEM = ctx.zedcloudCtx.PrevCertPEM
	updated := zedcloud.UpdateTLSProxyCerts(&cloudCtx)
	if updated {
		if onboardTLSConfig != nil {
			onboardTLSConfig.RootCAs = cloudCtx.TlsConfig.RootCAs
		}
		devtlsConfig.RootCAs = cloudCtx.TlsConfig.RootCAs
		log.Infof("handleDNSModify: client rootCAs updated")
	}

	log.Infof("handleDNSModify done for %s", key)
}

func handleDNSDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleDNSDelete for %s", key)
	ctx := ctxArg.(*clientContext)

	if key != "global" {
		log.Infof("handleDNSDelete: ignoring %s", key)
		return
	}
	*ctx.deviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctx.deviceNetworkStatus)
	ctx.usableAddressCount = newAddrCount
	log.Infof("handleDNSDelete done for %s", key)
}
