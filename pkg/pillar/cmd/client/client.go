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

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/api/go/register"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

const (
	agentName   = "zedclient"
	maxDelay    = time.Second * 600 // 10 minutes
	uuidMaxWait = time.Second * 60  // 1 minute
	// Time limits for event loop handlers
	errorTime             = 3 * time.Minute
	warningTime           = 40 * time.Second
	bailOnHTTPErr         = false // For 4xx and 5xx HTTP errors we try other interfaces
	uuidFileName          = types.PersistStatusDir + "/uuid"
	hardwaremodelFileName = types.PersistStatusDir + "/hardwaremodel"
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
//

type clientContext struct {
	agentbase.AgentBase
	subDeviceNetworkStatus pubsub.Subscription
	deviceNetworkStatus    *types.DeviceNetworkStatus
	usableAddressCount     int
	networkState           types.DPCState
	subGlobalConfig        pubsub.Subscription
	globalConfig           *types.ConfigItemValueMap
	zedcloudCtx            *zedcloud.ZedCloudContext
	getCertsTimer          *time.Timer
	zedcloudMetrics        *zedcloud.AgentMetrics
	// cli options
	operations    map[string]bool
	versionPtr    *bool
	noPidPtr      *bool
	maxRetriesPtr *int
}

// AddAgentSpecificCLIFlags adds CLI options
func (ctxPtr *clientContext) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	ctxPtr.versionPtr = flagSet.Bool("v", false, "Version")
	ctxPtr.noPidPtr = flagSet.Bool("p", false, "Do not check for running client")
	ctxPtr.maxRetriesPtr = flagSet.Int("r", 0, "Max retries")
}

// ProcessAgentSpecificCLIFlags process received CLI options
func (ctxPtr *clientContext) ProcessAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	for _, op := range flagSet.Args() {
		if _, ok := ctxPtr.operations[op]; ok {
			ctxPtr.operations[op] = true
		} else {
			log.Errorf("Unknown arg %s", op)
			log.Fatal("Usage: " + agentName +
				"[-o] [<operations>...]")
		}
	}
}

var (
	serverNameAndPort string
	onboardTLSConfig  *tls.Config
	devtlsConfig      *tls.Config
	logger            *logrus.Logger
	log               *base.LogObject
)

func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string) int { //nolint:gocyclo
	logger = loggerArg
	log = logArg

	clientCtx := clientContext{
		deviceNetworkStatus: &types.DeviceNetworkStatus{},
		globalConfig:        types.DefaultConfigItemValueMap(),
		zedcloudMetrics:     zedcloud.NewAgentMetrics(),
		operations: map[string]bool{
			"selfRegister": false,
			"getUuid":      false,
		},
	}

	agentbase.Init(&clientCtx, logger, log, agentName,
		agentbase.WithArguments(arguments))

	maxRetries := *clientCtx.maxRetriesPtr
	if *clientCtx.versionPtr {
		fmt.Printf("%s: %s\n", agentName, Version)
		return 0
	}
	if !*clientCtx.noPidPtr {
		if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
			log.Fatal(err)
		}
	}

	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.MetricsMap{},
	})
	if err != nil {
		log.Fatal(err)
	}

	pubOnboardStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		TopicType:  types.OnboardingStatus{},
		Persistent: true,
	})

	// Get any existing UUID from the above pub
	var oldUUID uuid.UUID
	var oldHardwaremodel string
	item, err := pubOnboardStatus.Get("global")
	if err == nil {
		status := item.(types.OnboardingStatus)
		oldUUID = status.DeviceUUID
		oldHardwaremodel = status.HardwareModel
		log.Noticef("Found existing UUID %s and model %s",
			oldUUID, oldHardwaremodel)
	}

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		CreateHandler: handleGlobalConfigCreate,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		Activate:      false,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Ctx:           &clientCtx,
	})
	if err != nil {
		log.Fatal(err)
	}
	clientCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	subDeviceNetworkStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		CreateHandler: handleDNSCreate,
		ModifyHandler: handleDNSModify,
		DeleteHandler: handleDNSDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
		AgentName:     "nim",
		MyAgentName:   agentName,
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
		AgentMetrics:     clientCtx.zedcloudMetrics,
		Serial:           hardware.GetProductSerial(log),
		SoftSerial:       hardware.GetSoftSerial(log),
		AgentName:        agentName,
	})

	clientCtx.zedcloudCtx = &zedcloudCtx
	log.Functionf("Client Get Device Serial %s, Soft Serial %s", zedcloudCtx.DevSerial,
		zedcloudCtx.DevSoftSerial)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Wait for a usable IP address.
	// After 5 seconds we check; if we already have a UUID we proceed.
	// If there is a UUID change later then zedagent will detect it and trigger
	// re-running client.
	t1 := time.NewTimer(5 * time.Second)

	ticker := flextimer.NewExpTicker(time.Second, maxDelay, 0.0)

	server, err := ioutil.ReadFile(types.ServerFileName)
	if err != nil {
		log.Fatal(err)
	}
	serverNameAndPort = strings.TrimSpace(string(server))

	var onboardCert tls.Certificate
	var deviceCertPem []byte
	var gotServerCerts bool

	if clientCtx.operations["selfRegister"] {
		var err error
		onboardCert, err = tls.LoadX509KeyPair(types.OnboardCertName,
			types.OnboardKeyName)
		if err != nil {
			log.Fatal(err)
		}
		onboardTLSConfig, err = zedcloud.GetTlsConfig(zedcloudCtx.DeviceNetworkStatus,
			&onboardCert, &zedcloudCtx)
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
		&deviceCert, &zedcloudCtx)
	if err != nil {
		log.Fatal(err)
	}

	done := false
	var devUUID uuid.UUID
	var hardwaremodel string
	gotUUID := false
	gotRegister := false
	retryCount := 0
	clientCtx.getCertsTimer = time.NewTimer(1 * time.Second)
	clientCtx.getCertsTimer.Stop()

	// Returns non-zero if we should exit with that exit code
	// Otherwise it updates "done" when done
	tryRegister := func() int {
		if clientCtx.usableAddressCount == 0 {
			log.Noticef("tryRegister: usableAddressCount still zero")
			// We keep exponential unchanged
			return 0
		}
		if clientCtx.networkState != types.DPCStateSuccess &&
			clientCtx.networkState != types.DPCStateFailWithIPAndDNS &&
			clientCtx.networkState != types.DPCStateRemoteWait {
			log.Noticef("tryRegister: networkState %s",
				clientCtx.networkState.String())
			// We keep exponential unchanged
			return 0
		}

		// try to fetch the server certs chain first, if it's V2
		if !gotServerCerts && zedcloudCtx.V2API {
			// Set force so we re-download certs on each boot
			gotServerCerts = fetchCertChain(&zedcloudCtx, devtlsConfig, retryCount, true)
			if !gotServerCerts {
				log.Errorf("Failed to fetch certs from %s. Wrong URL?",
					serverNameAndPort)
				if !zedcloudCtx.NoLedManager {
					utils.UpdateLedManagerConfig(log, types.LedBlinkInvalidControllerCert)
				}
				return 0 // Try again later
			}
			log.Noticef("Fetched certs from %s",
				serverNameAndPort)
		}

		if !gotRegister && clientCtx.operations["selfRegister"] {
			done = selfRegister(&zedcloudCtx, onboardTLSConfig, deviceCertPem, retryCount)
			if done {
				gotRegister = true
				log.Noticef("Registered at %s",
					serverNameAndPort)
			} else {
				log.Errorf("Failed to register at %s. Wrong URL? Not activated?",
					serverNameAndPort)
			}
			if !done && clientCtx.operations["getUuid"] {
				// Check if getUUid succeeds
				done, devUUID, hardwaremodel = doGetUUID(&clientCtx, devtlsConfig, retryCount)
				if done {
					log.Noticef("getUUID succeeded; selfRegister no longer needed")
					gotUUID = true
				}
			}
		}
		if !gotUUID && clientCtx.operations["getUuid"] {
			done, devUUID, hardwaremodel = doGetUUID(&clientCtx, devtlsConfig, retryCount)
			if done {
				log.Noticef("getUUID succeeded; selfRegister no longer needed")
				gotUUID = true
			} else {
				log.Errorf("Failed to getUUID at %s. Wrong URL? Not activated?",
					serverNameAndPort)
			}
		}
		retryCount++
		if maxRetries != 0 && retryCount > maxRetries {
			log.Errorf("Exceeded %d retries", maxRetries)
			return 1
		}
		return 0
	}

	for !done {
		log.Functionf("Waiting for usableAddressCount %d networkState %s and done %v",
			clientCtx.usableAddressCount, clientCtx.networkState.String(), done)
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)
			ret := tryRegister()
			if ret != 0 {
				log.Errorf("tryRegister failed %d", ret)
				return ret
			}

		case <-ticker.C:
			// Check in case /config/server changes while running
			nserver, err := ioutil.ReadFile(types.ServerFileName)
			if err != nil {
				log.Error(err)
			} else if len(nserver) != 0 && string(server) != string(nserver) {
				log.Warnf("/config/server changed from %s to %s",
					server, nserver)
				server = nserver
				serverNameAndPort = strings.TrimSpace(string(server))
				// Force a refresh
				ok := fetchCertChain(&zedcloudCtx, devtlsConfig, retryCount, true)
				if !ok && !zedcloudCtx.NoLedManager {
					utils.UpdateLedManagerConfig(log, types.LedBlinkInvalidControllerCert)
				}
				log.Noticef("get cert chain result %t", ok)
			}
			ret := tryRegister()
			if ret != 0 {
				log.Errorf("tryRegister failed %d", ret)
				return ret
			}

		case <-t1.C:
			// If we already know a uuid we can skip waiting
			// but if the network is working we do wait
			// This might not set hardwaremodel when upgrading
			// an onboarded system
			// Unlikely to have a network outage during that
			// upgrade *and* require an override.
			if clientCtx.networkState != types.DPCStateSuccess &&
				clientCtx.operations["getUuid"] && oldUUID != nilUUID {

				log.Noticef("Already have a UUID %s; declaring success",
					oldUUID.String())
				devUUID = oldUUID
				done = true
			}

		case <-clientCtx.getCertsTimer.C:
			// triggered by cert miss error in doGetUUID, so the TLS is device TLSConfig
			ok := fetchCertChain(&zedcloudCtx, devtlsConfig, retryCount, true)
			if !ok && !zedcloudCtx.NoLedManager {
				utils.UpdateLedManagerConfig(log, types.LedBlinkInvalidControllerCert)
			}
			log.Noticef("client timer get cert chain result %t", ok)

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
				log.Functionf("Replacing existing UUID %s",
					oldUUID.String())
			} else {
				log.Functionf("No change to UUID %s",
					devUUID)
				doWrite = false
			}
		} else {
			log.Functionf("Got config with UUID %s", devUUID)
		}
		// Set the kernel hostname
		cmd := "/bin/hostname"
		cmdArgs := []string{devUUID.String()}
		log.Noticef("Calling command %s %v", cmd, cmdArgs)
		out, err := base.Exec(log, cmd, cmdArgs...).CombinedOutput()
		if err != nil {
			log.Errorf("hostname command %s failed %s output %s",
				cmdArgs, err, out)
		} else {
			log.Noticef("Set hostname to %s", devUUID.String())
		}
		_, err = os.Stat(uuidFileName)
		if err != nil {
			doWrite = true
		}
		if doWrite {
			b := []byte(fmt.Sprintf("%s\n", devUUID))
			err = ioutil.WriteFile(uuidFileName, b, 0644)
			if err != nil {
				log.Errorf("WriteFile %s failed: %v",
					uuidFileName, err)
			} else {
				log.Noticef("Wrote UUID file %s", devUUID)
			}
		}
		if hardwaremodel == "" {
			hardwaremodel = oldHardwaremodel
		}
		if hardwaremodel == "" {
			// Nothing from controller; use dmidecode etc
			hardwaremodel = hardware.GetHardwareModelNoOverride(log)
		}
		// always publish the latest UUID and hardwaremode
		trigOnboardStatus.DeviceUUID = devUUID
		trigOnboardStatus.HardwareModel = hardwaremodel

		pubOnboardStatus.Publish("global", trigOnboardStatus)
		log.Functionf("client pub OnboardStatus")

		if hardwaremodel != oldHardwaremodel {
			// Write/update file for ledmanager
			// Note that no CRLF
			b := []byte(hardwaremodel)
			err = ioutil.WriteFile(hardwaremodelFileName, b, 0644)
			if err != nil {
				log.Errorf("WriteFile %s failed: %v",
					hardwaremodelFileName, err)
			} else {
				log.Noticef("Wrote hardwaremodel %s", hardwaremodel)
			}
		}
	}

	err = clientCtx.zedcloudMetrics.Publish(log, pub, "global")
	if err != nil {
		log.Errorln(err)
	}
	log.Noticef("client done")
	return 0
}

// Post something without a return type.
// Returns true when done; false when retry
// the third return value is the extra send status, for Cert Miss status for example
func myPost(zedcloudCtx *zedcloud.ZedCloudContext, tlsConfig *tls.Config,
	requrl string, skipVerify bool, retryCount int, reqlen int64, b *bytes.Buffer) (bool, *http.Response, types.SenderResult, []byte) {

	zedcloudCtx.TlsConfig = tlsConfig
	ctxWork, cancel := zedcloud.GetContextForAllIntfFunctions(zedcloudCtx)
	defer cancel()
	resp, contents, senderStatus, err := zedcloud.SendOnAllIntf(ctxWork, zedcloudCtx,
		requrl, reqlen, b, retryCount, bailOnHTTPErr)
	if err != nil {
		switch senderStatus {
		case types.SenderStatusUpgrade:
			log.Functionf("Controller upgrade in progress")
		case types.SenderStatusRefused:
			log.Functionf("Controller returned ECONNREFUSED")
		case types.SenderStatusCertInvalid:
			log.Warnf("Controller certificate invalid time")
		case types.SenderStatusCertMiss:
			log.Functionf("Controller certificate miss")
		case types.SenderStatusNotFound:
			if !zedcloudCtx.NoLedManager {
				// Inform ledmanager about cloud connectivity
				utils.UpdateLedManagerConfig(log,
					types.LedBlinkConnectedToController)
			}
		default:
			log.Error(err)
		}
		return false, resp, senderStatus, contents
	}

	switch resp.StatusCode {
	case http.StatusOK:
		if !zedcloudCtx.NoLedManager {
			// Inform ledmanager about existence in cloud
			utils.UpdateLedManagerConfig(log, types.LedBlinkOnboarded)
		}
		log.Functionf("%s StatusOK", requrl)
	case http.StatusCreated:
		if !zedcloudCtx.NoLedManager {
			// Inform ledmanager about existence in cloud
			utils.UpdateLedManagerConfig(log, types.LedBlinkOnboarded)
		}
		log.Functionf("%s StatusCreated", requrl)
	case http.StatusConflict:
		if !zedcloudCtx.NoLedManager {
			// Inform ledmanager about brokenness
			utils.UpdateLedManagerConfig(log, types.LedBlinkOnboardingFailure)
		}
		log.Errorf("%s StatusConflict", requrl)
		// Retry until fixed
		log.Errorf("%s", string(contents))
		return false, resp, senderStatus, contents
	case http.StatusNotFound, http.StatusUnauthorized, http.StatusNotModified:
		// Caller needs to handle
		if !zedcloudCtx.NoLedManager {
			// Inform ledmanager about cloud connectivity
			utils.UpdateLedManagerConfig(log,
				types.LedBlinkConnectedToController)
		}
		return false, resp, senderStatus, contents
	default:
		if !zedcloudCtx.NoLedManager {
			// Inform ledmanager about cloud connectivity
			utils.UpdateLedManagerConfig(log,
				types.LedBlinkConnectedToController)
		}
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
		log.Tracef("Received reply %s", string(contents))
	default:
		log.Errorln("Incorrect Content-Type " + mimeType)
		return false, resp, senderStatus, contents
	}
	if len(contents) == 0 {
		return true, resp, senderStatus, contents
	}
	contents, senderStatus, err = zedcloud.RemoveAndVerifyAuthContainer(zedcloudCtx,
		requrl, contents, skipVerify, senderStatus)
	if err != nil {
		if !zedcloudCtx.NoLedManager {
			utils.UpdateLedManagerConfig(log,
				types.LedBlinkInvalidAuthContainer)
		}
		log.Errorf("RemoveAndVerifyAuthContainer failed: %s",
			err)
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
	log.Functionf("ProductSerial %s, SoftwareSerial %s", productSerial, softSerial)

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
		requrl, false, retryCount,
		int64(len(b)), bytes.NewBuffer(b))
	if resp != nil && resp.StatusCode == http.StatusNotModified {
		if !zedcloudCtx.NoLedManager {
			// Inform ledmanager about brokenness
			utils.UpdateLedManagerConfig(log, types.LedBlinkOnboardingFailure)
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
	// Save and restore since we don't want the fetch of /certs to
	// appear as if the device is onboarded.
	savedNoLedManager := zedcloudCtx.NoLedManager
	zedcloudCtx.NoLedManager = true

	// currently there is no data included for the request, same as myGet()
	done, resp, _, contents = myPost(zedcloudCtx, tlsConfig, requrl, true, retryCount, 0, nil)
	zedcloudCtx.NoLedManager = savedNoLedManager
	if resp != nil {
		log.Functionf("client fetchCertChain done %v, resp-code %d, content len %d", done, resp.StatusCode, len(contents))
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized ||
			resp.StatusCode == http.StatusNotImplemented || resp.StatusCode == http.StatusBadRequest {
			// cloud server does not support V2 API
			log.Functionf("client fetchCertChain: server %s does not support V2 API", serverNameAndPort)
			return false
		}
		// catch default return status, if not done, will return false later
		log.Functionf("client fetchCertChain: server %s return status %s, done %v", serverNameAndPort, resp.Status, done)
	} else {
		log.Functionf("client fetchCertChain done %v, resp null, content len %d", done, len(contents))
	}
	if !done {
		return false
	}

	zedcloudCtx.TlsConfig = tlsConfig
	// verify the certificate chain
	certBytes, err := zedcloud.VerifyProtoSigningCertChain(log, contents)
	if err != nil {
		errStr := fmt.Sprintf("controller certificate signature verify fail, %v", err)
		log.Errorln("fetchCertChain: " + errStr)
		return false
	}

	// write the signing cert to file
	if err := zedcloud.SaveServerSigningCert(zedcloudCtx, certBytes); err != nil {
		errStr := fmt.Sprintf("%v", err)
		log.Errorln("fetchCertChain: " + errStr)
		return false
	}

	log.Functionf("client fetchCertChain: ok")
	return true
}

func doGetUUID(ctx *clientContext, tlsConfig *tls.Config,
	retryCount int) (bool, uuid.UUID, string) {
	//First try the new /uuid api, if fails, fall back to /config API
	done, devUUID, hardwaremodel := doGetUUIDNew(ctx, tlsConfig, retryCount)
	return done, devUUID, hardwaremodel
}

func doGetUUIDNew(ctx *clientContext, tlsConfig *tls.Config,
	retryCount int) (bool, uuid.UUID, string) {
	var resp *http.Response
	var contents []byte
	var senderStatus types.SenderResult

	zedcloudCtx := ctx.zedcloudCtx

	// get UUID does not have UUID string in V2 API
	requrl := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API, nilUUID, "uuid")
	var done bool
	b, err := generateUUIDRequest()
	if err != nil {
		log.Errorln(err)
		return false, nilUUID, ""
	}
	done, resp, senderStatus, contents = myPost(zedcloudCtx, tlsConfig, requrl, false, retryCount,
		int64(len(b)), bytes.NewBuffer(b))
	if !done {
		// This may be due to the cloud cert file is stale, since the hash does not match.
		// acquire new cert chain.
		if senderStatus == types.SenderStatusCertMiss {
			ctx.getCertsTimer = time.NewTimer(time.Second)
			log.Functionf("doGetUUID: Cert miss. Setup timer to acquire")
		}
		return false, nilUUID, ""
	}
	log.Functionf("doGetUUID: client getUUID ok")
	devUUID, hardwaremodel, err := parseUUIDResponse(resp, contents)
	if err == nil {
		// Inform ledmanager about config received from cloud
		if !zedcloudCtx.NoLedManager {
			utils.UpdateLedManagerConfig(log, types.LedBlinkOnboarded)
		}
		// If successfully connected to the controller, log the peer certificates,
		// can be used to detect if it's a MiTM proxy
		if resp != nil && resp.TLS != nil {
			for i, cert := range resp.TLS.PeerCertificates {
				log.Noticef("Peer certificate:(%d) Issuer: %s, Subject: %s, NotAfter: %v",
					i, cert.Issuer, cert.Subject, cert.NotAfter)
			}
		}
		return true, devUUID, hardwaremodel
	}
	// Keep on trying until it parses
	log.Errorf("Failed parsing uuid: %s", err)
	return false, nilUUID, ""
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

	ctx := ctxArg.(*clientContext)
	if key != "global" {
		log.Tracef("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s", key)
	gcp := agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	if gcp != nil {
		ctx.globalConfig = gcp
	}
	log.Functionf("handleGlobalConfigImpl done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*clientContext)
	if key != "global" {
		log.Tracef("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigDelete for %s", key)
	agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	*ctx.globalConfig = *types.DefaultConfigItemValueMap()
	log.Functionf("handleGlobalConfigDelete done for %s", key)
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
	ctx := ctxArg.(*clientContext)
	if key != "global" {
		log.Functionf("handleDNSImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleDNSImpl for %s", key)
	// Ignore timestamps
	if ctx.deviceNetworkStatus.State == status.State && ctx.deviceNetworkStatus.MostlyEqual(status) {
		log.Functionf("handleDNSImpl no change")
		return
	}

	log.Functionf("handleDNSImpl: changed %v",
		cmp.Diff(ctx.deviceNetworkStatus, status))
	*ctx.deviceNetworkStatus = status
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctx.deviceNetworkStatus)

	if newAddrCount != ctx.usableAddressCount {
		log.Functionf("DeviceNetworkStatus from %d to %d addresses",
			ctx.usableAddressCount, newAddrCount)
		// ledmanager subscribes to DeviceNetworkStatus to see changes
		ctx.usableAddressCount = newAddrCount
	}
	if ctx.deviceNetworkStatus.State != ctx.networkState {
		log.Functionf("DeviceNetworkStatus state from %s to %s",
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
		log.Functionf("handleDNSImpl: client rootCAs updated")
	}

	log.Functionf("handleDNSImpl done for %s", key)
}

func handleDNSDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleDNSDelete for %s", key)
	ctx := ctxArg.(*clientContext)

	if key != "global" {
		log.Functionf("handleDNSDelete: ignoring %s", key)
		return
	}
	*ctx.deviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctx.deviceNetworkStatus)
	ctx.usableAddressCount = newAddrCount
	log.Functionf("handleDNSDelete done for %s", key)
}
