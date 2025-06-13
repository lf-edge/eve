// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve-api/go/register"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
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
	withNetTrace          = false
	uuidFileName          = types.PersistStatusDir + "/uuid"
	hardwaremodelFileName = types.PersistStatusDir + "/hardwaremodel"
)

// Really a constant
var nilUUID uuid.UUID

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
	subCachedResolvedIPs   pubsub.Subscription
	globalConfig           *types.ConfigItemValueMap
	getCertsTimer          *time.Timer
	ctrlClient             *controllerconn.Client
	agentMetrics           *controllerconn.AgentMetrics
	// cli options
	operations    map[string]bool
	maxRetriesPtr *int
}

// AddAgentSpecificCLIFlags adds CLI options
func (ctxPtr *clientContext) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
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

func (ctxPtr *clientContext) getCachedResolvedIPs(hostname string) []types.CachedIP {
	if ctxPtr.subCachedResolvedIPs == nil {
		return nil
	}
	if item, err := ctxPtr.subCachedResolvedIPs.Get(hostname); err == nil {
		return item.(types.CachedResolvedIPs).CachedIPs
	}
	return nil
}

var (
	serverNameAndPort string
	onboardTLSConfig  *tls.Config
	devtlsConfig      *tls.Config
	logger            *logrus.Logger
	log               *base.LogObject
)

func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int { //nolint:gocyclo
	logger = loggerArg
	log = logArg

	clientCtx := clientContext{
		deviceNetworkStatus: &types.DeviceNetworkStatus{},
		globalConfig:        types.DefaultConfigItemValueMap(),
		agentMetrics:        controllerconn.NewAgentMetrics(),
		operations: map[string]bool{
			"selfRegister": false,
			"getUuid":      false,
		},
	}

	args := []agentbase.AgentOpt{agentbase.WithArguments(arguments), agentbase.WithBaseDir(baseDir), agentbase.WithPidFile()}
	agentbase.Init(&clientCtx, logger, log, agentName, args...)

	maxRetries := *clientCtx.maxRetriesPtr

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

	subCachedResolvedIPs, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "nim",
		MyAgentName: agentName,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
		TopicImpl:   types.CachedResolvedIPs{},
		Activate:    true,
	})
	if err != nil {
		log.Fatal(err)
	}
	clientCtx.subCachedResolvedIPs = subCachedResolvedIPs

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
	sendTimeoutSecs := clientCtx.globalConfig.GlobalValueInt(types.NetworkSendTimeout)
	dialTimeoutSecs := clientCtx.globalConfig.GlobalValueInt(types.NetworkDialTimeout)
	ctrlClient := controllerconn.NewClient(log, controllerconn.ClientOptions{
		DeviceNetworkStatus: clientCtx.deviceNetworkStatus,
		NetworkSendTimeout:  time.Duration(sendTimeoutSecs) * time.Second,
		NetworkDialTimeout:  time.Duration(dialTimeoutSecs) * time.Second,
		ResolverCacheFunc:   clientCtx.getCachedResolvedIPs,
		AgentMetrics:        clientCtx.agentMetrics,
		DevSerial:           hardware.GetProductSerial(log),
		DevSoftSerial:       hardware.GetSoftSerial(log),
		AgentName:           agentName,
	})

	clientCtx.ctrlClient = ctrlClient
	log.Functionf("Client Get Device Serial %s, Soft Serial %s", ctrlClient.DevSerial,
		ctrlClient.DevSoftSerial)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Wait for a usable IP address.
	// After 5 seconds we check; if we already have a UUID we proceed.
	// If there is a UUID change later then zedagent will detect it and trigger
	// re-running client.
	t1 := time.NewTimer(5 * time.Second)

	ticker := flextimer.NewExpTicker(time.Second, maxDelay, 0)

	server, err := os.ReadFile(types.ServerFileName)
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
		onboardTLSConfig, err = ctrlClient.GetTLSConfig(&onboardCert)
		if err != nil {
			log.Fatal(err)
		}
		// Load device text cert for upload
		deviceCertPem, err = os.ReadFile(types.DeviceCertName)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Load device cert
	deviceCert, err := controllerconn.GetClientCert()
	if err != nil {
		log.Fatal(err)
	}
	devtlsConfig, err = ctrlClient.GetTLSConfig(&deviceCert)
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
		if !gotServerCerts && ctrlClient.UsingV2API() {
			// Set force so we re-download certs on each boot
			gotServerCerts = fetchCertChain(ctrlClient, devtlsConfig, retryCount, true)
			if !gotServerCerts {
				log.Errorf("Failed to fetch certs from %s. Wrong URL?",
					serverNameAndPort)
				if !ctrlClient.NoLedManager {
					utils.UpdateLedManagerConfig(log, types.LedBlinkInvalidControllerCert)
				}
				return 0 // Try again later
			}
			log.Noticef("Fetched certs from %s",
				serverNameAndPort)
		}

		if !gotRegister && clientCtx.operations["selfRegister"] {
			done = selfRegister(ctrlClient, onboardTLSConfig, deviceCertPem, retryCount)
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

		case change := <-subCachedResolvedIPs.MsgChan():
			subCachedResolvedIPs.ProcessChange(change)

		case <-ticker.C:
			// Check in case /config/server changes while running
			nserver, err := os.ReadFile(types.ServerFileName)
			if err != nil {
				log.Error(err)
			} else if len(nserver) != 0 && string(server) != string(nserver) {
				log.Warnf("/config/server changed from %s to %s",
					server, nserver)
				server = nserver
				serverNameAndPort = strings.TrimSpace(string(server))
				// Force a refresh
				ok := fetchCertChain(ctrlClient, devtlsConfig, retryCount, true)
				if !ok && !ctrlClient.NoLedManager {
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
			ok := fetchCertChain(ctrlClient, devtlsConfig, retryCount, true)
			if !ok && !ctrlClient.NoLedManager {
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
			err = os.WriteFile(uuidFileName, b, 0644)
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
			err = os.WriteFile(hardwaremodelFileName, b, 0644)
			if err != nil {
				log.Errorf("WriteFile %s failed: %v",
					hardwaremodelFileName, err)
			} else {
				log.Noticef("Wrote hardwaremodel %s", hardwaremodel)
			}
		}
	}

	err = clientCtx.agentMetrics.Publish(log, pub, "global")
	if err != nil {
		log.Errorln(err)
	}
	log.Noticef("client done")
	return 0
}

// Post something without a return type.
// Returns true when done; false when retry.
func myPost(ctrlClient *controllerconn.Client, tlsConfig *tls.Config,
	requrl string, skipVerify bool, retryCount int,
	b *bytes.Buffer) (done bool, rv controllerconn.SendRetval) {

	ctrlClient.TLSConfig = tlsConfig
	ctx, cancel := ctrlClient.GetContextForAllIntfFunctions()
	defer cancel()
	rv, err := ctrlClient.SendOnAllIntf(ctx, requrl, b, controllerconn.RequestOptions{
		WithNetTracing: withNetTrace,
		BailOnHTTPErr:  bailOnHTTPErr,
		Iteration:      retryCount,
	})
	if err != nil {
		switch rv.Status {
		case types.SenderStatusUpgrade:
			log.Functionf("Controller upgrade in progress")
		case types.SenderStatusRefused:
			log.Functionf("Controller returned ECONNREFUSED")
		case types.SenderStatusCertInvalid:
			log.Warnf("Controller certificate invalid time")
		case types.SenderStatusCertMiss:
			log.Functionf("Controller certificate miss")
		case types.SenderStatusNotFound:
			if !ctrlClient.NoLedManager {
				// Inform ledmanager about controller connectivity
				utils.UpdateLedManagerConfig(log,
					types.LedBlinkConnectedToController)
			}
		default:
			log.Error(err)
		}
		return false, rv
	}

	switch rv.HTTPResp.StatusCode {
	case http.StatusOK:
		if !ctrlClient.NoLedManager {
			// Inform ledmanager about existence in cloud
			utils.UpdateLedManagerConfig(log, types.LedBlinkOnboarded)
		}
		log.Functionf("%s StatusOK", requrl)
	case http.StatusCreated:
		if !ctrlClient.NoLedManager {
			// Inform ledmanager about existence in cloud
			utils.UpdateLedManagerConfig(log, types.LedBlinkOnboarded)
		}
		log.Functionf("%s StatusCreated", requrl)
	case http.StatusConflict:
		if !ctrlClient.NoLedManager {
			// Inform ledmanager about brokenness
			utils.UpdateLedManagerConfig(log, types.LedBlinkOnboardingFailure)
		}
		log.Errorf("%s StatusConflict", requrl)
		// Retry until fixed
		log.Errorf("%s", string(rv.RespContents))
		return false, rv
	case http.StatusNotFound, http.StatusUnauthorized, http.StatusNotModified:
		// Caller needs to handle
		if !ctrlClient.NoLedManager {
			// Inform ledmanager about controller connectivity
			utils.UpdateLedManagerConfig(log,
				types.LedBlinkConnectedToController)
		}
		return false, rv
	default:
		if !ctrlClient.NoLedManager {
			// Inform ledmanager about controller connectivity
			utils.UpdateLedManagerConfig(log,
				types.LedBlinkConnectedToController)
		}
		log.Errorf("%s statuscode %d %s",
			requrl, rv.Status,
			http.StatusText(rv.HTTPResp.StatusCode))
		log.Errorf("%s", string(rv.RespContents))
		return false, rv
	}

	contentType := rv.HTTPResp.Header.Get("Content-Type")
	if contentType == "" {
		log.Errorf("%s no content-type", requrl)
		return false, rv
	}
	mimeType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		log.Errorf("%s ParseMediaType failed %v", requrl, err)
		return false, rv
	}
	switch mimeType {
	case "application/x-proto-binary", "application/json", "text/plain":
		log.Tracef("Received reply %s", string(rv.RespContents))
	default:
		log.Errorln("Incorrect Content-Type " + mimeType)
		return false, rv
	}
	if len(rv.RespContents) == 0 {
		return true, rv
	}
	err = ctrlClient.RemoveAndVerifyAuthContainer(&rv, skipVerify)
	if err != nil {
		if !ctrlClient.NoLedManager {
			utils.UpdateLedManagerConfig(log,
				types.LedBlinkInvalidAuthContainer)
		}
		log.Errorf("RemoveAndVerifyAuthContainer failed: %s",
			err)
		return false, rv
	}
	return true, rv
}

// Returns true when done; false when retry
func selfRegister(ctrlClient *controllerconn.Client, tlsConfig *tls.Config, deviceCertPem []byte, retryCount int) bool {
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
	requrl := controllerconn.URLPathString(
		serverNameAndPort, ctrlClient.UsingV2API(), nilUUID, "register")
	done, rv := myPost(ctrlClient, tlsConfig, requrl, false, retryCount,
		bytes.NewBuffer(b))
	if rv.HTTPResp != nil {
		// Inform ledmanager about brokenness
		if !ctrlClient.NoLedManager {
			// XXX zedcloud is not respecting the eve-api, fix this when zedcloud is updated.
			// for now it returns:
			// StatusBadRequest - if failed parse AuthContainer, verify signature or failed to unmarshal message.
			// StatusGatewayTimeout and StatusInternalServerError - if some internal error occurred on the controller side.
			// StatusOK - if registration was successful.
			// StatusNotModified - if the device is already registered (does this mean duplicate?)
			// StatusForbidden - if the device is not found in the controller.
			// see for expected codes:
			// https://github.com/lf-edge/eve-api/blob/main/APIv2.md#register
			switch rv.HTTPResp.StatusCode {
			case http.StatusBadRequest, http.StatusGatewayTimeout, http.StatusInternalServerError:
				utils.UpdateLedManagerConfig(log, types.LedBlinkOnboardingFailure)
			case http.StatusForbidden:
				utils.UpdateLedManagerConfig(log, types.LedBlinkOnboardingFailureNotFound)
			case http.StatusConflict, http.StatusNotModified:
				utils.UpdateLedManagerConfig(log, types.LedBlinkOnboardingFailureConflict)
			}
		}
		// Retry until fixed
		log.Errorf("Registration failed on URL %s with error %d (%s)", requrl,
			rv.HTTPResp.StatusCode, http.StatusText(rv.HTTPResp.StatusCode))
		log.Errorf("Full response : %s", string(rv.RespContents))
		done = false
	}

	return done
}

// fetch V2 certs from cloud, return GotCloudCerts and ServerIsV1 boolean
// if got certs, the leaf is saved to types.ServerSigningCertFileName file
func fetchCertChain(ctrlClient *controllerconn.Client, tlsConfig *tls.Config, retryCount int, force bool) bool {
	if !force {
		_, err := os.Stat(types.ServerSigningCertFileName)
		if err == nil {
			return true
		}
	}

	// certs API is always V2, and without UUID, use https
	requrl := controllerconn.URLPathString(serverNameAndPort, true, nilUUID, "certs")
	// Save and restore since we don't want the fetch of /certs to
	// appear as if the device is onboarded.
	savedNoLedManager := ctrlClient.NoLedManager
	ctrlClient.NoLedManager = true

	// currently there is no data included for the request, same as myGet()
	done, rv := myPost(ctrlClient, tlsConfig, requrl, true, retryCount, nil)
	ctrlClient.NoLedManager = savedNoLedManager
	if rv.HTTPResp != nil {
		log.Functionf("client fetchCertChain done %v, resp-code %d, content len %d",
			done, rv.HTTPResp.StatusCode, len(rv.RespContents))
		if rv.HTTPResp.StatusCode == http.StatusNotFound ||
			rv.HTTPResp.StatusCode == http.StatusUnauthorized ||
			rv.HTTPResp.StatusCode == http.StatusNotImplemented ||
			rv.HTTPResp.StatusCode == http.StatusBadRequest {
			// cloud server does not support V2 API
			log.Functionf("client fetchCertChain: server %s does not support V2 API",
				serverNameAndPort)
			return false
		}
		// catch default return status, if not done, will return false later
		log.Functionf("client fetchCertChain: server %s return status %s, done %v",
			serverNameAndPort, rv.HTTPResp.Status, done)
	} else {
		log.Functionf("client fetchCertChain done %v, resp null, content len %d",
			done, len(rv.RespContents))
	}
	if !done {
		return false
	}

	ctrlClient.TLSConfig = tlsConfig
	// verify the certificate chain
	certBytes, err := ctrlClient.VerifyProtoSigningCertChain(rv.RespContents)
	if err != nil {
		errStr := fmt.Sprintf("controller certificate signature verify fail, %v", err)
		log.Errorln("fetchCertChain: " + errStr)
		return false
	}

	// write the signing cert to file
	if err := ctrlClient.SaveServerSigningCert(certBytes); err != nil {
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
	ctrlClient := ctx.ctrlClient

	// get UUID does not have UUID string in V2 API
	requrl := controllerconn.URLPathString(
		serverNameAndPort, ctrlClient.UsingV2API(), nilUUID, "uuid")
	b, err := generateUUIDRequest()
	if err != nil {
		log.Errorln(err)
		return false, nilUUID, ""
	}
	done, rv := myPost(ctrlClient, tlsConfig, requrl, false, retryCount,
		bytes.NewBuffer(b))
	if !done {
		// This may be due to the cloud cert file is stale, since the hash does not match.
		// acquire new cert chain.
		if rv.Status == types.SenderStatusCertMiss {
			ctx.getCertsTimer = time.NewTimer(time.Second)
			log.Functionf("doGetUUID: Cert miss. Setup timer to acquire")
		}
		return false, nilUUID, ""
	}
	log.Functionf("doGetUUID: client getUUID ok")
	devUUID, hardwaremodel, err := parseUUIDResponse(rv.HTTPResp, rv.RespContents)
	if err == nil {
		// Inform ledmanager about config received from cloud
		if !ctrlClient.NoLedManager {
			utils.UpdateLedManagerConfig(log, types.LedBlinkOnboarded)
		}
		// If successfully connected to the controller, log the peer certificates,
		// can be used to detect if it's a MiTM proxy
		if rv.HTTPResp != nil && rv.HTTPResp.TLS != nil {
			for i, cert := range rv.HTTPResp.TLS.PeerCertificates {
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
	ctx.ctrlClient.DeviceNetworkStatus = &status

	// if there is proxy certs change, needs to update both
	// onboard and device tlsconfig
	ctx.ctrlClient.TLSConfig = devtlsConfig
	updated := ctx.ctrlClient.UpdateTLSProxyCerts()
	if updated {
		if onboardTLSConfig != nil {
			onboardTLSConfig.RootCAs = ctx.ctrlClient.TLSConfig.RootCAs
		}
		devtlsConfig.RootCAs = ctx.ctrlClient.TLSConfig.RootCAs
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
