// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/api/go/register"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

const (
	agentName   = "zedclient"
	tmpDirname  = "/var/tmp/zededa"
	DNCDirname  = tmpDirname + "/DeviceNetworkConfig"
	AADirname   = tmpDirname + "/AssignableAdapters"
	maxDelay    = time.Second * 600 // 10 minutes
	uuidMaxWait = time.Second * 60  // 1 minute
)

// Really a constant
var nilUUID uuid.UUID

// Set from Makefile
var Version = "No version specified"

// Assumes the config files are in identityDirname, which is /config
// by default. The files are
//  root-certificate.pem	Fixed? Written if redirected. factory-root-cert?
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
	subDeviceNetworkStatus *pubsub.Subscription
	deviceNetworkStatus    *types.DeviceNetworkStatus
	usableAddressCount     int
	subGlobalConfig        *pubsub.Subscription
}

var debug = false
var debugOverride bool // From command line arg

func Run() {
	versionPtr := flag.Bool("v", false, "Version")
	debugPtr := flag.Bool("d", false, "Debug flag")
	curpartPtr := flag.String("c", "", "Current partition")
	forcePtr := flag.Bool("f", false, "Force using onboarding cert")
	dirPtr := flag.String("D", "/config", "Directory with certs etc")
	stdoutPtr := flag.Bool("s", false, "Use stdout")
	noPidPtr := flag.Bool("p", false, "Do not check for running client")
	maxRetriesPtr := flag.Int("r", 0, "Max ping retries")
	pingURLPtr := flag.String("U", "", "Override ping url")
	insecurePtr := flag.Bool("I", false, "Do not check server cert")
	flag.Parse()

	versionFlag := *versionPtr
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	curpart := *curpartPtr
	forceOnboardingCert := *forcePtr
	identityDirname := *dirPtr
	useStdout := *stdoutPtr
	noPidFlag := *noPidPtr
	maxRetries := *maxRetriesPtr
	pingURL := *pingURLPtr
	insecure := *insecurePtr
	args := flag.Args()
	if versionFlag {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	// Sending json log format to stdout
	logf, err := agentlog.Init("client", curpart)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()
	if useStdout {
		multi := io.MultiWriter(logf, os.Stdout)
		log.SetOutput(multi)
	}
	if !noPidFlag {
		if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
			log.Fatal(err)
		}
	}
	log.Infof("Starting %s\n", agentName)
	operations := map[string]bool{
		"selfRegister": false,
		"ping":         false,
		"getUuid":      false,
	}
	for _, op := range args {
		if _, ok := operations[op]; ok {
			operations[op] = true
		} else {
			log.Errorf("Unknown arg %s\n", op)
			log.Fatal("Usage: " + os.Args[0] +
				"[-o] [-d <identityDirname> [<operations>...]]")
		}
	}

	onboardCertName := identityDirname + "/onboard.cert.pem"
	onboardKeyName := identityDirname + "/onboard.key.pem"
	deviceCertName := identityDirname + "/device.cert.pem"
	deviceKeyName := identityDirname + "/device.key.pem"
	serverFileName := identityDirname + "/server"
	uuidFileName := identityDirname + "/uuid"
	hardwaremodelFileName := identityDirname + "/hardwaremodel"
	enterpriseFileName := identityDirname + "/enterprise"
	nameFileName := identityDirname + "/name"

	cms := zedcloud.GetCloudMetrics() // Need type of data
	pub, err := pubsub.Publish(agentName, cms)
	if err != nil {
		log.Fatal(err)
	}

	var oldUUID uuid.UUID
	b, err := ioutil.ReadFile(uuidFileName)
	if err == nil {
		uuidStr := strings.TrimSpace(string(b))
		oldUUID, err = uuid.FromString(uuidStr)
		if err != nil {
			log.Warningf("Malformed UUID file ignored: %s\n", err)
		}
	}
	// Check if we have a /config/hardwaremodel file
	oldHardwaremodel := hardware.GetHardwareModelOverride()

	clientCtx := clientContext{
		deviceNetworkStatus: &types.DeviceNetworkStatus{},
	}

	// Look for global config such as log levels
	subGlobalConfig, err := pubsub.Subscribe("", types.GlobalConfig{},
		false, &clientCtx)
	if err != nil {
		log.Fatal(err)
	}
	subGlobalConfig.ModifyHandler = handleGlobalConfigModify
	subGlobalConfig.DeleteHandler = handleGlobalConfigDelete
	clientCtx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	subDeviceNetworkStatus, err := pubsub.Subscribe("nim",
		types.DeviceNetworkStatus{}, false, &clientCtx)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkStatus.ModifyHandler = handleDNSModify
	subDeviceNetworkStatus.DeleteHandler = handleDNSDelete
	clientCtx.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	// Wait for a usable IP address.
	// After 5 seconds we check; if we already have a UUID we proceed.
	// Otherwise we start connecting to zedcloud whether or not we
	// have any IP addresses.
	t1 := time.NewTimer(5 * time.Second)
	done := clientCtx.usableAddressCount != 0

	for !done {
		log.Infof("Waiting for usableAddressCount %d and done %v\n",
			clientCtx.usableAddressCount, done)
		select {
		case change := <-subGlobalConfig.C:
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.C:
			subDeviceNetworkStatus.ProcessChange(change)
			done = clientCtx.usableAddressCount != 0

		case <-t1.C:
			done = true
			// If we already know a uuid we can skip
			// This might not set hardwaremodel when upgrading
			// an onboarded system without /config/hardwaremodel.
			// Unlikely to have a network outage during that
			// upgrade *and* require an override.
			if clientCtx.usableAddressCount == 0 &&
				operations["getUuid"] && oldUUID != nilUUID {

				log.Infof("Already have a UUID %s; declaring success\n",
					oldUUID.String())
				// Likely zero metrics
				err := pub.Publish("global", zedcloud.GetCloudMetrics())
				if err != nil {
					log.Errorln(err)
				}
				return
			}
		}
	}
	log.Infof("Got for deviceNetworkConfig: %d addresses\n",
		clientCtx.usableAddressCount)

	zedcloudCtx := zedcloud.ZedCloudContext{
		DeviceNetworkStatus: clientCtx.deviceNetworkStatus,
		FailureFunc:         zedcloud.ZedCloudFailure,
		SuccessFunc:         zedcloud.ZedCloudSuccess,
	}
	var onboardCert, deviceCert tls.Certificate
	var deviceCertPem []byte
	deviceCertSet := false

	if operations["selfRegister"] ||
		(operations["ping"] && forceOnboardingCert) {
		var err error
		onboardCert, err = tls.LoadX509KeyPair(onboardCertName, onboardKeyName)
		if err != nil {
			log.Fatal(err)
		}
		// Load device text cert for upload
		deviceCertPem, err = ioutil.ReadFile(deviceCertName)
		if err != nil {
			log.Fatal(err)
		}
	}
	if operations["getUuid"] ||
		(operations["ping"] && !forceOnboardingCert) {
		// Load device cert
		var err error
		deviceCert, err = tls.LoadX509KeyPair(deviceCertName,
			deviceKeyName)
		if err != nil {
			log.Fatal(err)
		}
		deviceCertSet = true
	}

	server, err := ioutil.ReadFile(serverFileName)
	if err != nil {
		log.Fatal(err)
	}
	serverNameAndPort := strings.TrimSpace(string(server))
	serverName := strings.Split(serverNameAndPort, ":")[0]
	const return400 = false
	// Post something without a return type.
	// Returns true when done; false when retry
	myPost := func(retryCount int, requrl string, reqlen int64, b *bytes.Buffer) bool {
		resp, contents, cf, err := zedcloud.SendOnAllIntf(zedcloudCtx,
			requrl, reqlen, b, retryCount, return400)
		if err != nil {
			log.Errorln(err)
			if cf {
				log.Errorln("Certificate failure")
			}
			return false
		}

		if !zedcloudCtx.NoLedManager {
			// Inform ledmanager about cloud connectivity
			types.UpdateLedManagerConfig(3)
		}
		switch resp.StatusCode {
		case http.StatusOK:
			if !zedcloudCtx.NoLedManager {
				// Inform ledmanager about existence in cloud
				types.UpdateLedManagerConfig(4)
			}
			log.Infof("%s StatusOK\n", requrl)
		case http.StatusCreated:
			if !zedcloudCtx.NoLedManager {
				// Inform ledmanager about existence in cloud
				types.UpdateLedManagerConfig(4)
			}
			log.Infof("%s StatusCreated\n", requrl)
		case http.StatusConflict:
			if !zedcloudCtx.NoLedManager {
				// Inform ledmanager about brokenness
				types.UpdateLedManagerConfig(10)
			}
			log.Errorf("%s StatusConflict\n", requrl)
			// Retry until fixed
			log.Errorf("%s\n", string(contents))
			return false
		case http.StatusNotModified: // XXX from zedcloud
			if !zedcloudCtx.NoLedManager {
				// Inform ledmanager about brokenness
				types.UpdateLedManagerConfig(10)
			}
			log.Errorf("%s StatusNotModified\n", requrl)
			// Retry until fixed
			log.Errorf("%s\n", string(contents))
			return false
		default:
			log.Errorf("%s statuscode %d %s\n",
				requrl, resp.StatusCode,
				http.StatusText(resp.StatusCode))
			log.Errorf("%s\n", string(contents))
			return false
		}

		contentType := resp.Header.Get("Content-Type")
		if contentType == "" {
			log.Errorf("%s no content-type\n", requrl)
			return false
		}
		mimeType, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			log.Errorf("%s ParseMediaType failed %v\n", requrl, err)
			return false
		}
		switch mimeType {
		case "application/x-proto-binary", "application/json", "text/plain":
			log.Debugf("Received reply %s\n", string(contents))
		default:
			log.Errorln("Incorrect Content-Type " + mimeType)
			return false
		}
		return true
	}

	// Returns true when done; false when retry
	selfRegister := func(retryCount int) bool {
		// XXX add option to get this from a file in /config + override
		// logic
		productSerial := hardware.GetProductSerial()
		productSerial = strings.TrimSpace(productSerial)
		log.Infof("ProductSerial %s\n", productSerial)

		tlsConfig, err := zedcloud.GetTlsConfig(serverName, &onboardCert)
		if err != nil {
			log.Errorln(err)
			return false
		}
		zedcloudCtx.TlsConfig = tlsConfig
		registerCreate := &register.ZRegisterMsg{
			PemCert: []byte(base64.StdEncoding.EncodeToString(deviceCertPem)),
			Serial:  productSerial,
		}
		b, err := proto.Marshal(registerCreate)
		if err != nil {
			log.Errorln(err)
			return false
		}
		return myPost(retryCount,
			serverNameAndPort+"/api/v1/edgedevice/register",
			int64(len(b)), bytes.NewBuffer(b))
	}

	// Get something without a return type; used by ping
	// Returns true when done; false when retry.
	// Returns the response when done. Caller can not use resp.Body but
	// can use the contents []byte
	myGet := func(requrl string, retryCount int) (bool, *http.Response, []byte) {
		resp, contents, cf, err := zedcloud.SendOnAllIntf(zedcloudCtx,
			requrl, 0, nil, retryCount, return400)
		if err != nil {
			log.Errorln(err)
			if cf {
				log.Errorln("Certificate failure")
			}
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

	// Setup HTTPS client for deviceCert unless force
	var cert tls.Certificate
	if forceOnboardingCert || operations["selfRegister"] {
		log.Infof("Using onboarding cert\n")
		cert = onboardCert
	} else if deviceCertSet {
		log.Infof("Using device cert\n")
		cert = deviceCert
	} else {
		log.Fatalf("No device certificate for %v\n", operations)
	}

	if operations["ping"] {
		var requrl string
		if pingURL == "" {
			requrl = serverNameAndPort + "/api/v1/edgedevice/ping"
		} else {
			requrl = pingURL
			u, err := url.Parse(requrl)
			if err != nil {
				log.Fatalf("Malformed URL %s: %v",
					requrl, err)
			}
			serverName = u.Host
		}
		tlsConfig, err := zedcloud.GetTlsConfig(serverName, &cert)
		if err != nil {
			log.Fatal(err)
		}
		tlsConfig.InsecureSkipVerify = insecure
		zedcloudCtx.TlsConfig = tlsConfig
		// As we ping the cloud or other URLs, don't affect the LEDs
		zedcloudCtx.NoLedManager = true

		retryCount := 0
		done := false
		var delay time.Duration
		for !done {
			time.Sleep(delay)
			done, _, _ = myGet(requrl, retryCount)
			if done {
				continue
			}
			retryCount += 1
			if maxRetries != 0 && retryCount > maxRetries {
				log.Infof("Exceeded %d retries for ping\n",
					maxRetries)
				os.Exit(1)
			}
			delay = 2 * (delay + time.Second)
			if delay > maxDelay {
				delay = maxDelay
			}
			log.Infof("Retrying ping in %d seconds\n",
				delay/time.Second)
		}
	}

	tlsConfig, err := zedcloud.GetTlsConfig(serverName, &cert)
	if err != nil {
		log.Fatal(err)
	}
	zedcloudCtx.TlsConfig = tlsConfig

	if operations["selfRegister"] {
		retryCount := 0
		done := false
		var delay time.Duration
		for !done {
			time.Sleep(delay)
			done = selfRegister(retryCount)
			if done {
				continue
			}
			retryCount += 1
			if maxRetries != 0 && retryCount > maxRetries {
				log.Errorf("Exceeded %d retries for selfRegister\n",
					maxRetries)
				os.Exit(1)
			}
			delay = 2 * (delay + time.Second)
			if delay > maxDelay {
				delay = maxDelay
			}
			log.Infof("Retrying selfRegister in %d seconds\n",
				delay/time.Second)
		}
	}

	if operations["getUuid"] {
		var devUUID uuid.UUID
		var hardwaremodel string
		var enterprise string
		var name string

		doWrite := true
		requrl := serverNameAndPort + "/api/v1/edgedevice/config"
		retryCount := 0
		done := false
		var delay time.Duration
		for !done {
			var resp *http.Response
			var contents []byte

			time.Sleep(delay)
			done, resp, contents = myGet(requrl, retryCount)
			if done {
				var err error

				devUUID, hardwaremodel, enterprise, name, err = parseConfig(requrl, resp, contents)
				if err == nil {
					// Inform ledmanager about config received from cloud
					if !zedcloudCtx.NoLedManager {
						types.UpdateLedManagerConfig(4)
					}
					continue
				}
				// Keep on trying until it parses
				done = false
				log.Errorf("Failed parsing uuid: %s\n",
					err)
				continue
			}
			if oldUUID != nilUUID && retryCount > 2 {
				log.Infof("Sticking with old UUID\n")
				devUUID = oldUUID
				done = true
				continue
			}

			retryCount += 1
			if maxRetries != 0 && retryCount > maxRetries {
				log.Errorf("Exceeded %d retries for getUuid\n",
					maxRetries)
				os.Exit(1)
			}
			delay = 2 * (delay + time.Second)
			if delay > maxDelay {
				delay = maxDelay
			}
			log.Infof("Retrying config in %d seconds\n",
				delay/time.Second)

		}
		if oldUUID != nilUUID {
			if oldUUID != devUUID {
				log.Infof("Replacing existing UUID %s\n",
					oldUUID.String())
			} else {
				log.Infof("No change to UUID %s\n",
					devUUID)
				doWrite = false
			}
		} else {
			log.Infof("Got config with UUID %s\n", devUUID)
		}

		if doWrite {
			b := []byte(fmt.Sprintf("%s\n", devUUID))
			err = ioutil.WriteFile(uuidFileName, b, 0644)
			if err != nil {
				log.Fatal("WriteFile", err, uuidFileName)
			}
			log.Debugf("Wrote UUID %s\n", devUUID)
		}
		doWrite = true
		if hardwaremodel != "" {
			if oldHardwaremodel != hardwaremodel {
				if existingModel(hardwaremodel) {
					log.Infof("Replacing existing hardwaremodel %s with %s\n",
						oldHardwaremodel, hardwaremodel)
				} else {
					log.Errorf("Attempt to replace existing hardwaremodel %s with non-eixsting %s model - ignored\n",
						oldHardwaremodel, hardwaremodel)
					doWrite = false
				}

			} else {
				log.Infof("No change to hardwaremodel %s\n",
					hardwaremodel)
				doWrite = false
			}
		} else {
			log.Infof("Got config with no hardwaremodel\n")
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
			log.Debugf("Wrote hardwaremodel %s\n", hardwaremodel)
		}
		// We write the strings even if empty to make sure we have the most
		// recents. Since this is for debug use we are less careful
		// than for the hardwaremodel.
		b := []byte(enterprise) // Note that no CRLF
		err = ioutil.WriteFile(enterpriseFileName, b, 0644)
		if err != nil {
			log.Fatal("WriteFile", err, enterpriseFileName)
		}
		log.Debugf("Wrote enterprise %s\n", enterprise)
		b = []byte(name) // Note that no CRLF
		err = ioutil.WriteFile(nameFileName, b, 0644)
		if err != nil {
			log.Fatal("WriteFile", err, nameFileName)
		}
		log.Debugf("Wrote name %s\n", name)
	}

	err = pub.Publish("global", zedcloud.GetCloudMetrics())
	if err != nil {
		log.Errorln(err)
	}
}

func existingModel(model string) bool {
	AAFilename := fmt.Sprintf("%s/%s.json", AADirname, model)
	if _, err := os.Stat(AAFilename); err != nil {
		log.Debugln(err)
		return false
	}
	DNCFilename := fmt.Sprintf("%s/%s.json", DNCDirname, model)
	if _, err := os.Stat(DNCFilename); err != nil {
		log.Debugln(err)
		return false
	}
	return true
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*clientContext)
	if key != "global" {
		log.Debugf("handleGlobalConfigModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s\n", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	log.Infof("handleGlobalConfigModify done for %s\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*clientContext)
	if key != "global" {
		log.Debugf("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s\n", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
}

func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	status := cast.CastDeviceNetworkStatus(statusArg)
	ctx := ctxArg.(*clientContext)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleDNSModify for %s\n", key)
	if cmp.Equal(ctx.deviceNetworkStatus, status) {
		log.Infof("handleDNSModify no change\n")
		return
	}

	log.Infof("handleDNSModify: changed %v",
		cmp.Diff(ctx.deviceNetworkStatus, status))
	*ctx.deviceNetworkStatus = status
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctx.deviceNetworkStatus)
	if newAddrCount != ctx.usableAddressCount {
		log.Infof("DeviceNetworkStatus from %d to %d addresses\n",
			ctx.usableAddressCount, newAddrCount)
		// ledmanager subscribes to DeviceNetworkStatus to see changes
		ctx.usableAddressCount = newAddrCount
	}
	log.Infof("handleDNSModify done for %s\n", key)
}

func handleDNSDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleDNSDelete for %s\n", key)
	ctx := ctxArg.(*clientContext)

	if key != "global" {
		log.Infof("handleDNSDelete: ignoring %s\n", key)
		return
	}
	*ctx.deviceNetworkStatus = types.DeviceNetworkStatus{}
	newAddrCount := types.CountLocalAddrAnyNoLinkLocal(*ctx.deviceNetworkStatus)
	ctx.usableAddressCount = newAddrCount
	log.Infof("handleDNSDelete done for %s\n", key)
}
