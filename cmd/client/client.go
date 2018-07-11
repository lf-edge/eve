// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package client

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/satori/go.uuid"
	"github.com/zededa/api/zmet"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/hardware"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/zedcloud"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	agentName   = "zedclient"
	tmpDirname  = "/var/tmp/zededa"
	DNCDirname  = tmpDirname + "/DeviceNetworkConfig"
	maxDelay    = time.Second * 600 // 10 minutes
	uuidMaxWait = time.Second * 60  // 1 minute
	debug       = false
)

// Really a constant
var nilUUID uuid.UUID

// Set from Makefile
var Version = "No version specified"

// XXX generalize to DNCContext
type clientContext struct {
	usableAddressCount     int
	manufacturerModel      string
	subDeviceNetworkConfig *pubsub.Subscription
	deviceNetworkConfig    types.DeviceNetworkConfig
	deviceNetworkStatus    types.DeviceNetworkStatus
}

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
//
//
func Run() {
	versionPtr := flag.Bool("v", false, "Version")
	forcePtr := flag.Bool("f", false, "Force using onboarding cert")
	dirPtr := flag.String("d", "/config", "Directory with certs etc")
	stdoutPtr := flag.Bool("s", false, "Use stdout instead of console")
	noPidPtr := flag.Bool("p", false, "Do not check for running client")
	flag.Parse()
	versionFlag := *versionPtr
	forceOnboardingCert := *forcePtr
	identityDirname := *dirPtr
	useStdout := *stdoutPtr
	noPidFlag := *noPidPtr
	args := flag.Args()
	if versionFlag {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	logf, err := agentlog.Init("client")
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()
	// For limited output on console
	consolef := os.Stdout
	if !useStdout {
		consolef, err = os.OpenFile("/dev/console", os.O_RDWR|os.O_APPEND,
			0666)
		if err != nil {
			log.Fatal(err)
		}
	}
	multi := io.MultiWriter(logf, consolef)
	log.SetOutput(multi)
	if !noPidFlag {
		if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
			log.Fatal(err)
		}
	}
	operations := map[string]bool{
		"selfRegister": false,
		"ping":         false,
		"getUuid":      false,
	}
	for _, op := range args {
		if _, ok := operations[op]; ok {
			operations[op] = true
		} else {
			log.Printf("Unknown arg %s\n", op)
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
			log.Printf("Malformed UUID file ignored: %s\n", err)
		}
	}

	model := hardware.GetHardwareModel()
	DNCFilename := fmt.Sprintf("%s/%s.json", DNCDirname, model)
	// To better handle new hardware platforms log and blink if we
	// don't have a DeviceNetworkConfig
	for {
		if _, err := os.Stat(DNCFilename); err == nil {
			break
		}
		// Tell the world that we have issues
		types.UpdateLedManagerConfig(10)
		log.Println(err)
		log.Printf("You need to create this file for this hardware: %s\n",
			DNCFilename)
		time.Sleep(time.Second)
	}

	clientCtx := clientContext{manufacturerModel: model}

	// Get the initial DeviceNetworkConfig
	// Subscribe from "" means /var/tmp/zededa/
	subDeviceNetworkConfig, err := pubsub.Subscribe("",
		types.DeviceNetworkConfig{}, false, &clientCtx)
	if err != nil {
		log.Fatal(err)
	}
	subDeviceNetworkConfig.ModifyHandler = handleDNCModify
	subDeviceNetworkConfig.DeleteHandler = handleDNCDelete
	clientCtx.subDeviceNetworkConfig = subDeviceNetworkConfig
	subDeviceNetworkConfig.Activate()

	// After 5 seconds we check if we have a UUID and proceed
	t1 := time.NewTimer(5 * time.Second)

	for clientCtx.usableAddressCount == 0 {
		log.Printf("Waiting for DeviceNetworkConfig\n")
		select {
		case change := <-subDeviceNetworkConfig.C:
			subDeviceNetworkConfig.ProcessChange(change)

		case <-t1.C:
			// If we already know a uuid we can skip
			if clientCtx.usableAddressCount == 0 &&
				operations["getUuid"] && oldUUID != nilUUID {

				log.Printf("Already have a UUID %s; declaring success\n",
					oldUUID.String())
				// Likely zero metrics
				err := pub.Publish("global", zedcloud.GetCloudMetrics())
				if err != nil {
					log.Println(err)
				}
				return
			}
		}
	}
	log.Printf("Got for DeviceNetworkConfig: %d addresses\n",
		clientCtx.usableAddressCount)

	// Inform ledmanager that we have uplink addresses
	types.UpdateLedManagerConfig(2)

	zedcloudCtx := zedcloud.ZedCloudContext{
		DeviceNetworkStatus: &clientCtx.deviceNetworkStatus,
		Debug:               true,
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
	// XXX for local testing
	// serverNameAndPort = "localhost:9069"

	// Post something without a return type.
	// Returns true when done; false when retry
	myPost := func(retryCount int, url string, reqlen int64, b *bytes.Buffer) bool {
		resp, contents, err := zedcloud.SendOnAllIntf(zedcloudCtx,
			serverNameAndPort+url, reqlen, b, retryCount, false)
		if err != nil {
			log.Println(err)
			return false
		}

		// Inform ledmanager about cloud connectivity
		types.UpdateLedManagerConfig(3)

		switch resp.StatusCode {
		case http.StatusOK:
			// Inform ledmanager about existence in cloud
			types.UpdateLedManagerConfig(4)
			log.Printf("%s StatusOK\n", url)
		case http.StatusCreated:
			// Inform ledmanager about existence in cloud
			types.UpdateLedManagerConfig(4)
			log.Printf("%s StatusCreated\n", url)
		case http.StatusConflict:
			// Inform ledmanager about brokenness
			types.UpdateLedManagerConfig(10)
			log.Printf("%s StatusConflict\n", url)
			// Retry until fixed
			log.Printf("%s\n", string(contents))
			return false
		case http.StatusNotModified: // XXX from zedcloud
			// Inform ledmanager about brokenness
			types.UpdateLedManagerConfig(10)
			log.Printf("%s StatusNotModified\n", url)
			// Retry until fixed
			log.Printf("%s\n", string(contents))
			return false
		default:
			log.Printf("%s statuscode %d %s\n",
				url, resp.StatusCode,
				http.StatusText(resp.StatusCode))
			log.Printf("%s\n", string(contents))
			return false
		}

		contentType := resp.Header.Get("Content-Type")
		if contentType == "" {
			log.Printf("%s no content-type\n", url)
			return false
		}
		mimeType, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			log.Printf("%s ParseMediaType failed %v\n", url, err)
			return false
		}
		switch mimeType {
		case "application/x-proto-binary", "application/json", "text/plain":
			log.Printf("Received reply %s\n", string(contents))
		default:
			log.Println("Incorrect Content-Type " + mimeType)
			return false
		}
		return true
	}

	// Returns true when done; false when retry
	selfRegister := func(retryCount int) bool {
		tlsConfig, err := zedcloud.GetTlsConfig(serverName, &onboardCert)
		if err != nil {
			log.Println(err)
			return false
		}
		zedcloudCtx.TlsConfig = tlsConfig
		registerCreate := &zmet.ZRegisterMsg{
			PemCert: []byte(base64.StdEncoding.EncodeToString(deviceCertPem)),
		}
		b, err := proto.Marshal(registerCreate)
		if err != nil {
			log.Println(err)
			return false
		}
		return myPost(retryCount, "/api/v1/edgedevice/register",
			int64(len(b)), bytes.NewBuffer(b))
	}

	// Get something without a return type; used by ping
	// Returns true when done; false when retry.
	// Returns the response when done. Caller can not use resp.Body but
	// can use the contents []byte
	myGet := func(url string, retryCount int) (bool, *http.Response, []byte) {
		resp, contents, err := zedcloud.SendOnAllIntf(zedcloudCtx,
			serverNameAndPort+url, 0, nil, retryCount, false)
		if err != nil {
			log.Println(err)
			return false, nil, nil
		}

		switch resp.StatusCode {
		case http.StatusOK:
			log.Printf("%s StatusOK\n", url)
			return true, resp, contents
		default:
			log.Printf("%s statuscode %d %s\n",
				url, resp.StatusCode,
				http.StatusText(resp.StatusCode))
			log.Printf("Received %s\n", string(contents))
			return false, nil, nil
		}
	}

	// Setup HTTPS client for deviceCert unless force
	var cert tls.Certificate
	if forceOnboardingCert || operations["selfRegister"] {
		log.Printf("Using onboarding cert\n")
		cert = onboardCert
	} else if deviceCertSet {
		log.Printf("Using device cert\n")
		cert = deviceCert
	} else {
		log.Fatalf("No device certificate for %v\n", operations)
	}
	tlsConfig, err := zedcloud.GetTlsConfig(serverName, &cert)
	if err != nil {
		log.Fatal(err)
	}
	zedcloudCtx.TlsConfig = tlsConfig

	if operations["ping"] {
		url := "/api/v1/edgedevice/ping"
		retryCount := 0
		done := false
		var delay time.Duration
		for !done {
			time.Sleep(delay)
			done, _, _ = myGet(url, retryCount)
			if done {
				continue
			}
			retryCount += 1
			delay = 2 * (delay + time.Second)
			if delay > maxDelay {
				delay = maxDelay
			}
			log.Printf("Retrying ping in %d seconds\n",
				delay/time.Second)
		}
	}

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
			delay = 2 * (delay + time.Second)
			if delay > maxDelay {
				delay = maxDelay
			}
			log.Printf("Retrying selfRegister in %d seconds\n",
				delay/time.Second)
		}
	}

	if operations["getUuid"] {
		var devUUID uuid.UUID
		doWrite := true
		url := "/api/v1/edgedevice/config"
		retryCount := 0
		done := false
		var delay time.Duration
		for !done {
			var resp *http.Response
			var contents []byte

			time.Sleep(delay)
			done, resp, contents = myGet(url, retryCount)
			if done {
				var err error
				devUUID, err = parseUUID(url, resp, contents)
				if err == nil {
					continue
				}
				// Keep on trying until it parses
				done = false
				log.Printf("Failed parsing uuid: %s\n",
					err)
			}
			retryCount += 1
			delay = 2 * (delay + time.Second)
			if delay > maxDelay {
				delay = maxDelay
			}
			log.Printf("Retrying config in %d seconds\n",
				delay/time.Second)
		}
		if oldUUID != nilUUID {
			if oldUUID != devUUID {
				log.Printf("Replacing existing UUID %s\n",
					oldUUID.String())
			} else {
				log.Printf("No change to UUID %s\n",
					devUUID)
				doWrite = false
			}
		} else {
			log.Printf("Got config with UUID %s\n", devUUID)
		}
		// Inform ledmanager about config received from cloud
		types.UpdateLedManagerConfig(4)

		if doWrite {
			b := []byte(fmt.Sprintf("%s\n", devUUID))
			err = ioutil.WriteFile(uuidFileName, b, 0644)
			if err != nil {
				log.Fatal("WriteFile", err, uuidFileName)
			}
			log.Printf("Wrote UUID %s\n", devUUID)
		}
	}

	err = pub.Publish("global", zedcloud.GetCloudMetrics())
	if err != nil {
		log.Println(err)
	}
}
