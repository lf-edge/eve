// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/RevH/ipinfo"
	"github.com/golang/protobuf/proto"
	"github.com/satori/go.uuid"
	"github.com/zededa/api/zmet"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/devicenetwork"
	"github.com/zededa/go-provision/hardware"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/zedcloud"
	"io/ioutil"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	tmpDirname  = "/var/tmp/zededa"
	DNCDirname  = "/var/tmp/zededa/DeviceNetworkConfig"
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
//  oldserver			Used if -o; XXX remove later
//  onboard.cert.pem, onboard.key.pem	Per device onboarding certificate/key
//  		   		for selfRegister operation
//  device.cert.pem,
//  device.key.pem		Device certificate/key created before this
//  		     		client is started.
//  infra			If this file exists assume zedcontrol and do not
//  				create ACLs
//  uuid			Written by getUuid operation
//
//  /var/tmp/zededa/zedserverconfig		Written by lookupParam operation; zed server EIDs
//  /var/tmp/zededa/zedrouterconfig.json	Written by lookupParam operation
//
func main() {
	logf, err := agentlog.Init("client")
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	versionPtr := flag.Bool("v", false, "Version")
	oldPtr := flag.Bool("o", false, "Old use of prov01")
	forcePtr := flag.Bool("f", false, "Force using onboarding cert")
	dirPtr := flag.String("d", "/config",
		"Directory with certs etc")
	flag.Parse()
	versionFlag := *versionPtr
	oldFlag := *oldPtr
	forceOnboardingCert := *forcePtr
	identityDirname := *dirPtr
	args := flag.Args()
	if versionFlag {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	operations := map[string]bool{
		"selfRegister": false,
		"lookupParam":  false,
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
	oldServerFileName := identityDirname + "/oldserver"
	infraFileName := identityDirname + "/infra"
	uuidFileName := identityDirname + "/uuid"
	zedserverConfigFileName := tmpDirname + "/zedserverconfig"
	zedrouterConfigFileName := tmpDirname + "/zedrouterconfig.json"

	var oldUUID uuid.UUID
	b, err := ioutil.ReadFile(uuidFileName)
	if err == nil {
		uuidStr := strings.TrimSpace(string(b))
		oldUUID, err = uuid.FromString(uuidStr)
		if err != nil {
			log.Printf("UUID file ignored: %s\n", err)
		}
	}

	var deviceNetworkStatus types.DeviceNetworkStatus

	model := hardware.GetHardwareModel()
	DNCFilename := fmt.Sprintf("%s/%s.json", DNCDirname, model)
	addrCount := 0
	for addrCount == 0 {
		deviceNetworkConfig, err := devicenetwork.GetDeviceNetworkConfig(DNCFilename)
		if err != nil {
			log.Fatal(err)
		}
		deviceNetworkStatus, err = devicenetwork.MakeDeviceNetworkStatus(deviceNetworkConfig)
		if err != nil {
			log.Printf("%s from MakeDeviceNetworkStatus\n", err)
			// Proceed even if some uplinks are missing
		}
		addrCount = types.CountLocalAddrAnyNoLinkLocal(deviceNetworkStatus)
		if addrCount == 0 {
			// If we already know a uuid we can skip
			if operations["getUuid"] && oldUUID != nilUUID {
				log.Printf("Already have a UUID %s; declaring success\n",
					oldUUID.String())
				return
			}
			log.Printf("Waiting for some uplink addresses to use\n")
			delay := time.Second
			log.Printf("Retrying in %d seconds\n",
				delay/time.Second)
			time.Sleep(delay)
		}
	}
	log.Printf("Have %d uplinks addresses to use\n", addrCount)

	// Inform ledmanager that we have uplink addresses
	types.UpdateLedManagerConfig(2)

	zedcloudCtx := zedcloud.ZedCloudContext{
		DeviceNetworkStatus: &deviceNetworkStatus,
		Debug:               true,
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
	if operations["lookupParam"] || operations["getUuid"] ||
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
	//XXX: remove oldFlag later
	if oldFlag {
		server, err = ioutil.ReadFile(oldServerFileName)
		if err != nil {
			log.Fatal(err)
		}
	}
	serverNameAndPort := strings.TrimSpace(string(server))
	serverName := strings.Split(serverNameAndPort, ":")[0]
	// XXX for local testing
	// serverNameAndPort = "localhost:9069"

	// If infraFileName exists then don't set ACLs to eidset; allow any
	// EID to connect.
	ACLPromisc := false
	if _, err := os.Stat(infraFileName); err == nil {
		log.Printf("Setting ACLPromisc\n")
		ACLPromisc = true
	}

	// Post something without a return type.
	// Returns true when done; false when retry
	myPost := func(retryCount int, url string, reqlen int64, b *bytes.Buffer) bool {
		resp, err := zedcloud.SendOnAllIntf(zedcloudCtx,
			serverNameAndPort+url, reqlen, b, retryCount)
		if err != nil {
			log.Println(err)
			return false
		}
		defer resp.Body.Close()

		// Inform ledmanager about cloud connectivity
		types.UpdateLedManagerConfig(3)

		contents, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println(err)
			return false
		}

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
		case "application/x-proto-binary":
		case "application/json":
		case "text/plain":
			log.Printf("Received reply %s\n", string(contents))
		default:
			log.Println("Incorrect Content-Type " + mimeType)
			return false
		}
		return true
	}

	// XXX remove later
	oldMyPost := func(retryCount int, url string, reqlen int64, b *bytes.Buffer) bool {
		resp, err := zedcloud.SendOnAllIntf(zedcloudCtx,
			serverNameAndPort+url, reqlen, b, retryCount)
		if err != nil {
			log.Println(err)
			return false
		}
		defer resp.Body.Close()

		// Inform ledmanager about cloud connectivity
		types.UpdateLedManagerConfig(3)

		contents, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println(err)
			return false
		}

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
		case "application/json":
			log.Printf("%s\n", string(contents))
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

	// XXX remove later
	oldSelfRegister := func(retryCount int) bool {
		// Setup HTTPS client
		tlsConfig, err := zedcloud.GetTlsConfig(serverName, &onboardCert)
		if err != nil {
			log.Println(err)
			return false
		}
		zedcloudCtx.TlsConfig = tlsConfig

		rc := types.RegisterCreate{PemCert: deviceCertPem}
		b := new(bytes.Buffer)
		json.NewEncoder(b).Encode(rc)
		// XXX Random value 100 for length since we are deleting this
		// code soon
		return oldMyPost(retryCount, "/rest/self-register",
			100, b)
	}

	// Returns true when done; false when retry
	lookupParam := func(retryCount int, device *types.DeviceDb) bool {
		url := "/rest/device-param"
		resp, err := zedcloud.SendOnAllIntf(zedcloudCtx,
			serverNameAndPort+url, 0, nil, retryCount)
		if err != nil {
			log.Println(err)
			return false
		}
		defer resp.Body.Close()

		// Inform ledmanager about connectivity to cloud
		types.UpdateLedManagerConfig(3)

		contents, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println(err)
			return false
		}
		switch resp.StatusCode {
		case http.StatusOK:
			// Inform ledmanager about device existence in cloud
			types.UpdateLedManagerConfig(4)
			log.Printf("device-param StatusOK\n")
		case http.StatusNotFound:
			log.Printf("device-param StatusNotFound\n")
			return false
		default:
			log.Printf("device-param statuscode %d %s\n",
				resp.StatusCode,
				http.StatusText(resp.StatusCode))
			log.Printf("%s\n", string(contents))
			return false
		}
		contentType := resp.Header.Get("Content-Type")
		if contentType == "" {
			log.Printf("device-param no content-type\n")
			return false
		}
		mimeType, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			log.Printf("device-param ParseMediaType failed %v\n", err)
			return false
		}
		switch mimeType {
		case "application/json":
			break
		default:
			log.Println("Incorrect Content-Type " + mimeType)
			return false
		}
		if err := json.Unmarshal(contents, &device); err != nil {
			log.Println(err)
			return false
		}
		return true
	}

	// Get something without a return type; used by ping
	// Returns true when done; false when retry.
	// Returns the response when done. Note caller must do resp.Body.Close()
	myGet := func(url string, retryCount int) (bool, *http.Response) {
		resp, err := zedcloud.SendOnAllIntf(zedcloudCtx,
			serverNameAndPort+url, 0, nil, retryCount)
		if err != nil {
			log.Println(err)
			return false, nil
		}
		// Perform resp.Body.Close() except in success case

		switch resp.StatusCode {
		case http.StatusOK:
			log.Printf("%s StatusOK\n", url)
			return true, resp
		case http.StatusCreated:
			log.Printf("%s StatusCreated\n", url)
			resp.Body.Close()
			return false, nil
		default:
			log.Printf("%s statuscode %d %s\n",
				url, resp.StatusCode,
				http.StatusText(resp.StatusCode))
			contents, err := ioutil.ReadAll(resp.Body)
			if err == nil {
				log.Printf("Received %s\n", string(contents))
			}
			resp.Body.Close()
			return false, nil
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

	var addInfoDevice *types.AdditionalInfoDevice
	if operations["lookupParam"] {
		// Determine location information and use as AdditionalInfo
		if myIP, err := ipinfo.MyIP(); err == nil {
			addInfo := types.AdditionalInfoDevice{
				UnderlayIP: myIP.IP,
				Hostname:   myIP.Hostname,
				City:       myIP.City,
				Region:     myIP.Region,
				Country:    myIP.Country,
				Loc:        myIP.Loc,
				Org:        myIP.Org,
			}
			addInfoDevice = &addInfo
		}
	}

	if operations["ping"] {
		if oldFlag {
			log.Printf("XXX ping not supported using %s\n",
				serverName)
			return
		}
		url := "/api/v1/edgedevice/ping"
		retryCount := 0
		done := false
		var delay time.Duration
		for !done {
			var resp *http.Response

			time.Sleep(delay)
			done, resp = myGet(url, retryCount)
			if done {
				resp.Body.Close()
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
			if oldFlag {
				done = oldSelfRegister(retryCount)
			} else {
				done = selfRegister(retryCount)
			}
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
		// In the old case we locally generate one.
		// In the new case we get it from the deviceConfig
		if oldFlag {
			if _, err := os.Stat(uuidFileName); err == nil {
				log.Fatalf("UUID file already exists: %s\n",
					uuidFileName)
			}
			// Create and write with initial values
			// XXX ignoring any error
			devUUID, _ = uuid.NewV4()
			log.Printf("Created UUID %s\n", devUUID)
		} else {
			url := "/api/v1/edgedevice/config"
			retryCount := 0
			done := false
			var delay time.Duration
			for !done {
				var resp *http.Response

				time.Sleep(delay)
				done, resp = myGet(url, retryCount)
				if done {
					defer resp.Body.Close()
					var err error
					devUUID, err = parseUUID(url, resp)
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
		}
		if doWrite {
			b := []byte(fmt.Sprintf("%s\n", devUUID))
			err = ioutil.WriteFile(uuidFileName, b, 0644)
			if err != nil {
				log.Fatal("WriteFile", err, uuidFileName)
			}
			log.Printf("Wrote UUID %s\n", devUUID)
		}
	}

	if operations["lookupParam"] {
		if !oldFlag {
			log.Printf("XXX lookupParam not yet supported using %s\n",
				serverName)
			os.Remove(zedrouterConfigFileName)
			return
		}
		b, err := ioutil.ReadFile(uuidFileName)
		if err != nil {
			log.Fatal("ReadFile", err, uuidFileName)
		}
		uuidStr := strings.TrimSpace(string(b))
		devUUID, err := uuid.FromString(uuidStr)
		if err != nil {
			log.Fatal("uuid.FromString", err, string(b))
		}
		log.Printf("Read UUID %s\n", devUUID)

		retryCount := 0
		done := false
		var delay time.Duration
		device := types.DeviceDb{}
		for !done {
			time.Sleep(delay)
			done = lookupParam(retryCount, &device)
			if done {
				continue
			}
			retryCount += 1
			delay = 2 * (delay + time.Second)
			if delay > maxDelay {
				delay = maxDelay
			}
			log.Printf("Retrying lookupParam in %d seconds\n",
				delay/time.Second)
		}

		// If we got a StatusNotFound the EID will be zero
		if device.EID == nil {
			log.Printf("Did not receive an EID\n")
			os.Remove(zedserverConfigFileName)
			return
		}

		// XXX add Redirect support and store + retry
		// XXX try redirected once and then fall back to original; repeat
		// XXX once redirect successful, then save server and rootCert

		// Convert from IID and IPv6 EID to a string with
		// [iid]eid, where the eid uses the textual format defined in
		// RFC 5952. The iid is printed as an integer.
		sigdata := fmt.Sprintf("[%d]%s",
			device.LispInstance, device.EID.String())
		log.Printf("sigdata (len %d) %s\n", len(sigdata), sigdata)

		hasher := sha256.New()
		hasher.Write([]byte(sigdata))
		hash := hasher.Sum(nil)
		log.Printf("hash (len %d) % x\n", len(hash), hash)
		log.Printf("base64 hash %s\n",
			base64.StdEncoding.EncodeToString(hash))

		var signature string
		switch deviceCert.PrivateKey.(type) {
		default:
			log.Fatal("Private Key RSA type not supported")
		case *ecdsa.PrivateKey:
			key := deviceCert.PrivateKey.(*ecdsa.PrivateKey)
			r, s, err := ecdsa.Sign(rand.Reader, key, hash)
			if err != nil {
				log.Fatal("ecdsa.Sign: ", err)
			}
			log.Printf("r.bytes %d s.bytes %d\n", len(r.Bytes()),
				len(s.Bytes()))
			sigres := r.Bytes()
			sigres = append(sigres, s.Bytes()...)
			log.Printf("sigres (len %d): % x\n", len(sigres), sigres)
			signature = base64.StdEncoding.EncodeToString(sigres)
			log.Println("signature:", signature)
		}
		log.Printf("UserName %s\n", device.UserName)
		log.Printf("MapServers %s\n", device.LispMapServers)
		log.Printf("Lisp IID %d\n", device.LispInstance)
		log.Printf("EID %s\n", device.EID)
		log.Printf("EID hash length %d\n", device.EIDHashLen)

		// write zedserverconfig file with hostname to EID mappings
		f, err := os.Create(zedserverConfigFileName)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		for _, ne := range device.ZedServers.NameToEidList {
			for _, eid := range ne.EIDs {
				output := fmt.Sprintf("%-46v %s\n",
					eid, ne.HostName)
				_, err := f.WriteString(output)
				if err != nil {
					log.Fatal(err)
				}
			}
		}
		f.Sync()

		// Determine whether NAT is in use
		if publicIP, err := addrStringToIP(device.ClientAddr); err != nil {
			log.Printf("Failed to convert %s, error %s\n",
				device.ClientAddr, err)
		} else {
			nat := !IsMyAddress(publicIP)
			log.Printf("NAT %v, publicIP %v\n", nat, publicIP)
		}

		// Write an AppNetworkConfig for the ZedManager application
		uv := types.UUIDandVersion{
			UUID:    devUUID,
			Version: "0",
		}
		config := types.AppNetworkConfig{
			UUIDandVersion: uv,
			DisplayName:    "zedmanager",
			IsZedmanager:   true,
		}
		olconf := make([]types.OverlayNetworkConfig, 1)
		config.OverlayNetworkList = olconf
		olconf[0].IID = device.LispInstance
		olconf[0].EID = device.EID
		olconf[0].LispSignature = signature
		olconf[0].AdditionalInfoDevice = addInfoDevice
		olconf[0].NameToEidList = device.ZedServers.NameToEidList
		// XXX temporary to populate map servers
		lispServers := make([]types.LispServerInfo, 2)
		olconf[0].LispServers = lispServers
		lispServers[0].NameOrIp = "ms1.zededa.net"
		lispServers[0].Credential = fmt.Sprintf("test1_%d",
			device.LispInstance)
		lispServers[1].NameOrIp = "ms2.zededa.net"
		lispServers[1].Credential = fmt.Sprintf("test2_%d",
			device.LispInstance)
		acl := make([]types.ACE, 1)
		olconf[0].ACLs = acl
		matches := make([]types.ACEMatch, 1)
		acl[0].Matches = matches
		actions := make([]types.ACEAction, 1)
		acl[0].Actions = actions
		if ACLPromisc {
			matches[0].Type = "ip"
			matches[0].Value = "::/0"
		} else {
			matches[0].Type = "eidset"
		}
		writeNetworkConfig(&config, zedrouterConfigFileName)
	}
}

func writeNetworkConfig(config *types.AppNetworkConfig,
	configFilename string) {
	log.Printf("Writing AppNetworkConfig to %s\n", configFilename)
	b, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err, "json Marshal AppNetworkConfig")
	}
	err = ioutil.WriteFile(configFilename, b, 0644)
	if err != nil {
		log.Fatal(err, configFilename)
	}
}

func addrStringToIP(addrString string) (net.IP, error) {
	clientTCP, err := net.ResolveTCPAddr("tcp", addrString)
	if err != nil {
		return net.IP{}, err
	}
	return clientTCP.IP, nil
}

// IsMyAddress checks the IP address against the local IPs. Returns True if
// there is a match.
func IsMyAddress(clientIP net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok &&
			!ipnet.IP.IsLoopback() {
			if bytes.Compare(ipnet.IP, clientIP) == 0 {
				return true
			}
		}
	}
	return false
}
