package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/RevH/ipinfo"
	"github.com/golang/protobuf/proto"
	"github.com/satori/go.uuid"
	"github.com/zededa/api/zmet"
	"github.com/zededa/go-provision/types"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const tmpDirname = "/var/tmp/zededa"

// Set from Makefile
var Version = "No version specified"

var maxDelay = time.Second * 600 // 10 minutes

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
//  /var/tmp/zededa/zedserverconfig		Written by lookupParam operation; zed server EIDs
//  /var/tmp/zededa/zedrouterconfig.json	Written by lookupParam operation
//  /var/tmp/zededa/uuid	Written by lookupParam operation
//
func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
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
	rootCertName := identityDirname + "/root-certificate.pem"
	serverFileName := identityDirname + "/server"
	oldServerFileName := identityDirname + "/oldserver"
	infraFileName := identityDirname + "/infra"
	zedserverConfigFileName := tmpDirname + "/zedserverconfig"
	zedrouterConfigFileName := tmpDirname + "/zedrouterconfig.json"
	uuidFileName := tmpDirname + "/uuid"

	var hasDeviceNetworkStatus = false
	var deviceNetworkStatus types.DeviceNetworkStatus

	globalNetworkConfigFilename := "/var/tmp/zededa/DeviceNetworkConfig/global.json"
	if _, err := os.Stat(globalNetworkConfigFilename); err == nil {
		deviceNetworkConfig, err := types.GetDeviceNetworkConfig(globalNetworkConfigFilename)
		if err != nil {
			log.Fatal(err)
		}
		deviceNetworkStatus, err = types.MakeDeviceNetworkStatus(deviceNetworkConfig)
		if err != nil {
			log.Fatal(err)
		}
		hasDeviceNetworkStatus = true
		addrCount := types.CountLocalAddrAnyNoLinkLocal(deviceNetworkStatus)
		fmt.Printf("Have %d uplinks addresses to use\n", addrCount)
		if addrCount != 0 {
			// Inform ledmanager that we have uplink addresses
			types.UpdateLedManagerConfig(2)
		}
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
	if operations["lookupParam"] ||
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

	// Load CA cert
	caCert, err := ioutil.ReadFile(rootCertName)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

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
		fmt.Printf("Setting ACLPromisc\n")
		ACLPromisc = true
	}

	// Post something without a return type.
	// Returns true when done; false when retry
	myPost := func(tlsConfig *tls.Config, retryCount int,
		url string, b *bytes.Buffer) bool {
		var localAddr net.IP
		if hasDeviceNetworkStatus {
			localAddr, err = types.GetLocalAddrAny(deviceNetworkStatus,
				retryCount, "")
			if err != nil {
				log.Fatal(err)
			}
		}
		localTCPAddr := net.TCPAddr{IP: localAddr}
		fmt.Printf("Connecting to %s/%s using source %v\n",
			serverNameAndPort, url, localTCPAddr)
		d := net.Dialer{LocalAddr: &localTCPAddr}
		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
			Dial:            d.Dial,
		}
		client := &http.Client{Transport: transport}

		// Should we distinguish retry due to inappropriate source
		// IP ("no suitable address found") and retry due to server
		// side response errors such as 401? In both cases
		// we don't want to retry immediately
		resp, err := client.Post("https://"+serverNameAndPort+url,
			"application/x-proto-binary", b)
		if err != nil {
			fmt.Println(err)
			return false
		}
		defer resp.Body.Close()
		connState := resp.TLS
		if connState == nil {
			fmt.Println("no TLS connection state")
			return false
		}

		if connState.OCSPResponse == nil ||
			!stapledCheck(connState) {
			if connState.OCSPResponse == nil {
				fmt.Println("no OCSP response")
			} else {
				fmt.Println("OCSP stapled check failed")
			}
			//XXX OSCP is not implemented in cloud side so
			// commenting out it for now. Should be:
			// Inform ledmanager about broken cloud connectivity
			// types.UpdateLedManagerConfig(10)
			// return false
		}

		// Inform ledmanager about cloud connectivity
		types.UpdateLedManagerConfig(3)

		contents, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err)
			return false
		}

		switch resp.StatusCode {
		case http.StatusOK:
			// Inform ledmanager about existence in cloud
			types.UpdateLedManagerConfig(4)
			fmt.Printf("%s StatusOK\n", url)
		case http.StatusCreated:
			// Inform ledmanager about existence in cloud
			types.UpdateLedManagerConfig(4)
			fmt.Printf("%s StatusCreated\n", url)
		case http.StatusConflict:
			// Inform ledmanager about brokenness
			types.UpdateLedManagerConfig(10)
			fmt.Printf("%s StatusConflict\n", url)
			// Retry until fixed
			fmt.Printf("%s\n", string(contents))
			return false
		default:
			fmt.Printf("%s statuscode %d %s\n",
				url, resp.StatusCode,
				http.StatusText(resp.StatusCode))
			fmt.Printf("%s\n", string(contents))
			return false
		}

		contentType := resp.Header.Get("Content-Type")
		if contentType == "" {
			fmt.Printf("%s no content-type\n", url)
			return false
		}
		mimeType, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			fmt.Printf("%s ParseMediaType failed %v\n", url, err)
			return false
		}
		switch mimeType {
		case "application/x-proto-binary":
		case "application/json":
		case "text/plain":
			fmt.Printf("Received reply %s\n", string(contents))
		default:
			fmt.Println("Incorrect Content-Type " + mimeType)
			return false
		}
		return true
	}

	// XXX remove later
	oldMyPost := func(tlsConfig *tls.Config, retryCount int,
		url string, b *bytes.Buffer) bool {
		var localAddr net.IP
		if hasDeviceNetworkStatus {
			localAddr, err = types.GetLocalAddrAny(deviceNetworkStatus,
				retryCount, "")
			if err != nil {
				log.Fatal(err)
			}
		}
		localTCPAddr := net.TCPAddr{IP: localAddr}
		fmt.Printf("Connecting to %s/%s using source %v\n",
			serverNameAndPort, url, localTCPAddr)
		d := net.Dialer{LocalAddr: &localTCPAddr}
		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
			Dial:            d.Dial,
		}
		client := &http.Client{Transport: transport}
		resp, err := client.Post("https://"+serverNameAndPort+url,
			"application/json", b)
		if err != nil {
			fmt.Println(err)
			return false
		}
		defer resp.Body.Close()
		connState := resp.TLS
		if connState == nil {
			fmt.Println("no TLS connection state")
			return false
		}

		if connState.OCSPResponse == nil ||
			!stapledCheck(connState) {
			if connState.OCSPResponse == nil {
				fmt.Println("no OCSP response")
			} else {
				fmt.Println("OCSP stapled check failed")
			}
			// Inform ledmanager about broken cloud connectivity
			types.UpdateLedManagerConfig(10)
			return false
		}
		// Inform ledmanager about cloud connectivity
		types.UpdateLedManagerConfig(3)

		contents, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err)
			return false
		}

		switch resp.StatusCode {
		case http.StatusOK:
			// Inform ledmanager about existence in cloud
			types.UpdateLedManagerConfig(4)
			fmt.Printf("%s StatusOK\n", url)
		case http.StatusCreated:
			// Inform ledmanager about existence in cloud
			types.UpdateLedManagerConfig(4)
			fmt.Printf("%s StatusCreated\n", url)
		case http.StatusConflict:
			// Inform ledmanager about brokenness
			types.UpdateLedManagerConfig(10)
			fmt.Printf("%s StatusConflict\n", url)
			// Retry until fixed
			fmt.Printf("%s\n", string(contents))
			return false
		default:
			fmt.Printf("%s statuscode %d %s\n",
				url, resp.StatusCode,
				http.StatusText(resp.StatusCode))
			fmt.Printf("%s\n", string(contents))
			return false
		}

		contentType := resp.Header.Get("Content-Type")
		if contentType == "" {
			fmt.Printf("%s no content-type\n", url)
			return false
		}
		mimeType, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			fmt.Printf("%s ParseMediaType failed %v\n", url, err)
			return false
		}
		switch mimeType {
		case "application/json":
			fmt.Printf("%s\n", string(contents))
		default:
			fmt.Println("Incorrect Content-Type " + mimeType)
			return false
		}
		return true
	}

	// Returns true when done; false when retry
	selfRegister := func(retryCount int) bool {
		// Setup HTTPS client
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{onboardCert},
			ServerName:   serverName,
			RootCAs:      caCertPool,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			// TLS 1.2 because we can
			MinVersion: tls.VersionTLS12,
		}
		tlsConfig.BuildNameToCertificate()

		registerCreate := &zmet.ZRegisterMsg{
			PemCert: []byte(base64.StdEncoding.EncodeToString(deviceCertPem)),
		}
		b, err := proto.Marshal(registerCreate)
		if err != nil {
			log.Println(err)
		}
		return myPost(tlsConfig, retryCount, "/api/v1/edgedevice/register", bytes.NewBuffer(b))
	}

	// XXX remove later
	oldSelfRegister := func(retryCount int) bool {
		// Setup HTTPS client
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{onboardCert},
			ServerName:   serverName,
			RootCAs:      caCertPool,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			// TLS 1.2 because we can
			MinVersion: tls.VersionTLS12,
		}
		tlsConfig.BuildNameToCertificate()

		rc := types.RegisterCreate{PemCert: deviceCertPem}
		b := new(bytes.Buffer)
		json.NewEncoder(b).Encode(rc)
		return oldMyPost(tlsConfig, retryCount, "/rest/self-register", b)
	}

	// Returns true when done; false when retry
	lookupParam := func(tlsConfig *tls.Config, retryCount int,
		device *types.DeviceDb) bool {
		url := "/rest/device-param"
		var localAddr net.IP
		if hasDeviceNetworkStatus {
			localAddr, err = types.GetLocalAddrAny(deviceNetworkStatus,
				retryCount, "")
			if err != nil {
				log.Fatal(err)
			}
		}
		localTCPAddr := net.TCPAddr{IP: localAddr}
		fmt.Printf("Connecting to %s/%s using source %v\n",
			serverNameAndPort, url, localTCPAddr)
		d := net.Dialer{LocalAddr: &localTCPAddr}
		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
			Dial:            d.Dial,
		}
		client := &http.Client{Transport: transport}

		resp, err := client.Get("https://" + serverNameAndPort + url)
		if err != nil {
			fmt.Println(err)
			return false
		}
		defer resp.Body.Close()
		connState := resp.TLS
		if connState == nil {
			log.Println("no TLS connection state")
			return false
		}
		if connState.OCSPResponse == nil ||
			!stapledCheck(connState) {
			if connState.OCSPResponse == nil {
				fmt.Println("no OCSP response")
			} else {
				fmt.Println("OCSP stapled check failed")
			}
			// Inform ledmanager about brokenness
			types.UpdateLedManagerConfig(10)
			return false
		}

		// Inform ledmanager about connectivity to cloud
		types.UpdateLedManagerConfig(3)

		contents, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err)
			return false
		}
		switch resp.StatusCode {
		case http.StatusOK:
			// Inform ledmanager about device existence in cloud
			types.UpdateLedManagerConfig(4)
			fmt.Printf("device-param StatusOK\n")
		case http.StatusNotFound:
			fmt.Printf("device-param StatusNotFound\n")
			// XXX:FIXME
			// New devices which are only registered in zedcloud
			// will not have state in prov1 hence no EID for
			// zedmanager until we add lookupParam to zedcloud
			return true
		default:
			fmt.Printf("device-param statuscode %d %s\n",
				resp.StatusCode,
				http.StatusText(resp.StatusCode))
			fmt.Printf("%s\n", string(contents))
			return false
		}
		contentType := resp.Header.Get("Content-Type")
		if contentType == "" {
			fmt.Printf("device-param no content-type\n")
			return false
		}
		mimeType, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			fmt.Printf("device-param ParseMediaType failed %v\n", err)
			return false
		}
		switch mimeType {
		case "application/json":
			break
		default:
			fmt.Println("Incorrect Content-Type " + mimeType)
			return false
		}
		if err := json.Unmarshal(contents, &device); err != nil {
			fmt.Println(err)
			return false
		}
		return true
	}

	// Get something without a return type; used by ping
	// Returns true when done; false when retry
	myGet := func(tlsConfig *tls.Config, url string, retryCount int) bool {
		var localAddr net.IP
		if hasDeviceNetworkStatus {
			localAddr, err = types.GetLocalAddrAny(deviceNetworkStatus,
				retryCount, "")
			if err != nil {
				log.Fatal(err)
			}
		}
		localTCPAddr := net.TCPAddr{IP: localAddr}
		fmt.Printf("Connecting to %s/%s using source %v\n",
			serverNameAndPort, url, localTCPAddr)
		d := net.Dialer{LocalAddr: &localTCPAddr}
		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
			Dial:            d.Dial,
		}
		client := &http.Client{Transport: transport}

		// Should we distinguish retry due to inappropriate source
		// IP ("no suitable address found") and retry due to server
		// side response errors such as 401? In both cases
		// we don't want to retry immediately
		resp, err := client.Get("https://" + serverNameAndPort + url)
		if err != nil {
			fmt.Println(err)
			return false
		}
		defer resp.Body.Close()
		connState := resp.TLS
		if connState == nil {
			fmt.Println("no TLS connection state")
			return false
		}

		if connState.OCSPResponse == nil ||
			!stapledCheck(connState) {
			if connState.OCSPResponse == nil {
				fmt.Println("no OCSP response")
			} else {
				fmt.Println("OCSP stapled check failed")
			}
			//XXX OSCP is not implemented in cloud side so
			// commenting out it for now. Should be:
			// Inform ledmanager about broken cloud connectivity
			// types.UpdateLedManagerConfig(10)
			// return false
		}
		contents, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err)
			return false
		}
		switch resp.StatusCode {
		case http.StatusOK:
			fmt.Printf("%s StatusOK\n", url)
			return true
		case http.StatusCreated:
			fmt.Printf("%s StatusCreated\n", url)
			return false
		default:
			fmt.Printf("%s statuscode %d %s\n",
				url, resp.StatusCode,
				http.StatusText(resp.StatusCode))
			fmt.Printf("%s\n", string(contents))
			return false
		}
	}

	// Setup HTTPS client for deviceCert unless force
	var cert tls.Certificate
	if forceOnboardingCert {
		fmt.Printf("Using onboarding cert\n")
		cert = onboardCert
	} else if deviceCertSet {
		fmt.Printf("Using device cert\n")
		cert = deviceCert
	} else {
		log.Fatalf("No device certificate for %v\n", operations)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   serverName,
		RootCAs:      caCertPool,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		// TLS 1.2 because we can
		MinVersion: tls.VersionTLS12,
	}
	tlsConfig.BuildNameToCertificate()

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

	var devUUID uuid.UUID

	if operations["lookupParam"] || operations["selfRegister"] {
		if _, err := os.Stat(uuidFileName); err != nil {
			// Create and write with initial values
			// XXX ignoring any error
			devUUID, _ = uuid.NewV4()
			b := []byte(fmt.Sprintf("%s\n", devUUID))
			err = ioutil.WriteFile(uuidFileName, b, 0644)
			if err != nil {
				log.Fatal("WriteFile", err, uuidFileName)
			}
			fmt.Printf("Created UUID %s\n", devUUID)
		} else {
			b, err := ioutil.ReadFile(uuidFileName)
			if err != nil {
				log.Fatal("ReadFile", err, uuidFileName)
			}
			uuidStr := strings.TrimSpace(string(b))
			devUUID, err = uuid.FromString(uuidStr)
			if err != nil {
				log.Fatal("uuid.FromString", err, string(b))
			}
			fmt.Printf("Read UUID %s\n", devUUID)
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
			time.Sleep(delay)
			done = myGet(tlsConfig, url, retryCount)
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

	if operations["lookupParam"] {
		if !oldFlag {
			log.Printf("XXX lookupParam not yet supported using %s\n",
				serverName)
			os.Remove(zedrouterConfigFileName)
			return
		}
		retryCount := 0
		done := false
		var delay time.Duration
		device := types.DeviceDb{}
		for !done {
			time.Sleep(delay)
			done = lookupParam(tlsConfig, retryCount, &device)
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
		fmt.Printf("sigdata (len %d) %s\n", len(sigdata), sigdata)

		hasher := sha256.New()
		hasher.Write([]byte(sigdata))
		hash := hasher.Sum(nil)
		fmt.Printf("hash (len %d) % x\n", len(hash), hash)
		fmt.Printf("base64 hash %s\n",
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
			fmt.Printf("r.bytes %d s.bytes %d\n", len(r.Bytes()),
				len(s.Bytes()))
			sigres := r.Bytes()
			sigres = append(sigres, s.Bytes()...)
			fmt.Printf("sigres (len %d): % x\n", len(sigres), sigres)
			signature = base64.StdEncoding.EncodeToString(sigres)
			fmt.Println("signature:", signature)
		}
		fmt.Printf("UserName %s\n", device.UserName)
		fmt.Printf("MapServers %s\n", device.LispMapServers)
		fmt.Printf("Lisp IID %d\n", device.LispInstance)
		fmt.Printf("EID %s\n", device.EID)
		fmt.Printf("EID hash length %d\n", device.EIDHashLen)

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
			fmt.Printf("NAT %v, publicIP %v\n", nat, publicIP)
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
	fmt.Printf("Writing AppNetworkConfig to %s\n", configFilename)
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

func stapledCheck(connState *tls.ConnectionState) bool {
	issuer := connState.VerifiedChains[0][1]
	resp, err := ocsp.ParseResponse(connState.OCSPResponse, issuer)
	if err != nil {
		log.Println("error parsing response: ", err)
		return false
	}
	now := time.Now()
	age := now.Unix() - resp.ProducedAt.Unix()
	remain := resp.NextUpdate.Unix() - now.Unix()
	fmt.Printf("OCSP age %d, remain %d\n", age, remain)
	if remain < 0 {
		fmt.Println("OCSP expired.")
		return false
	}
	if resp.Status == ocsp.Good {
		fmt.Println("Certificate Status Good.")
	} else if resp.Status == ocsp.Unknown {
		fmt.Println("Certificate Status Unknown")
	} else {
		fmt.Println("Certificate Status Revoked")
	}
	return resp.Status == ocsp.Good
}
