package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/zededa/go-provision/types"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var maxDelay = time.Second * 600 // 10 minutes

// Assumes the config files are in dirName, which is /usr/local/etc/zededa/
// by default. The files are
//  root-certificate.pem	Fixed? Written if redirected. factory-root-cert?
//  server			Fixed? Written if redirected. factory-root-cert?
//  prov.cert.pem, prov.key.pem	Per device provisioning certificate/key
//  		   		for selfRegister operation
//  device.cert.pem,
//  device.key.pem		Device certificate/key created before this
//  		     		client is started.
//  lisp.config			Written by lookupParam operation
//  XXX zed.json			Written by lookupParam operation; zed server EIDs
//  hwstatus.json		Uploaded by updateHwStatus operation
//  swstatus.json		Uploaded by updateSwStatus operation
//
func main() {
	args := os.Args[1:]
	if len(args) > 10 { // XXX
		log.Fatal("Usage: " + os.Args[0] +
			"[<dirName> [<operations>...]]")
	}
	dirName := "/usr/local/etc/zededa/"
	if len(args) > 0 {
		dirName = args[0]
	}
	operations := map[string]bool{
		"selfRegister":   false,
		"lookupParam":    false,
		"updateHwStatus": false,
		"updateSwStatus": false,
	}
	if len(args) > 1 {
		for _, op := range args[1:] {
			operations[op] = true
		}
	} else {
		// XXX for compat
		operations["selfRegister"] = true
		operations["lookupParam"] = true
	}

	provCertName := dirName + "/prov.cert.pem"
	provKeyName := dirName + "/prov.key.pem"
	deviceCertName := dirName + "/device.cert.pem"
	deviceKeyName := dirName + "/device.key.pem"
	rootCertName := dirName + "/root-certificate.pem"
	serverFileName := dirName + "/server"
	lispConfigTemplateFileName := dirName + "/lisp.config.zed"
	lispConfigFileName := dirName + "/lisp.config"
	lispConfigTmpFileName := dirName + "/lisp.config.tmp"
	hwStatusFileName := dirName + "/hwstatus.json"
	swStatusFileName := dirName + "/swstatus.json"

	var provCert, deviceCert tls.Certificate
	var deviceCertPem []byte
	deviceCertSet := false

	if operations["selfRegister"] {
		var err error
		provCert, err = tls.LoadX509KeyPair(provCertName, provKeyName)
		if err != nil {
			log.Fatal(err)
		}
		// Load device text cert for upload
		deviceCertPem, err = ioutil.ReadFile(deviceCertName)
		if err != nil {
			log.Fatal(err)
		}
	}
	if operations["lookupParam"] || operations["updateHwStatus"] ||
		operations["updateSwStatus"] {
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
	serverNameAndPort := strings.TrimSpace(string(server))
	serverName := strings.Split(serverNameAndPort, ":")[0]

	// Post something without a return type.
	// Returns true when done; false when retry
	myPost := func(client *http.Client, url string, b *bytes.Buffer) bool {
		resp, err := client.Post("https://"+serverNameAndPort+url,
			"application/json", b)
		if err != nil {
			fmt.Println(err)
			return false
		}
		defer resp.Body.Close()
		connState := resp.TLS
		if connState == nil {
			fmt.Println("no connection state")
			return false
		}

		if connState.OCSPResponse == nil ||
			!stapledCheck(connState) {
			if connState.OCSPResponse == nil {
				fmt.Println("no OCSP response")
			} else {
				fmt.Println("OCSP stapled check failed")
			}
			return false
		}

		// XXX is this url-specific?
		switch resp.StatusCode {
		case http.StatusOK:
			fmt.Printf("%s StatusOK\n", url)
		case http.StatusCreated:
			fmt.Printf("%s StatusCreated\n", url)
		case http.StatusConflict:
			fmt.Printf("%s StatusConflict\n", url)
			// Retry until fixed
			return false
		default:
			fmt.Printf("%s statuscode %d %s\n",
				url, resp.StatusCode,
				http.StatusText(resp.StatusCode))
			return false
		}

		contentType := resp.Header.Get("Content-Type")
		if contentType != "application/json" {
			fmt.Println("Incorrect Content-Type " + contentType)
			return false
		}
		contents, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err)
			return false
		}
		fmt.Printf("%s\n", string(contents))
		return true
	}

	// Returns true when done; false when retry
	selfRegister := func() bool {
		// Setup HTTPS client
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{provCert},
			ServerName:   serverName,
			RootCAs:      caCertPool,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			// TLS 1.2 because we can
			MinVersion: tls.VersionTLS12,
		}
		tlsConfig.BuildNameToCertificate()

		fmt.Printf("Connecting to %s\n", serverNameAndPort)

		transport := &http.Transport{TLSClientConfig: tlsConfig}
		client := &http.Client{Transport: transport}
		rc := types.RegisterCreate{PemCert: deviceCertPem}
		b := new(bytes.Buffer)
		json.NewEncoder(b).Encode(rc)
		return myPost(client, "/rest/self-register", b)
	}

	// Returns true when done; false when retry
	lookupParam := func(client *http.Client, device *types.DeviceDb) bool {
		resp, err := client.Get("https://" + serverNameAndPort +
			"/rest/device-param")
		if err != nil {
			fmt.Println(err)
			return false
		}
		defer resp.Body.Close()
		// XXX can we use GetClientCertificate to inspect this once
		// when connection comes up? Or do we not yet know the server
		// cert in GetClientCertificate?
		// XXX or call crypto/tls/Conn.Handshake and then check!
		connState := resp.TLS
		if connState == nil {
			fmt.Println("no connection state")
			return false
		}

		if connState.OCSPResponse == nil ||
			!stapledCheck(connState) {
			if connState.OCSPResponse == nil {
				fmt.Println("no OCSP response")
			} else {
				fmt.Println("OCSP stapled check failed")
			}
			return false
		}

		switch resp.StatusCode {
		case http.StatusOK:
			fmt.Printf("device-param StatusOK\n")
		default:
			fmt.Printf("device-param statuscode %d %s\n",
				resp.StatusCode,
				http.StatusText(resp.StatusCode))
			return false
		}
		contentType := resp.Header.Get("Content-Type")
		if contentType != "application/json" {
			fmt.Println("Incorrect Content-Type " + contentType)
			return false
		}
		contents, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err)
			return false
		}
		if err := json.Unmarshal(contents, &device); err != nil {
			fmt.Println(err)
			return false
		}
		return true
	}

	if operations["selfRegister"] {
		done := false
		var delay time.Duration
		for !done {
			time.Sleep(delay)
			done = selfRegister()
			delay = 2 * (delay + time.Second)
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}

	if !deviceCertSet {
		return
	}
	// Setup HTTPS client for deviceCert
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{deviceCert},
		ServerName:   serverName,
		RootCAs:      caCertPool,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		// TLS 1.2 because we can
		MinVersion: tls.VersionTLS12,
	}
	tlsConfig.BuildNameToCertificate()

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	if operations["lookupParam"] {
		done := false
		var delay time.Duration
		device := types.DeviceDb{}
		for !done {
			time.Sleep(delay)
			done = lookupParam(client, &device)
			delay = 2 * (delay + time.Second)
			if delay > maxDelay {
				delay = maxDelay
			}
		}

		fmt.Printf("UserName %s\n", device.UserName)
		// XXX add Redirect support and store + retry
		// XXX try redirected once and then fall back to original; repeat
		// XXX once redirect successful, then save server and rootCert
		fmt.Printf("MapServers %s\n", device.LispMapServers)
		fmt.Printf("Lisp IID %d\n", device.LispInstance)
		fmt.Printf("EID %s\n", device.EID)
		fmt.Printf("EID hash length %d\n", device.EIDHashLen)

		// XXX need to concat second map server info
		// XXX eid4 == 0?
		// XXX authentication-key??
		r := strings.NewReplacer(
			"instance-id = <iid>",
			"instance-id = "+strconv.FormatUint(uint64(device.LispInstance), 10),
			"eid-prefix = <eid-prefix6>",
			"eid-prefix = "+device.EID.String()+"/128",
			"<username>", device.UserName,
			"dns-name = <map-server>",
			"dns-name = "+device.LispMapServers[0].NameOrIp,
			"authentication-key = <map-server-key>",
			"authentication-key = "+device.LispMapServers[0].Credential)
		//
		lispTemplate, err := ioutil.ReadFile(lispConfigTemplateFileName)
		if err != nil {
			log.Fatal(err)
		}
		lispConfig := r.Replace(string(lispTemplate))
		for i, ms := range device.LispMapServers {
			if i == 0 {
				continue
			}
			addConfig := fmt.Sprintf("lisp map-resolver {\n"+
				"    dns-name = %s\n}\nlisp map-server {\n"+
				"    dns-name = %s\n"+
				"    authentication-key = %s\n}\n",
				ms.NameOrIp, ms.NameOrIp, ms.Credential)
			lispConfig += addConfig
		}
		// write to temp file and then rename to avois loss
		err = ioutil.WriteFile(lispConfigTmpFileName,
			[]byte(lispConfig), 0)
		if err != nil {
			log.Fatal(err)
		}
		err = os.Rename(lispConfigTmpFileName, lispConfigFileName)
		if err != nil {
			log.Fatal(err)
		}
		// XXX write zm.conf file with servers. Fix servers.
	}
	if operations["updateHwStatus"] {
		// Load file for upload
		buf, err := ioutil.ReadFile(hwStatusFileName)
		if err != nil {
			log.Fatal(err)
		}
		// Input is in json format
		b := bytes.NewBuffer(buf)
		done := false
		var delay time.Duration
		for !done {
			time.Sleep(delay)
			done = myPost(client, "/rest/update-hw-status", b)
			delay = 2 * (delay + time.Second)
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}
	if operations["updateSwStatus"] {
		// Load file for upload
		buf, err := ioutil.ReadFile(swStatusFileName)
		if err != nil {
			log.Fatal(err)
		}
		// Input is in json format
		b := bytes.NewBuffer(buf)
		done := false
		var delay time.Duration
		for !done {
			time.Sleep(delay)
			done = myPost(client, "/rest/update-sw-status", b)
			delay = 2 * (delay + time.Second)
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}
}

func stapledCheck(connState *tls.ConnectionState) bool {
	// server := connState.VerifiedChains[0][0]
	issuer := connState.VerifiedChains[0][1]
	resp, err := ocsp.ParseResponse(connState.OCSPResponse, issuer)
	if err != nil {
		log.Println("error parsing response: ", err)
		return false
	}
	now := time.Now()
	age := now.Unix() - resp.ProducedAt.Unix()
	remain := resp.NextUpdate.Unix() - now.Unix()
	log.Printf("OCSP age %d, remain %d\n", age, remain)
	if remain < 0 {
		log.Println("OCSP expired.")
		return false
	}
	if resp.Status == ocsp.Good {
		log.Println("Certificate Status Good.")
	} else if resp.Status == ocsp.Unknown {
		log.Println("Certificate Status Unknown")
	} else {
		log.Println("Certificate Status Revoked")
	}
	return resp.Status == ocsp.Good
}
