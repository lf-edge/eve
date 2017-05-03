package main

import (
	"bufio"
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
	"strings"
	"time"
)

var maxDelay = time.Second * 600 // 10 minutes

// Assumes the config files are in dirName, which is /etc/zededa/ by default
// The files are
//  root-certificate.pem	Fixed? Written if redirected. factory-root-cert?
//  server			Fixed? Written if redirected. factory-root-cert?
//  prov.cert.pem, prov.key.pem	Per device provisioning certificate/key
//  		   		for selfRegister operation
//  device.cert.pem,
//  device.key.pem		Device certificate/key created before this
//  		     		client is started.
//  lisp.config			Written by lookupParam operation
//  hwstatus XXX.json?		Uploaded by updateHwStatus operation
//  swstatus XXX.json?		Uploaded by updateSwStatus operation
//
func main() {
	args := os.Args[1:]
	if len(args) > 10 { // XXX
		log.Fatal("Usage: " + os.Args[0] + "[<dirName>]")
	}
	dirName := "/etc/zededa/"
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
	lispConfigFileName := dirName + "/lisp.config"
	hwStatusFileName := dirName + "/hwstatus"
	swStatusFileName := dirName + "/swstatus"

	var provCert, deviceCert tls.Certificate
	var deviceCertPem []byte

	if operations["selfRegister"] {
		fmt.Println("Need provisioning cert for selfRegister")
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
		fmt.Println("Need device cert for all other operations")
		// Load device cert
		var err error
		deviceCert, err = tls.LoadX509KeyPair(deviceCertName,
			deviceKeyName)
		if err != nil {
			log.Fatal(err)
		}
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
		// XXX defer transport.Close()
		// defer client.Close()

		rc := types.RegisterCreate{PemCert: deviceCertPem}
		b := new(bytes.Buffer)
		json.NewEncoder(b).Encode(rc)
		resp, err := client.Post("https://"+serverNameAndPort+
			"/rest/self-register", "application/json", b)
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

		if connState.OCSPResponse == nil {
			fmt.Println("no OCSP response")
			// XXX return false
		} else {
			// parse the ocsp response
			log.Println("stapled check")
			if !stapledCheck(connState) {
				fmt.Println("OCSP stapled check failed")
				return false
			}
		}

		switch resp.StatusCode {
		case http.StatusOK:
			fmt.Printf("self-register StatusOK\n")
		case http.StatusCreated:
			fmt.Printf("self-register StatusCreated\n")
		case http.StatusConflict:
			fmt.Printf("self-register StatusConflict\n")
			// Retry until fixed
			return false
		default:
			fmt.Printf("self-register statuscode %d %s\n",
				resp.StatusCode,
				http.StatusText(resp.StatusCode))
			// XXX when should we not retry?
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
		// XXX remove
		fmt.Printf("%s\n", string(contents))
		return true
	}

	// Returns true when done; false when retry
	lookupParam := func(device *types.DeviceDb) bool {
		// Setup HTTPS client
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
		// XXX defer transport.Close()
		// defer client.Close()

		resp, err := client.Get("https://" + serverNameAndPort +
			"/rest/device-param")
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

		if connState.OCSPResponse == nil {
			fmt.Println("no OCSP response")
			// XXX return false
		} else {
			// parse the ocsp response
			log.Println("stapled check")
			if !stapledCheck(connState) {
				fmt.Println("OCSP stapled check failed")
				return false
			}
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

	if operations["lookupParam"] {
		done := false
		var delay time.Duration
		device := types.DeviceDb{}
		for !done {
			time.Sleep(delay)
			done = lookupParam(&device)
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
		// Should take ztp/lisp.config.zed and do the following replacements
		f, err := os.Create(lispConfigFileName)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		w := bufio.NewWriter(f)
		_, err = fmt.Fprintf(w, "instance-id = %v\n", device.LispInstance)
		if err != nil {
			log.Fatal(err)
		}
		_, err = fmt.Fprintf(w, "eid-prefix = %v/128\n", device.EID)
		if err != nil {
			log.Fatal(err)
		}
		for _, ms := range device.LispMapServers {
			_, err = fmt.Fprintf(w, "dns-name = %v\n", ms.NameOrIp)
			if err != nil {
				log.Fatal(err)
			}
			_, err = fmt.Fprintf(w, "authentication-key = %v\n",
				ms.Credential)
			if err != nil {
				log.Fatal(err)
			}
		}
		w.Flush()
	}
	if operations["updateHwStatus"] {
		// Load file for upload
		_, err := ioutil.ReadFile(hwStatusFileName)
		if err != nil {
			log.Fatal(err)
		}
		// XXX post
	}
	if operations["updateSwStatus"] {
		// Load file for upload
		_, err := ioutil.ReadFile(swStatusFileName)
		if err != nil {
			log.Fatal(err)
		}
		// XXX post
	}
}

func stapledCheck(connState *tls.ConnectionState) bool {
	server := connState.VerifiedChains[0][0]
	issuer := connState.VerifiedChains[0][1]
	log.Printf("Server: %v\n", server.Subject.CommonName)
	log.Printf("Issuer: %v\n", issuer.Subject.CommonName)
	resp, err := ocsp.ParseResponse(connState.OCSPResponse, issuer)
	if err != nil {
		log.Fatalln("error parsing response: ", err)
		return false
	}
	// XXX check lifetime? does parser?
	now := time.Now()
	log.Printf("OCSP NextUpdate %s ProducedAt %s ThisUpdate %s now %s\n",
		resp.NextUpdate, resp.ProducedAt,
		resp.ThisUpdate, now)
	age := now.Unix() - resp.ProducedAt.Unix()
	remain := resp.NextUpdate.Unix() - now.Unix()
	log.Printf("OCSP age %d, remain %d\n", age, remain)
	if resp.Status == ocsp.Good {
		log.Println("Certificate Status Good.")
		return true
	} else if resp.Status == ocsp.Unknown {
		log.Println("Certificate Status Unknown")
		return false
	} else {
		log.Println("Certificate Status Revoked")
		return false
	}
}
