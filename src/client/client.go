package main

import (
        "bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
        "github.com/zededa/go-provision/types"
	"golang.org/x/crypto/ocsp"
)

var maxDelay = time.Second * 600	// 10 minutes

// Assumes the config files are in dirName, which is /etc/zededa/ by default
// The files are
//  root-certificate.pem	Fixed? Written if redirected. factory-root-cert?
//  server			Fixed? Written if redirected. factory-root-cert?
//  pc.cert.pem, pc.key.pem	Per device
//  device.cert.pem, device.key.pem XXX written before we are called
//
func main() {
	args := os.Args[1:]
	if len(args) >1 {
		log.Fatal("Usage: " + os.Args[0] + "[<dirName>]")
	}
	dirName := "/etc/zededa/"
	if len(args) > 0 {
	   dirName = args[0]
	}

	provCertName := dirName + "/pc.cert.pem"
	provKeyName := dirName + "/pc.key.pem"
	deviceCertName := dirName + "/device.cert.pem"
	deviceKeyName := dirName + "/device.key.pem"
	rootCertName := dirName + "/root-certificate.pem"
	serverFileName := dirName + "/server"

	// Load provisioning cert
	provCert, err := tls.LoadX509KeyPair(provCertName, provKeyName)
	if err != nil {
		log.Fatal(err)
	}

	// Load device cert
	deviceCert, err := tls.LoadX509KeyPair(deviceCertName, deviceKeyName)
	if err != nil {
		log.Fatal(err)
	}

	// Load text cert
	deviceCertPem, err := ioutil.ReadFile(deviceCertName)
	if err != nil {
		log.Fatal(err)
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
	serverName := strings.TrimSpace(string(server))
	
	// Returns true when done; false when retry
	selfRegister := func() (bool) {
		// Setup HTTPS client
	     	tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{provCert},
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
	
		rc := types.RegisterCreate{ PemCert: deviceCertPem, }
		b := new(bytes.Buffer)
		json.NewEncoder(b).Encode(rc)
		resp, err := client.Post("https://" + serverName +
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
			fmt.Printf("self-register statuscode %d\n",
						  resp.StatusCode)
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
	lookupParam := func(device *types.DeviceDb) (bool) {
		// Setup HTTPS client
	     	tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{deviceCert},
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
	
		resp, err := client.Get("https://" + serverName +
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
			fmt.Printf("device-param statuscode %d\n",
						 resp.StatusCode)
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

	done := false
	var delay time.Duration
	
	for !done {
	    time.Sleep(delay)
	    done = selfRegister()
	    delay = 2*(delay+time.Second)
	    if delay > maxDelay {
	       delay = maxDelay
            }
	}

	done = false
	device := types.DeviceDb{}
	delay = 0
	for !done {
	    time.Sleep(delay)
	    done = lookupParam(&device)
	    delay = 2*(delay+time.Second)
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
	// XXX save ouput
	// XXX also save as a lisp.config file
	// Should take ztp/lisp.config.zed and do the following replacements
//        ("instance-id = <iid>", "instance-id = {}".format(iid)),
//        ("eid-prefix = <eid-prefix4>", "eid-prefix = {}/32".format(eid4)),
//        ("eid-prefix = <eid-prefix6>", "eid-prefix = {}/128".format(eid6)),
//        ("dns-name = <map-server>", "dns-name = {}".format(ms)),
//        ("authentication-key = <map-server-key>", 
//         "authentication-key = {}".format(ms_key)) ]
	 
}

func stapledCheck(connState *tls.ConnectionState)(bool) {
	server := connState.VerifiedChains[0][0]
	issuer := connState.VerifiedChains[0][1]
	log.Printf("Server: %v\n", server.Subject.CommonName)
	log.Printf("Issuer: %v\n", issuer.Subject.CommonName)
	resp, err := ocsp.ParseResponse(connState.OCSPResponse, issuer)
	if err != nil {
		log.Fatalln("error parsing response: ", err)
		return false
	}
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
