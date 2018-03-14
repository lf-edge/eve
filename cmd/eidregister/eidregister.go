// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Temporary microservice to register the EIDs allocated by identitymgr with
// prov1.zededa.net which in turn registers them to the map servers
// Reacts to the the collection of EIDStatus structs in
// /var/run/identitymgr/status/*.json, and invokes /rest/eid-register
// Reads config from -d configdir or /config

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"
)

const (
	agentName         = "eidregister"
	inputBaseDirname  = "/var/run/" + agentName
	outputBaseDirname = "/var/run/" + agentName
	inputDirname      = inputBaseDirname + "/status"
	outputDirname     = outputBaseDirname + "/status"
)

var maxDelay = time.Second * 600 // 10 minutes

var deviceCert tls.Certificate
var serverNameAndPort, serverName string
var caCertPool *x509.CertPool

// Set from Makefile
var Version = "No version specified"

// Dummy since we don't have anything to pass
type dummyContext struct {
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	versionPtr := flag.Bool("v", false, "Version")
	oldPtr := flag.Bool("o", false, "Old use of prov01")
	dirPtr := flag.String("d", "/config",
		"Directory with certs etc")
	flag.Parse()
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	oldFlag := *oldPtr
	identityDirname := *dirPtr
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Printf("Starting %s\n", agentName)
	watch.CleanupRestarted(agentName)

	deviceCertName := identityDirname + "/device.cert.pem"
	deviceKeyName := identityDirname + "/device.key.pem"
	rootCertName := identityDirname + "/root-certificate.pem"
	serverFileName := identityDirname + "/server"
	oldServerFileName := identityDirname + "/oldserver"

	// Load device cert
	var err error
	deviceCert, err = tls.LoadX509KeyPair(deviceCertName, deviceKeyName)
	if err != nil {
		log.Fatal(err)
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile(rootCertName)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool = x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	server, err := ioutil.ReadFile(serverFileName)
	if err != nil {
		log.Fatal(err)
	}
	if oldFlag {
		server, err = ioutil.ReadFile(oldServerFileName)
		if err != nil {
			log.Fatal(err)
		}
	}
	serverNameAndPort = strings.TrimSpace(string(server))
	serverName = strings.Split(serverNameAndPort, ":")[0]

	if _, err := os.Stat(inputBaseDirname); err != nil {
		if err := os.Mkdir(inputBaseDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(outputBaseDirname); err != nil {
		if err := os.Mkdir(outputBaseDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(inputDirname); err != nil {
		if err := os.Mkdir(inputDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(outputDirname); err != nil {
		if err := os.Mkdir(outputDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	fileChanges := make(chan string)
	go watch.WatchConfigStatus(inputDirname, outputDirname, fileChanges)
	for {
		change := <-fileChanges
		watch.HandleConfigStatusEvent(change, dummyContext{},
			inputDirname, outputDirname,
			&types.EIDStatus{},
			&types.EIDStatus{},
			handleCreate, handleModify, handleDelete, nil)
	}
}

func writeEIDStatus(status *types.EIDStatus,
	statusFilename string) {
	b, err := json.Marshal(status)
	if err != nil {
		log.Fatal(err, "json Marshal EIDStatus")
	}
	// We assume a /var/run path hence we don't need to worry about
	// partial writes/empty files due to a kernel crash.
	err = ioutil.WriteFile(statusFilename, b, 0644)
	if err != nil {
		log.Fatal(err, statusFilename)
	}
}

// Post something without a return type.
// Returns true when done; false when retry
// XXX Duplicated from client.go
func myPost(client *http.Client, url string, b *bytes.Buffer) bool {
	resp, err := client.Post("https://"+serverNameAndPort+url,
		"application/json", b)
	if err != nil {
		fmt.Printf("client.Post: ", err)
		return false
	}
	defer resp.Body.Close()
	connState := resp.TLS
	if connState == nil {
		fmt.Println("no TLS connection state")
		return false
	}

	if connState.OCSPResponse == nil || !stapledCheck(connState) {
		if connState.OCSPResponse == nil {
			fmt.Println("no OCSP response")
		} else {
			fmt.Println("OCSP stapled check failed")
		}
		return false
	}

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return false
	}

	// XXX Should this behavior be url-specific?
	switch resp.StatusCode {
	case http.StatusOK:
		fmt.Printf("%s StatusOK\n", url)
	case http.StatusCreated:
		fmt.Printf("%s StatusCreated\n", url)
	case http.StatusConflict:
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
	if contentType != "application/json" {
		fmt.Println("Incorrect Content-Type " + contentType)
		return false
	}
	fmt.Printf("%s\n", string(contents))
	return true
}

// XXX Duplicated from client.go
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

// Returns true when done; false when retry
func registerEID(register *types.EIDRegister) bool {
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

	fmt.Printf("Connecting to %s\n", serverNameAndPort)

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}
	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(register)
	return myPost(client, "/rest/eid-register", b)
}

func handleCreate(ctxArg interface{}, outputFilename string,
	inputArg interface{}) {
	input := inputArg.(*types.EIDStatus)
	log.Printf("handleCreate(%v) for %s\n",
		input.UUIDandVersion, input.DisplayName)

	// Start by marking with PendingAdd
	output := *input
	output.PendingAdd = true
	// XXX or should we just wait to write this until we have
	// an ack from the server?
	// writeEIDStatus(&output, outputFilename)
	register := types.EIDRegister{
		UUID:         input.UUIDandVersion.UUID,
		IID:          input.IID,
		DisplayName:  input.DisplayName,
		AppCert:      input.PemCert,
		AppPublicKey: input.PemPublicKey,
		EID:          input.EID,
		EIDHashLen:   uint8(128 - 8*len(input.AllocationPrefix)),
		CreateTime:   input.CreateTime,
	}
	// XXX hardcode this to work with existing zed-lispiotcontroller
	register.LispMapServers = make([]types.LispServerInfo, 2)
	register.LispMapServers[0].NameOrIp = "ms1.zededa.net"
	register.LispMapServers[0].Credential = fmt.Sprintf("test1_%d", input.IID)
	register.LispMapServers[1].NameOrIp = "ms2.zededa.net"
	register.LispMapServers[1].Credential = fmt.Sprintf("test2_%d", input.IID)
	done := false
	var delay time.Duration
	// XXX need to give up or run this in a separate goroutine??
	for !done {
		time.Sleep(delay)
		done = registerEID(&register)
		delay = 2 * (delay + time.Second)
		if delay > maxDelay {
			delay = maxDelay
		}
	}

	output.PendingAdd = false
	writeEIDStatus(&output, outputFilename)
	log.Printf("handleCreate done for %s\n", input.DisplayName)
}

// Need to compare what might have changed. If any content change
// then we need to reboot. Thus version by itself can change but nothing
// else. Such a version change would be e.g. due to an ACL change.
func handleModify(ctxArg interface{}, outputFilename string, inputArg interface{},
	outputArg interface{}) {
	input := inputArg.(*types.EIDStatus)
	output := outputArg.(*types.EIDStatus)
	log.Printf("handleModify(%v) for %s\n",
		input.UUIDandVersion, input.DisplayName)

	if input.UUIDandVersion.Version == output.UUIDandVersion.Version {
		fmt.Printf("Same version %s for %s\n",
			input.UUIDandVersion.Version, outputFilename)
		return
	}
	// Reject any changes to EIDAllocation.
	// XXX report internal error?
	if !reflect.DeepEqual(input.EIDAllocation, output.EIDAllocation) {
		log.Printf("handleModify(%v,%d) EIDAllocation changed for %s\n",
			input.UUIDandVersion, input.IID, input.DisplayName)
		return
	}

	output.PendingModify = true
	writeEIDStatus(output, outputFilename)
	// XXX Any work in modify?
	if output.CreateTime != input.CreateTime {
		log.Printf("handleModify(%v) changed CreateTime for %s\n",
			input.UUIDandVersion, input.DisplayName)
		handleDelete(ctxArg, outputFilename, output)
		handleCreate(ctxArg, outputFilename, input)
	}
	output.PendingModify = false
	output.UUIDandVersion = input.UUIDandVersion
	writeEIDStatus(output, outputFilename)
	log.Printf("handleModify done for %s\n", input.DisplayName)
}

func handleDelete(ctxArg interface{}, outputFilename string,
	outputArg interface{}) {
	output := outputArg.(*types.EIDStatus)
	log.Printf("handleDelete(%v) for %s\n",
		output.UUIDandVersion, output.DisplayName)

	output.PendingDelete = true
	writeEIDStatus(output, outputFilename)
	// XXX Do work? Should we do an http.Delete?
	output.PendingDelete = false
	writeEIDStatus(output, outputFilename)
	// Write out what we modified aka delete
	if err := os.Remove(outputFilename); err != nil {
		log.Println(err)
	}
	log.Printf("handleDelete done for %s\n", output.DisplayName)
}
