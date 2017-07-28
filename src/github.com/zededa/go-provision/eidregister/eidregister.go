// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Temporary microservice to register the EIDs allocated by identitymgr with
// prov1.zededa.net which in turn registers them to the map servers
// Reacts to the the collection of EIDStatus structs in
// /var/run/identitymgr/status/*.json, and invokes /rest/eid-register
// Reads config from arg1 or /usr/local/etc/zededa/

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var maxDelay = time.Second * 600 // 10 minutes

var deviceCert tls.Certificate
var serverNameAndPort, serverName string
var caCertPool *x509.CertPool

func main() {
	args := os.Args[1:]
	dirName := "/usr/local/etc/zededa/"
	if len(args) > 0 {
		dirName = args[0]
	}
	deviceCertName := dirName + "/device.cert.pem"
	deviceKeyName := dirName + "/device.key.pem"
	rootCertName := dirName + "/root-certificate.pem"
	serverFileName := dirName + "/server"

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
	serverNameAndPort = strings.TrimSpace(string(server))
	serverName = strings.Split(serverNameAndPort, ":")[0]

	// Keeping status in /var/run to be clean after a crash/reboot
	inputBaseDirname := "/var/run/identitymgr"
	outputBaseDirname := "/var/run/eidregister"
	inputDirname := inputBaseDirname + "/status"
	outputDirname := outputBaseDirname + "/status"
	
	if _, err := os.Stat(outputDirname); err != nil {
		if err := os.Mkdir(outputDirname, 0755); err != nil {
			log.Fatal("Mkdir ", outputDirname, err)
		}
	}
	if _, err := os.Stat(outputDirname); err != nil {
		if err := os.Mkdir(outputDirname, 0755); err != nil {
			log.Fatal("Mkdir ", outputDirname, err)
		}
	}

	// XXX this is common code except for the types used with json
	// and uuid/iid check
	fileChanges := make(chan string)
	go watch.WatchConfigStatus(inputDirname, outputDirname, fileChanges)
	for {
		change := <-fileChanges
		parts := strings.Split(change, " ")
		operation := parts[0]
		fileName := parts[1]
		if !strings.HasSuffix(fileName, ".json") {
			log.Printf("Ignoring file <%s>\n", fileName)
			continue
		}
		if operation == "D" {
			statusFile := outputDirname + "/" + fileName
			if _, err := os.Stat(statusFile); err != nil {
				// File just vanished!
				log.Printf("File disappeared <%s>\n", fileName)
				continue
			}
			sb, err := ioutil.ReadFile(statusFile)
			if err != nil {
				log.Printf("%s for %s\n", err, statusFile)
				continue
			}
			status := types.EIDStatus{}
			if err := json.Unmarshal(sb, &status); err != nil {
				log.Printf("%s EIDStatus file: %s\n",
					err, statusFile)
				continue
			}
			expect := fmt.Sprintf("%s:%d.json",
				status.UUIDandVersion.UUID.String(), status.IID)
			if expect != fileName {
				log.Printf("Mismatch #1 between filename and contained uuid/iid: %s vs. %s\n",
					fileName, expect)
				continue
			}
			outputName := outputDirname + "/" + fileName
			handleDelete(outputName, status)
			continue
		}
		if operation != "M" {
			log.Fatal("Unknown operation from Watcher: ", operation)
		}
		configFile := inputDirname + "/" + fileName
		cb, err := ioutil.ReadFile(configFile)
		if err != nil {
			log.Printf("%s for %s\n", err, configFile)
			continue
		}
		config := types.EIDStatus{}
		if err := json.Unmarshal(cb, &config); err != nil {
			log.Printf("%s EIDRegister file: %s\n",
				err, configFile)
			continue
		}
		expect := fmt.Sprintf("%s:%d.json",
			config.UUIDandVersion.UUID.String(), config.IID)
		if expect != fileName {
			log.Printf("Mismatch #2 between filename and contained uuid/iid: %s vs. %s\n",
				fileName, expect)
			continue
		}
		statusFile := outputDirname + "/" + fileName
		if _, err := os.Stat(statusFile); err != nil {
			// File does not exist in status hence new
			outputName := outputDirname + "/" + fileName
			handleCreate(outputName, config)
			continue
		}
		// Compare Version string
		sb, err := ioutil.ReadFile(statusFile)
		if err != nil {
			log.Printf("%s for %s\n", err, statusFile)
			continue
		}
		status := types.EIDStatus{}
		if err := json.Unmarshal(sb, &status); err != nil {
			log.Printf("%s EIDStatus file: %s\n",
				err, statusFile)
			continue
		}
		expect = fmt.Sprintf("%s:%d.json",
			status.UUIDandVersion.UUID.String(), status.IID)
		if expect != fileName {
			log.Printf("Mismatch #3 between filename and contained uuid/iid: %s vs. %s\n",
				fileName, expect)
			continue
		}
		// Look for pending* in status and repeat that operation.
		// XXX After that do a full ReadDir to restart ...
		if status.PendingAdd {
			outputName := outputDirname + "/" + fileName
			handleCreate(outputName, config)
			// XXX set something to rescan?
			continue
		}
		if status.PendingDelete {
			outputName := outputDirname + "/" + fileName
			handleDelete(outputName, status)
			// XXX set something to rescan?
			continue
		}
		if status.PendingModify {
			outputName := outputDirname + "/" + fileName
			handleModify(outputName, config, status)
			// XXX set something to rescan?
			continue
		}
			
		if config.UUIDandVersion.Version ==
			status.UUIDandVersion.Version {
			fmt.Printf("Same version %s for %s\n",
				config.UUIDandVersion.Version,
				fileName)
			continue
		}
		outputName := outputDirname + "/" + fileName
		handleModify(outputName, config, status)
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
	// XXX which permissions?
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

func handleCreate(outputFilename string, input types.EIDStatus) {
	log.Printf("handleCreate(%v) for %s\n",
		input.UUIDandVersion, input.DisplayName)

	// Start by marking with PendingAdd
	output := input
	output.PendingAdd = true
	// XXX or should we just wait to write this until we have
	// an ack from the server?
	// writeEIDStatus(&output, outputFilename)
	register := types.EIDRegister{
		UUID: input.UUIDandVersion.UUID,
		IID: input.IID,
		DisplayName: input.DisplayName,
		AppCert: input.PemCert,
		AppPublicKey: input.PemPublicKey,
		EID: input.EID,
		EIDHashLen: uint8(128 - 8 * len(input.AllocationPrefix)),
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
func handleModify(outputFilename string, input types.EIDStatus,
	output types.EIDStatus) {
	log.Printf("handleModify(%v) for %s\n",
		input.UUIDandVersion, input.DisplayName)

	output.PendingModify = true
	writeEIDStatus(&output, outputFilename)
	// XXX Any work?
	output.PendingModify = false
	writeEIDStatus(&output, outputFilename)
	log.Printf("handleModify done for %s\n", input.DisplayName)
}

// Need the olNum and ulNum to delete and EID route to delete
func handleDelete(outputFilename string, output types.EIDStatus) {
	log.Printf("handleDelete(%v) for %s\n",
		output.UUIDandVersion, output.DisplayName)

	output.PendingDelete = true
	writeEIDStatus(&output, outputFilename)
	// XXX Do work? Should we do an http.Delete?
	output.PendingDelete = false
	writeEIDStatus(&output, outputFilename)
	// Write out what we modified aka delete
	if err := os.Remove(outputFilename); err != nil {
		log.Println("Failed to remove", outputFilename, err)
	}
	log.Printf("handleDelete done for %s\n", output.DisplayName)
}



