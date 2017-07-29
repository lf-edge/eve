// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Manage the allocation of EIDs for application instances based on input
// as EIDConfig structs in /var/tmp/identitymgr/config/*.json and report
// on status in the collection of EIDStatus structs in
// /var/run/identitymgr/status/*.json

package main

import (
	"crypto/sha256"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	// Keeping status in /var/run to be clean after a crash/reboot
	baseDirname := "/var/tmp/identitymgr"
	runDirname := "/var/run/identitymgr"
	configDirname := baseDirname + "/config"
	statusDirname := runDirname + "/status"
	
	if _, err := os.Stat(baseDirname); err != nil {
		if err := os.Mkdir(baseDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(configDirname); err != nil {
		if err := os.Mkdir(configDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(runDirname); err != nil {
		if err := os.Mkdir(runDirname, 0755); err != nil {
			log.Fatal( err)
		}
	}
	if _, err := os.Stat(statusDirname); err != nil {
		if err := os.Mkdir(statusDirname, 0755); err != nil {
			log.Fatal(err)
		}
	}

	// XXX this is common code except for the types used with json
	// and uuid/iid check
	fileChanges := make(chan string)
	go watch.WatchConfigStatus(configDirname, statusDirname, fileChanges)
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
			statusFile := statusDirname + "/" + fileName
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
			statusName := statusDirname + "/" + fileName
			handleDelete(statusName, status)
			continue
		}
		if operation != "M" {
			log.Fatal("Unknown operation from Watcher: ", operation)
		}
		configFile := configDirname + "/" + fileName
		cb, err := ioutil.ReadFile(configFile)
		if err != nil {
			log.Printf("%s for %s\n", err, configFile)
			continue
		}
		config := types.EIDConfig{}
		if err := json.Unmarshal(cb, &config); err != nil {
			log.Printf("%s EIDConfig file: %s\n",
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
		statusFile := statusDirname + "/" + fileName
		if _, err := os.Stat(statusFile); err != nil {
			// File does not exist in status hence new
			statusName := statusDirname + "/" + fileName
			handleCreate(statusName, config)
			continue
		}
		// Read and check statusFile
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
			statusName := statusDirname + "/" + fileName
			handleCreate(statusName, config)
			// XXX set something to rescan?
			continue
		}
		if status.PendingDelete {
			statusName := statusDirname + "/" + fileName
			handleDelete(statusName, status)
			// XXX set something to rescan?
			continue
		}
		if status.PendingModify {
			statusName := statusDirname + "/" + fileName
			handleModify(statusName, config, status)
			// XXX set something to rescan?
			continue
		}
			
		statusName := statusDirname + "/" + fileName
		handleModify(statusName, config, status)
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

func handleCreate(statusFilename string, config types.EIDConfig) {
	log.Printf("handleCreate(%v,%d) for %s\n",
		config.UUIDandVersion, config.IID, config.DisplayName)

	// Start by marking with PendingAdd
	status := types.EIDStatus{
		UUIDandVersion: config.UUIDandVersion,
		DisplayName:    config.DisplayName,
		EIDStatusDetails: types.EIDStatusDetails{
			IID:		config.IID,
			EIDAllocation:	config.EIDAllocation,
			PendingAdd:     true,
			EID:		config.EID,
			LispSignature:	config.LispSignature,
			PemCert:	config.PemCert,
		},
	}
	// Default is 0xfd
	if len(config.AllocationPrefix) == 0 {
		config.AllocationPrefix = []byte{0xfd}
		config.AllocationPrefixLen = 8 * len(config.AllocationPrefix)
		status.EIDAllocation = config.EIDAllocation
	}
	// XXX defer write?
	// writeEIDStatus(&status, statusFilename)
	pemPrivateKey := config.PemPrivateKey

	var publicPem []byte
	if config.Allocate {
		// Generate a ECDSA key pair
		limit := new(big.Int).Lsh(big.NewInt(1), 128)
		serial, err := rand.Int(rand.Reader, limit)
		if err != nil {
			log.Printf("Generate serial failed: %s", err)
			return
		}
		// Give it a 20 year lifetime. XXX allow cloud to set lifetime?
		notBefore := time.Now()
		notAfter := notBefore.AddDate(20,0,0)
		fmt.Printf("notAfter %v\n", notAfter)

		// XXX allow cloud to set curve?
		keypair, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Printf("GenerateKey failed: %s", err)
			return
		}

		ct := x509.Certificate{
			SerialNumber: serial,
			Subject: pkix.Name{
				Country: []string{"US"},
				Province: []string{"CA"},
				Locality: []string{"Santa Clara"},
				Organization: []string{"Zededa, Inc"},
				CommonName: "Application Instance",
			},
			NotBefore: notBefore,
			NotAfter:  notAfter,
			IsCA: true,
			// XXX template.KeyUsage: x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		}

		// Generate self-signed certificate
		b, err := x509.CreateCertificate(rand.Reader, &ct, &ct,
			&keypair.PublicKey, keypair)
		if err != nil {
			log.Printf("Generate certificate failed: %s", err)
			return
		}
		status.PemCert = pem.EncodeToMemory(
			&pem.Block{Type: "CERTIFICATE", Bytes: b})

		var publicDer []byte
		publicPem, publicDer, err = extractPublicPem(&keypair.PublicKey)
		if err != nil {
			log.Printf("extractPublicPem failed: %s", err)
			// XXX any error cleanup?
			return
		}
		
		eid := generateEID(config.IID, config.AllocationPrefix,
			publicDer)
		fmt.Printf("EID: (len %d) %s\n", len(eid), eid)
		status.EID = eid

		signature, err := generateLispSignature(eid, config.IID, keypair)
		if err != nil {
			return
		}
		fmt.Println("signature:", signature)
		status.LispSignature = signature

		// Generate the PemPrivateKey
		pemPrivateKey, err = encodePrivateKey(keypair)
		if err != nil {
			return
		}
	} else {
		block, _ := pem.Decode(config.PemCert)
		if block == nil {
			log.Println("failed to decode PEM block containing certificate")
			return
		}
		if block.Type != "CERTIFICATE" {
			log.Println("failed to decode PEM block containing certificate. Type " +
				block.Type)
			return
		}
		appCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Println("ParseCerticate", err)
			return
		}
		publicPem, _, err = extractPublicPem(appCert.PublicKey)
		if err != nil {
			// XXX any error cleanup?
			return
		}
	}

	status.PemPublicKey = publicPem
	if config.ExportPrivate {
		status.PemPrivateKey = pemPrivateKey
	}
	status.PendingAdd = false
	writeEIDStatus(&status, statusFilename)
	log.Printf("handleCreate done for %s\n", config.DisplayName)
}

func extractPublicPem(pk interface{}) ([]byte, []byte, error) {
	// Extract the publicKey to make it easier for eidregister
	publicDer, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		log.Printf("MarshalPKIXPublicKey for %v failed:%v\n",
			pk, err)
		return nil, nil, err
	}
	// Form PEM for public key and print/store it
	var publicKey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicDer,
	}
	publicPem := pem.EncodeToMemory(publicKey)
	fmt.Printf("public %s\n", string(publicPem))
	return publicPem, publicDer, nil
}
	
// Generate the EID
func generateEID(iid uint32, allocationPrefix []byte, publicDer []byte) net.IP {
	iidData := make([]byte, 4)
	binary.BigEndian.PutUint32(iidData, iid)

	hasher := sha256.New()
	fmt.Printf("iidData % x\n", iidData)
	hasher.Write(iidData)
	fmt.Printf("AllocationPrefix % x\n", allocationPrefix)
	hasher.Write(allocationPrefix)
	hasher.Write(publicDer)
	sum := hasher.Sum(nil)
	fmt.Printf("SUM: (len %d) % 2x\n", len(sum), sum)
	// Truncate to get EidHashLen by taking the first
	// EidHashLen/8 bytes from the left.
	eid := net.IP(append(allocationPrefix, sum...)[0:16])
	return eid
}

// Generate the Lisp signature
func generateLispSignature(eid net.IP, iid uint32,
	keypair *ecdsa.PrivateKey) (string, error) {
	// Convert from IID and IPv6 EID to a string with
	// [iid]eid, where the eid has includes leading zeros i.e.
	// is a fixed 39 bytes long. The iid is printed as an integer.
	p := eid
	sigdata := fmt.Sprintf("[%d]%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
		iid,
		(uint32(p[0])<<8)|uint32(p[0+1]),
		(uint32(p[2])<<8)|uint32(p[2+1]),
		(uint32(p[4])<<8)|uint32(p[4+1]),
		(uint32(p[6])<<8)|uint32(p[6+1]),
		(uint32(p[8])<<8)|uint32(p[8+1]),
		(uint32(p[10])<<8)|uint32(p[10+1]),
		(uint32(p[12])<<8)|uint32(p[12+1]),
		(uint32(p[14])<<8)|uint32(p[14+1]))
	fmt.Printf("sigdata (len %d) %s\n", len(sigdata), sigdata)

	hasher := sha256.New()
	hasher.Write([]byte(sigdata))
	hash := hasher.Sum(nil)
	fmt.Printf("hash (len %d) % x\n", len(hash), hash)
	fmt.Printf("base64 hash %s\n",
		base64.StdEncoding.EncodeToString(hash))
	r, s, err := ecdsa.Sign(rand.Reader, keypair, hash)
	if err != nil {
		log.Println("ecdsa.Sign: ", err)
		return "", err
	}
	fmt.Printf("r.bytes %d s.bytes %d\n", len(r.Bytes()),
	len(s.Bytes()))
	sigres := r.Bytes()
	sigres = append(sigres, s.Bytes()...)
	fmt.Printf("sigres (len %d): % x\n", len(sigres), sigres)
	return base64.StdEncoding.EncodeToString(sigres), nil
}

func encodePrivateKey(keypair *ecdsa.PrivateKey) ([]byte, error) {
	b, err := x509.MarshalECPrivateKey(keypair)
	if err != nil {
		log.Printf("Unable to marshal ECDSA private key: %v", err)
		return nil, err
	}
	var privateKey = &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: b,
	}
	return pem.EncodeToMemory(privateKey), nil
}

// Need to compare what might have changed. If any content change
// then we need to reboot. Thus version by itself can change but nothing
// else. Such a version change would be e.g. due to an ACL change.
func handleModify(statusFilename string, config types.EIDConfig,
	status types.EIDStatus) {
	log.Printf("handleModify(%v,%d) for %s\n",
		config.UUIDandVersion, config.IID, config.DisplayName)

	if config.UUIDandVersion.Version == status.UUIDandVersion.Version {
		fmt.Printf("Same version %s for %s\n",
			config.UUIDandVersion.Version, statusFilename)
		return
	}
	status.PendingModify = true
	writeEIDStatus(&status, statusFilename)
	// XXX Any work?
	status.PendingModify = false
	writeEIDStatus(&status, statusFilename)
	log.Printf("handleModify done for %s\n", config.DisplayName)
}

// Need the olNum and ulNum to delete and EID route to delete
func handleDelete(statusFilename string, status types.EIDStatus) {
	log.Printf("handleDelete(%v,%d) for %s\n",
		status.UUIDandVersion, status.IID, status.DisplayName)

	// No work to do other than deleting the status

	// Write out what we modified aka delete
	if err := os.Remove(statusFilename); err != nil {
		log.Println("Failed to remove", statusFilename, err)
	}
	log.Printf("handleDelete done for %s\n", status.DisplayName)
}



