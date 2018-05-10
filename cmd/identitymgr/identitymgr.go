// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Manage the allocation of EIDs for application instances based on input
// as EIDConfig structs in /var/tmp/identitymgr/config/*.json and report
// on status in the collection of EIDStatus structs in
// /var/run/identitymgr/status/*.json

package identitymgr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"reflect"
	"time"
)

// Keeping status in /var/run to be clean after a crash/reboot
const (
	agentName     = "identitymgr"
	baseDirname   = "/var/tmp/identitymgr"
	runDirname    = "/var/run/identitymgr"
	configDirname = baseDirname + "/config"
	statusDirname = runDirname + "/status"
)

// Set from Makefile
var Version = "No version specified"

// Dummy since we don't have anything to pass
type dummyContext struct {
}

func Run() {
	logf, err := agentlog.Init(agentName)
	if err != nil {
	       log.Fatal(err)
	}
	defer logf.Close()

	versionPtr := flag.Bool("v", false, "Version")
	flag.Parse()
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
		log.Fatal(err)
	}
	log.Printf("Starting %s\n", agentName)
	watch.CleanupRestarted(agentName)

	if _, err := os.Stat(baseDirname); err != nil {
		log.Printf("Create %s\n", baseDirname)
		if err := os.Mkdir(baseDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(configDirname); err != nil {
		log.Printf("Create %s\n", configDirname)
		if err := os.Mkdir(configDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(runDirname); err != nil {
		log.Printf("Create %s\n", runDirname)
		if err := os.Mkdir(runDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(statusDirname); err != nil {
		log.Printf("Create %s\n", statusDirname)
		if err := os.Mkdir(statusDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	var restartFn watch.ConfigRestartHandler = handleRestart

	fileChanges := make(chan string)
	go watch.WatchConfigStatus(configDirname, statusDirname, fileChanges)
	for {
		change := <-fileChanges
		watch.HandleConfigStatusEvent(change, dummyContext{},
			configDirname, statusDirname,
			&types.EIDConfig{},
			&types.EIDStatus{},
			handleCreate, handleModify, handleDelete, &restartFn)
	}
}

func handleRestart(ctxArg interface{}, done bool) {
	log.Printf("handleRestart(%v)\n", done)
	if done {
		// Since all work is done inline we can immediately say that
		// we have restarted.
		watch.SignalRestarted(agentName)
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

func handleCreate(ctxArg interface{}, statusFilename string,
	configArg interface{}) {
	config := configArg.(*types.EIDConfig)
	log.Printf("handleCreate(%v,%d) for %s\n",
		config.UUIDandVersion, config.IID, config.DisplayName)

	// Start by marking with PendingAdd
	status := types.EIDStatus{
		UUIDandVersion: config.UUIDandVersion,
		DisplayName:    config.DisplayName,
		EIDStatusDetails: types.EIDStatusDetails{
			IID:           config.IID,
			EIDAllocation: config.EIDAllocation,
			PendingAdd:    true,
			EID:           config.EID,
			LispSignature: config.LispSignature,
			PemCert:       config.PemCert,
		},
	}
	// Default is 0xfd
	if len(config.AllocationPrefix) == 0 {
		config.AllocationPrefix = []byte{0xfd}
		config.AllocationPrefixLen = 8 * len(config.AllocationPrefix)
		status.EIDAllocation = config.EIDAllocation
	}
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
		notAfter := notBefore.AddDate(20, 0, 0)
		log.Printf("notAfter %v\n", notAfter)

		// XXX allow cloud to set curve?
		keypair, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Printf("GenerateKey failed: %s", err)
			return
		}

		ct := x509.Certificate{
			SerialNumber: serial,
			Subject: pkix.Name{
				Country:      []string{"US"},
				Province:     []string{"CA"},
				Locality:     []string{"Santa Clara"},
				Organization: []string{"Zededa, Inc"},
				CommonName:   "Application Instance",
			},
			NotBefore: notBefore,
			NotAfter:  notAfter,
			IsCA:      true,
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
		log.Printf("EID: (len %d) %s\n", len(eid), eid)
		status.EID = eid
		status.CreateTime = time.Now()
		signature, err := generateLispSignature(eid, config.IID, keypair)
		if err != nil {
			return
		}
		log.Println("signature:", signature)
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
	log.Printf("public %s\n", string(publicPem))
	return publicPem, publicDer, nil
}

// Generate the EID
func generateEID(iid uint32, allocationPrefix []byte, publicDer []byte) net.IP {
	iidData := make([]byte, 4)
	binary.BigEndian.PutUint32(iidData, iid)

	hasher := sha256.New()
	log.Printf("iidData % x\n", iidData)
	hasher.Write(iidData)
	log.Printf("AllocationPrefix % x\n", allocationPrefix)
	hasher.Write(allocationPrefix)
	hasher.Write(publicDer)
	sum := hasher.Sum(nil)
	log.Printf("SUM: (len %d) % 2x\n", len(sum), sum)
	// Truncate to get EidHashLen by taking the first
	// EidHashLen/8 bytes from the left.
	eid := net.IP(append(allocationPrefix, sum...)[0:16])
	return eid
}

// Generate the Lisp signature
func generateLispSignature(eid net.IP, iid uint32,
	keypair *ecdsa.PrivateKey) (string, error) {

	// Convert from IID and IPv6 EID to a string with
	// [iid]eid, where the eid uses the textual format defined in
	// RFC 5952. The iid is printed as an integer.
	sigdata := fmt.Sprintf("[%d]%s", iid, eid.String())
	log.Printf("sigdata (len %d) %s\n", len(sigdata), sigdata)

	hasher := sha256.New()
	hasher.Write([]byte(sigdata))
	hash := hasher.Sum(nil)
	log.Printf("hash (len %d) % x\n", len(hash), hash)
	log.Printf("base64 hash %s\n",
		base64.StdEncoding.EncodeToString(hash))
	r, s, err := ecdsa.Sign(rand.Reader, keypair, hash)
	if err != nil {
		log.Println("ecdsa.Sign: ", err)
		return "", err
	}
	log.Printf("r.bytes %d s.bytes %d\n", len(r.Bytes()),
		len(s.Bytes()))
	sigres := r.Bytes()
	sigres = append(sigres, s.Bytes()...)
	log.Printf("sigres (len %d): % x\n", len(sigres), sigres)
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
func handleModify(ctxArg interface{}, statusFilename string, configArg interface{},
	statusArg interface{}) {
	config := configArg.(*types.EIDConfig)
	status := statusArg.(*types.EIDStatus)
	log.Printf("handleModify(%v,%d) for %s\n",
		config.UUIDandVersion, config.IID, config.DisplayName)

	if config.UUIDandVersion.Version == status.UUIDandVersion.Version {
		log.Printf("Same version %s for %s\n",
			config.UUIDandVersion.Version, statusFilename)
		return
	}
	// Reject any changes to EIDAllocation.
	// XXX report internal error?
	if !reflect.DeepEqual(status.EIDAllocation, config.EIDAllocation) {
		log.Printf("handleModify(%v,%d) EIDAllocation changed for %s\n",
			config.UUIDandVersion, config.IID, config.DisplayName)
		return
	}
	status.PendingModify = true
	writeEIDStatus(status, statusFilename)
	// XXX Any work in modify?
	status.PendingModify = false
	status.UUIDandVersion = config.UUIDandVersion
	writeEIDStatus(status, statusFilename)
	log.Printf("handleModify done for %s\n", config.DisplayName)
}

func handleDelete(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {
	status := statusArg.(*types.EIDStatus)
	log.Printf("handleDelete(%v,%d) for %s\n",
		status.UUIDandVersion, status.IID, status.DisplayName)

	// No work to do other than deleting the status

	// Write out what we modified aka delete
	if err := os.Remove(statusFilename); err != nil {
		log.Println(err)
	}
	log.Printf("handleDelete done for %s\n", status.DisplayName)
}
