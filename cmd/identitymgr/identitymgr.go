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
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/zededa/go-provision/agentlog"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/pidfile"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"log"
	"math/big"
	"net"
	"os"
	"reflect"
	"time"
)

// Keeping status in /var/run to be clean after a crash/reboot
const (
	agentName = "identitymgr"
)

// Set from Makefile
var Version = "No version specified"

// Information for handleCreate/Modify/Delete
type identityContext struct {
	subEIDConfig *pubsub.Subscription
	pubEIDStatus *pubsub.Publication
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

	identityCtx := identityContext{}

	pubEIDStatus, err := pubsub.Publish(agentName,
		types.EIDStatus{})
	if err != nil {
		log.Fatal(err)
	}
	identityCtx.pubEIDStatus = pubEIDStatus
	pubEIDStatus.ClearRestarted()

	// Subscribe to EIDConfig from zedmanager
	subEIDConfig, err := pubsub.Subscribe("zedmanager",
		types.EIDConfig{}, false, &identityCtx)
	if err != nil {
		log.Fatal(err)
	}
	subEIDConfig.ModifyHandler = handleEIDConfigModify
	subEIDConfig.DeleteHandler = handleEIDConfigDelete
	subEIDConfig.RestartHandler = handleRestart
	identityCtx.subEIDConfig = subEIDConfig
	subEIDConfig.Activate()

	for {
		select {
		case change := <-subEIDConfig.C:
			subEIDConfig.ProcessChange(change)
		}
	}
}

func handleRestart(ctxArg interface{}, done bool) {
	log.Printf("handleRestart(%v)\n", done)
	ctx := ctxArg.(*identityContext)
	if done {
		// Since all work is done inline we can immediately say that
		// we have restarted.
		ctx.pubEIDStatus.SignalRestarted()
	}
}

func updateEIDStatus(ctx *identityContext, key string, status *types.EIDStatus) {

	log.Printf("updateEIDStatus(%s)\n", key)
	pub := ctx.pubEIDStatus
	pub.Publish(key, status)
}

func removeEIDStatus(ctx *identityContext, key string) {

	log.Printf("removeEIDStatus(%s)\n", key)
	pub := ctx.pubEIDStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Printf("removeEIDStatus(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

// Wrappers around handleCreate, handleModify, and handleDelete

// Determine whether it is an create or modify
func handleEIDConfigModify(ctxArg interface{}, key string, configArg interface{}) {

	log.Printf("handleEIDConfigModify(%s)\n", key)
	ctx := ctxArg.(*identityContext)
	config := cast.CastEIDConfig(configArg)
	if config.Key() != key {
		log.Printf("handleEIDConfigModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return
	}
	status := lookupEIDStatus(ctx, key)
	if status == nil {
		handleCreate(ctx, key, &config)
	} else {
		handleModify(ctx, key, &config, status)
	}
	log.Printf("handleEIDConfigModify(%s) done\n", key)
}

func handleEIDConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Printf("handleEIDConfigDelete(%s)\n", key)
	ctx := ctxArg.(*identityContext)
	status := cast.CastEIDStatus(statusArg)
	if status.Key() != key {
		log.Printf("handleEIDConfigDelete key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	handleDelete(ctx, key, &status)
	log.Printf("handleEIDConfigDelete(%s) done\n", key)
}

// Callers must be careful to publish any changes to EIDStatus
func lookupEIDStatus(ctx *identityContext, key string) *types.EIDStatus {

	pub := ctx.pubEIDStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Printf("lookupEIDStatus(%s) not found\n", key)
		return nil
	}
	status := cast.CastEIDStatus(st)
	if status.Key() != key {
		log.Printf("lookupEIDStatus key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func lookupEIDConfig(ctx *identityContext, key string) *types.EIDConfig {

	sub := ctx.subEIDConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Printf("lookupEIDConfig(%s) not found\n", key)
		return nil
	}
	config := cast.CastEIDConfig(c)
	if config.Key() != key {
		log.Printf("lookupEIDConfig key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return nil
	}
	return &config
}

func handleCreate(ctx *identityContext, key string, config *types.EIDConfig) {
	log.Printf("handleCreate(%s) for %s\n", key, config.DisplayName)

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
	updateEIDStatus(ctx, key, &status)
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
	updateEIDStatus(ctx, key, &status)
	log.Printf("handleCreate(%s) done for %s\n", key, config.DisplayName)
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
func handleModify(ctx *identityContext, key string, config *types.EIDConfig,
	status *types.EIDStatus) {

	log.Printf("handleModify(%s) for %s\n", key, config.DisplayName)

	if config.UUIDandVersion.Version == status.UUIDandVersion.Version {
		log.Printf("Same version %s for %s\n",
			config.UUIDandVersion.Version, key)
		return
	}
	// Reject any changes to EIDAllocation.
	// XXX report internal error?
	// XXX switch to Equal?
	if !reflect.DeepEqual(status.EIDAllocation, config.EIDAllocation) {
		log.Printf("handleModify(%s) EIDAllocation changed for %s\n",
			key, config.DisplayName)
		return
	}
	status.PendingModify = true
	updateEIDStatus(ctx, key, status)
	// XXX Any work in modify?
	status.PendingModify = false
	status.UUIDandVersion = config.UUIDandVersion
	updateEIDStatus(ctx, key, status)
	log.Printf("handleModify(%s) done for %s\n", key, config.DisplayName)
}

func handleDelete(ctx *identityContext, key string, status *types.EIDStatus) {

	log.Printf("handleDelete(%s) for %s\n", key, status.DisplayName)

	// No work to do other than deleting the status

	// Write out what we modified aka delete
	removeEIDStatus(ctx, key)
	log.Printf("handleDelete(%s) done for %s\n", key, status.DisplayName)
}
