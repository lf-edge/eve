package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/nanobox-io/golang-scribble"
	"github.com/zededa/go-provision/types"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"time"
)

var zedServerConfig types.ZedServerConfig

// Assumes the config files are in dirName, which is
// is /usr/local/etc/zededa-server/ by default. The files are
//  intermediate-server.cert.pem  server cert plus intermediate CA cert
//  server.key.pem
//  zedserverconfig.json	ZedServerConfig sent to devices
// Note that the IIDs and LISP passwords are random.
//
func main() {
	args := os.Args[1:]
	if len(args) > 1 {
		log.Fatal("Usage: " + os.Args[0] + "[<dirName>]")
	}
	dirName := "/usr/local/etc/zededa-server/"
	if len(args) > 0 {
		dirName = args[0]
	}

	serverCertName := dirName + "/intermediate-server.cert.pem"
	serverKeyName := dirName + "/server.key.pem"
	zedServerConfigFileName := dirName + "/zedserverconfig.json"

	http.HandleFunc("/rest/self-register", SelfRegister)
	http.HandleFunc("/rest/device-param", DeviceParam)
	http.HandleFunc("/rest/update-hw-status", UpdateHwStatus)
	http.HandleFunc("/rest/update-sw-status", UpdateSwStatus)

	zcb, err := ioutil.ReadFile(zedServerConfigFileName)
	if err != nil {
		log.Fatal(err)
	}
	zedServerConfig = types.ZedServerConfig{}
	if err := json.Unmarshal(zcb, &zedServerConfig); err != nil {
		log.Fatal("Error decoding ZedServerConfig:\n", err)
	}

	serverCert, err := tls.LoadX509KeyPair(serverCertName, serverKeyName)
	if err != nil {
		log.Fatal(err)
	}

	// seed oscpResponse and oscpResponseBytes using serverCert
	var ocspTimer int64 // periodic timer value
	var timerBackoff int64 = 1
	var ocspResponse *ocsp.Response
	var ocspResponseBytes []byte
	var lastOcspUpdate, lastOcspUse time.Time

	done := false
	// XXX ocsp01 not reachable
	// done = true; ocspTimer = 60000
	for !done {
		var err error
		ocspResponse, ocspResponseBytes, err =
			getOcspResponseBytes(&serverCert)
		if err != nil {
			log.Println(err)
			time.Sleep(5 * time.Second)
			continue
		}

		now := time.Now()
		age := now.Unix() - ocspResponse.ProducedAt.Unix()
		remain := ocspResponse.NextUpdate.Unix() - now.Unix()
		log.Printf("OCSP age %d, remain %d\n", age, remain)
		// Check again after half the remaining time
		ocspTimer = remain / 2
		if ocspResponse.Status == ocsp.Good {
			log.Println("Certificate Status Good.")
			done = true
			lastOcspUpdate = now
		} else if ocspResponse.Status == ocsp.Unknown {
			log.Println("Certificate Status Unknown")
			time.Sleep(5 * time.Second)
		} else {
			log.Println("Certificate Status Revoked")
			time.Sleep(5 * time.Second)
		}
	}
	log.Printf("Setup timer every %d seconds\n", ocspTimer)

	var periodicOcsp func()
	var t *time.Timer

	// XXX use this for initial assignment? Need a non-zero ocspTimer in
	// case the initial fails? But want one success before starting
	// to serve requests.
	// Channel to send "done" to caller? Plus 1,2,4,8 ocspTimer until
	// we have a response?
	periodicOcsp = func() {
		// XXX update time based on lastOcspUse
		if lastOcspUse.Before(lastOcspUpdate) {
			timerBackoff *= 2
			log.Printf("OCSP was not used. Backoff %d\n",
				timerBackoff)
		}
		// If we get an updated success, then we use that for subsequent
		// stapling
		response, responseBytes, err :=
			getOcspResponseBytes(&serverCert)
		if err == nil {
			// Have an updated response to staple
			ocspResponse = response
			ocspResponseBytes = responseBytes
			now := time.Now()
			age := now.Unix() - ocspResponse.ProducedAt.Unix()
			remain := ocspResponse.NextUpdate.Unix() - now.Unix()
			log.Printf("OCSP age %d, remain %d\n", age, remain)
			// Check again after half the remaining time
			ocspTimer = remain / 2
			if ocspResponse.Status == ocsp.Good {
				log.Println("Certificate Status Good.")
				lastOcspUpdate = now
			} else if ocspResponse.Status == ocsp.Unknown {
				log.Println("Certificate Status Unknown")
			} else {
				log.Println("Certificate Status Revoked")
			}
		}
		t = time.AfterFunc(time.Duration(timerBackoff*ocspTimer)*
			time.Second, periodicOcsp)
	}
	t = time.AfterFunc(time.Duration(timerBackoff*ocspTimer)*
		time.Second, periodicOcsp)
	defer t.Stop()

	// XXX could we instead update serverCert when we run the periodic
	// function?
	getCertificate := func(hello *tls.ClientHelloInfo) (*tls.Certificate,
		error) {
		cert := serverCert
		now := time.Now()
		lastOcspUse = now
		// XXX needed if we don't require on startup
		if ocspResponseBytes == nil {
			return &cert, nil
		}
		// We staple the cert we have even if it is not Good
		age := now.Unix() - ocspResponse.ProducedAt.Unix()
		remain := ocspResponse.NextUpdate.Unix() - now.Unix()
		log.Printf("OCSP status %v, age %d, remain %d\n",
			ocspResponse.Status, age, remain)
		if remain < 0 {
			// Force update now. Reset timerBackoff.
			log.Println("OCSP expired - force update.")
			response, responseBytes, err :=
				getOcspResponseBytes(&cert)
			if err == nil {
				// Have an updated response to staple
				ocspResponse = response
				ocspResponseBytes = responseBytes
				now := time.Now()
				age := now.Unix() - ocspResponse.ProducedAt.Unix()
				remain := ocspResponse.NextUpdate.Unix() - now.Unix()
				log.Printf("OCSP age %d, remain %d\n", age, remain)
				// Check again after half the remaining time
				ocspTimer = remain / 2
				if ocspResponse.Status == ocsp.Good {
					log.Println("Certificate Status Good.")
					lastOcspUpdate = now
				} else if ocspResponse.Status == ocsp.Unknown {
					log.Println("Certificate Status Unknown")
				} else {
					log.Println("Certificate Status Revoked")
				}
			}
			timerBackoff = 1
			t = time.AfterFunc(time.Duration(timerBackoff*ocspTimer)*
				time.Second, periodicOcsp)
		}
		cert.OCSPStaple = ocspResponseBytes
		return &cert, nil
	}
	// Setup HTTPS client
	tlsConfig := &tls.Config{
		GetCertificate: getCertificate,
		ClientAuth:     tls.RequireAnyClientCert,
		// PFS because we can but this will reject client with RSA
		// certificates
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		// Force it server side
		PreferServerCipherSuites: true,
		// TLS 1.2 because we can
		MinVersion: tls.VersionTLS12,
	}
	tlsConfig.BuildNameToCertificate()

	server := &http.Server{
		Addr:      ":9069",
		TLSConfig: tlsConfig,
	}

	err = server.ListenAndServeTLS(serverCertName, serverKeyName)
	if err != nil {
		log.Fatal(err)
	}
}

func getOcspResponseBytes(cert *tls.Certificate) (*ocsp.Response, []byte,
	error) {
	// Fetch OCSP
	x509Cert := cert.Leaf
	if cert.Leaf == nil {
		// Above load drops parsed form
		parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			log.Println("x509.ParseCertificate 0", err)
			return nil, nil, err
		}
		x509Cert = parsedCert
	}
	if x509Cert.OCSPServer == nil {
		log.Println("No OCSPServer in certificate")
		return nil, nil, errors.New("No OCSPServer in certificate")
	}
	ocspServer := x509Cert.OCSPServer[0]
	if len(cert.Certificate) == 1 {
		log.Println("No issuer in certificate")
		return nil, nil, errors.New("No issuer in certificate")
	}
	x509Issuer, err := x509.ParseCertificate(cert.Certificate[1])
	if err != nil {
		log.Println("x509.ParseCertificate 1", err)
		return nil, nil, err
	}
	ocspRequest, err := ocsp.CreateRequest(x509Cert, x509Issuer, nil)
	if err != nil {
		log.Println("ocsp.CreateRequest", err)
		return nil, nil, err
	}
	fmt.Printf("Connecting to OCSP at %s\n", ocspServer)
	ocspRequestReader := bytes.NewReader(ocspRequest)
	httpResponse, err := http.Post(ocspServer, "application/ocsp-request",
		ocspRequestReader)
	if err != nil {
		log.Println("http.Post ocsp", err)
		return nil, nil, err
	}
	defer httpResponse.Body.Close()
	ocspResponseBytes, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		log.Println("getOcspResponseBytes ReadAll", err)
		return nil, nil, err
	}
	// XXX parse http return code?
	ocspResponse, err := ocsp.ParseResponse(ocspResponseBytes, x509Issuer)
	if err != nil {
		log.Println("ocsp.ParseResponse", err)
		return nil, nil, err
	}
	return ocspResponse, ocspResponseBytes, err
}

func SelfRegister(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Method %s Host %s Proto %s\n", r.Method, r.Host,
		r.Proto)
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed),
			http.StatusMethodNotAllowed)
		return
	}
	cert := r.TLS.PeerCertificates[0]
	// Validating it is self-signed
	if !cert.IsCA || !reflect.DeepEqual(cert.Issuer, cert.Subject) {
		fmt.Printf("provCert not self-signed: Issuer %s, Subject %s, IsCa %s\n",
			cert.Issuer, cert.Subject, cert.IsCA)
		http.Error(w, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	// validate it has not expired
	now := time.Now()
	if now.After(cert.NotAfter) {
		// XXX use log instead?
		fmt.Printf("provCert expired NotAfter %s, now %s\n",
			cert.NotAfter, now)
		http.Error(w, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	if now.Before(cert.NotBefore) {
		fmt.Printf("provCert too early NotBefore %s, now %s\n",
			cert.NotBefore, now)
		http.Error(w, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}

	hasher := sha256.New()
	hasher.Write(cert.Raw)
	provKey := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	fmt.Println("provKey:", provKey)

	// Look up in database
	// XXX create db and deviceDb and put in global vars!
	// a new or existing scribble driver, providing the directory
	// where it will be writing to, and a qualified logger if desired
	db, err := scribble.New("/var/tmp/zededa-prov", nil)
	if err != nil {
		fmt.Println("scribble.New", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	prov := types.ProvisioningCert{}
	if err := db.Read("prov", provKey, &prov); err != nil {
		fmt.Println("db.Read", err)
		http.Error(w, http.StatusText(http.StatusNotFound),
			http.StatusNotFound)
		return
	}
	userName := prov.UserName
	// Check we have a reasonable content-length
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		fmt.Println("Incorrect Content-Type " + contentType)
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType),
			http.StatusUnsupportedMediaType)
		return
	}
	contentLength := r.Header.Get("Content-Length")
	if contentLength == "" {
		fmt.Println("No Content-Length field")
		http.Error(w, http.StatusText(http.StatusLengthRequired),
			http.StatusLengthRequired)
		return
	}
	length, err := strconv.Atoi(contentLength)
	if err != nil {
		fmt.Println("Atoi", err)
		http.Error(w, http.StatusText(http.StatusBadRequest),
			http.StatusBadRequest)
		return
	}
	// XXX what is the max device certificate length? Have up to 753
	if length > 4096 {
		fmt.Printf("Too large Content-Length %d\n", length)
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge),
			http.StatusRequestEntityTooLarge)
		return
	}

	// parsing RegisterCreate json payload
	rc := &types.RegisterCreate{}
	if err := json.NewDecoder(r.Body).Decode(rc); err != nil {
		fmt.Printf("Error decoding RegisterCreate: %s\n", err)
		http.Error(w, http.StatusText(http.StatusBadRequest),
			http.StatusBadRequest)
		return
	}
	// Check if the payload is a certificate in pem format and compute sha256
	block, _ := pem.Decode(rc.PemCert)
	if block == nil || block.Type != "CERTIFICATE" {
		fmt.Println("failed to decode PEM block containing certificate. Type " +
			block.Type)
		http.Error(w, http.StatusText(http.StatusBadRequest),
			http.StatusBadRequest)
		return
	}
	hasher = sha256.New()
	hasher.Write(block.Bytes)
	deviceKey := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	fmt.Println("deviceKey:", deviceKey)

	deviceDb, err := scribble.New("/var/tmp/zededa-device", nil)
	if err != nil {
		fmt.Println("scribble.New", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	device := types.DeviceDb{}
	err = deviceDb.Read("ddb", deviceKey, &device)
	if err == nil {
		if device.UserName == userName {
			if reflect.DeepEqual(device.DeviceCert, rc.PemCert) {
				// Re-registering the same key with same value
				fmt.Printf("Identical device cert already exists in deviceDb since %s\n",
					device.RegTime)
				// Update counter for reregistrations which indicate
				// retransmissions/retries
				device.ReRegisteredCount++
				err = deviceDb.Write("ddb", deviceKey, device)
				if err != nil {
					fmt.Println("deviceDb.Write", err)
					// Note we ignore error and ReRegisteredCount will not be
					// updated
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
			} else {
				fmt.Printf("Conflict: same hash but different certificate for deviceKey %s\n",
					deviceKey)
				fmt.Printf("Old cert %v since %s, attempted cert %v\n",
					device.DeviceCert, device.RegTime, rc.PemCert)
				http.Error(w, http.StatusText(http.StatusConflict),
					http.StatusConflict)
			}
		} else {
			// Different userName
			fmt.Printf("Conflict: different userName for deviceKey %s\n",
				deviceKey)
			fmt.Printf("Old userName %v since %s, attempted userName %v\n",
				device.UserName, device.RegTime, userName)
			http.Error(w, http.StatusText(http.StatusConflict),
				http.StatusConflict)
		}
		return
	}
	if prov.RemainingUse == 0 {
		fmt.Printf("provCert already used. Registered at %s. LastUsed at %s\n",
			prov.RegTime, prov.LastUsedTime)
		http.Error(w, http.StatusText(http.StatusGone),
			http.StatusGone)
		return
	}
	deviceCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("ParseCerticate", err)
		http.Error(w, http.StatusText(http.StatusBadRequest),
			http.StatusBadRequest)
		return
	}
	publicDer, err := x509.MarshalPKIXPublicKey(deviceCert.PublicKey)
	if err != nil {
		fmt.Println("MarshalPKIXPublicKey", err)
		http.Error(w, http.StatusText(http.StatusBadRequest),
			http.StatusBadRequest)
		return
	}
	// XXX remove? check content with Dino
	fmt.Printf("publicDer (len %d) % x\n", len(publicDer), publicDer)

	// Form PEM for public key and print/store it
	var publicKey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicDer,
	}
	publicPem := pem.EncodeToMemory(publicKey)
	fmt.Printf("public %s\n", string(publicPem))

	// Form an EID based on the sha256 hash of the public key.
	// Use the prefix and instanceId as input to the hash.

	// XXX lispInstance should come from user's account info
	// XXX we make it a hash of the userName
	hasher = sha256.New()
	hasher.Write([]byte(userName))
	sum := hasher.Sum(nil)
	lispInstance := uint32(65536) + 256*uint32(sum[0]) + uint32(sum[1])
	fmt.Printf("lispInstance %v\n", lispInstance)

	iidData := make([]byte, 4)
	binary.BigEndian.PutUint32(iidData, lispInstance)

	eidPrefix := []byte{0xFD} // Hard-coded for Zededa management overlay
	eidHashLen := 128 - len(eidPrefix)*8

	// XXX temporary to get raw
	if true {
		hasher = sha256.New()
		hasher.Write(publicDer)
		sum := hasher.Sum(nil)
		fmt.Printf("RAW SUM: (len %d) % 2x\n", len(sum), sum)
		fmt.Printf("RAW2 SUM: % 2x\n", sha256.Sum256(publicDer))
	}
	// XXX new
	hasher = sha256.New()
	fmt.Printf("iidData % x\n", iidData)
	hasher.Write(iidData)
	fmt.Printf("eidPrefix % x\n", eidPrefix)
	hasher.Write(eidPrefix)
	hasher.Write(publicDer)
	sum = hasher.Sum(nil)
	fmt.Printf("SUM: (len %d) % 2x\n", len(sum), sum)
	// Truncate to get EidHashLen by taking the first EidHashLen/8 bytes
	// from the left.
	eid := net.IP(append(eidPrefix, sum...)[0:16])
	fmt.Printf("EID: (len %d) %s\n", len(eid), eid)
	if false {
		/// XXX using hmac with zero length key
		mac := hmac.New(sha256.New, []byte{})
		mac.Write(iidData)
		mac.Write(eidPrefix)
		mac.Write(publicDer)
		sum = mac.Sum(nil)
		fmt.Printf("SUM: (len %d) % 2x\n", len(sum), sum)
		eid := net.IP(append(eidPrefix, sum...)[0:16])
		fmt.Printf("EID: (len %d) %s\n", len(eid), eid)
	}
	// We generate different credentials for different users,
	// using the fact that each user has a different lispInstance
	credential1 := fmt.Sprintf("test1_%d", lispInstance)
	credential2 := fmt.Sprintf("test2_%d", lispInstance)
	device = types.DeviceDb{
		DeviceCert:      rc.PemCert,
		DevicePublicKey: publicPem,
		UserName:        userName,
		RegTime:         time.Now(),
		LispMapServers: []types.LispServerInfo{
			{"ms1.zededa.net", credential1},
			{"ms2.zededa.net", credential2},
		},
		LispInstance: lispInstance,
		EID:          eid,
		EIDHashLen:   uint8(eidHashLen),
		ZedServers:   zedServerConfig,
	}
	err = deviceDb.Write("ddb", deviceKey, device)
	if err != nil {
		fmt.Println("deviceDb.Write", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}

	// Created in deviceDb under userName, so we decrement the remaining uses
	prov.RemainingUse--
	prov.LastUsedTime = time.Now()
	err = db.Write("prov", provKey, prov)
	if err != nil {
		fmt.Println("db.Write", err)
		// Note we ignore error and RemainingUse is not updated; but we did
		// registed deviceCert. Alternative is to undo the deviceCert registration
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
}

func DeviceParam(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Method %s Host %s Proto %s\n", r.Method, r.Host,
		r.Proto)
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed),
			http.StatusMethodNotAllowed)
		return
	}
	cert := r.TLS.PeerCertificates[0]

	// XXX support rooted device certificates. Call validate on some chain?
	// XXX should that be our own trust chain?
	// Validating it is self-signed
	if !cert.IsCA || !reflect.DeepEqual(cert.Issuer, cert.Subject) {
		fmt.Printf("deviceCert not self-signed: Issuer %s, Subject %s, IsCa %s\n",
			cert.Issuer, cert.Subject, cert.IsCA)
		http.Error(w, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	// validate it has not expired
	now := time.Now()
	if now.Before(cert.NotBefore) {
		// XXX use log instead?
		fmt.Printf("deviceCert too new: NotBefore %s, now %s\n",
			cert.NotBefore, now)
		http.Error(w, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	if now.After(cert.NotAfter) {
		fmt.Printf("deviceCert too old: NotAfter %s, now %s\n",
			cert.NotAfter, now)
		http.Error(w, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	hasher := sha256.New()
	hasher.Write(cert.Raw)
	deviceKey := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	fmt.Println("deviceKey:", deviceKey)

	// Look up in device database
	// a new or existing scribble driver, providing the directory
	// where it will be writing to, and a qualified logger if desired
	deviceDb, err := scribble.New("/var/tmp/zededa-device", nil)
	if err != nil {
		fmt.Println("scribble.New", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	device := types.DeviceDb{}
	if err := deviceDb.Read("ddb", deviceKey, &device); err != nil {
		fmt.Println("deviceDb.Read", err)
		http.Error(w, http.StatusText(http.StatusNotFound),
			http.StatusNotFound)
		return
	}
	// XXX if device.Redirect == true, should we use diff code?
	res, _ := json.Marshal(device)
	device.ReadTime = time.Now()
	if err := deviceDb.Write("ddb", deviceKey, device); err != nil {
		fmt.Println("deviceDb.Write", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(res)
}

// XXX lots of commonality with above up to lookup of deviceKey
// XXX lots of commonality with UpdateSwStatus
func UpdateHwStatus(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Method %s Host %s Proto %s\n", r.Method, r.Host,
		r.Proto)
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed),
			http.StatusMethodNotAllowed)
		return
	}
	cert := r.TLS.PeerCertificates[0]

	// XXX support rooted device certificates. Call validate on some chain?
	// XXX should that be our own trust chain?
	// Validating it is self-signed
	if !cert.IsCA || !reflect.DeepEqual(cert.Issuer, cert.Subject) {
		fmt.Printf("deviceCert not self-signed: Issuer %s, Subject %s, IsCa %s\n",
			cert.Issuer, cert.Subject, cert.IsCA)
		http.Error(w, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	// validate it has not expired
	now := time.Now()
	if now.Before(cert.NotBefore) {
		fmt.Printf("deviceCert too new: NotBefore %s, now %s\n",
			cert.NotBefore, now)
		http.Error(w, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	if now.After(cert.NotAfter) {
		fmt.Printf("deviceCert too old: NotAfter %s, now %s\n",
			cert.NotAfter, now)
		http.Error(w, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	hasher := sha256.New()
	hasher.Write(cert.Raw)
	deviceKey := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	fmt.Println("deviceKey:", deviceKey)

	// Look up in device database
	// a new or existing scribble driver, providing the directory
	// where it will be writing to, and a qualified logger if desired
	deviceDb, err := scribble.New("/var/tmp/zededa-device", nil)
	if err != nil {
		fmt.Println("scribble.New", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	device := types.DeviceDb{}
	if err := deviceDb.Read("ddb", deviceKey, &device); err != nil {
		fmt.Println("deviceDb.Read", err)
		http.Error(w, http.StatusText(http.StatusNotFound),
			http.StatusNotFound)
		return
	}
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		fmt.Println("Incorrect Content-Type " + contentType)
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType),
			http.StatusUnsupportedMediaType)
		return
	}
	contentLength := r.Header.Get("Content-Length")
	if contentLength == "" {
		fmt.Println("No Content-Length field")
		http.Error(w, http.StatusText(http.StatusLengthRequired),
			http.StatusLengthRequired)
		return
	}
	length, err := strconv.Atoi(contentLength)
	if err != nil {
		fmt.Println("Atoi", err)
		http.Error(w, http.StatusText(http.StatusBadRequest),
			http.StatusBadRequest)
		return
	}
	// XXX which max length?
	if length > 4096 {
		fmt.Printf("Too large Content-Length %d\n", length)
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge),
			http.StatusRequestEntityTooLarge)
		return
	}

	// parsing DeviceHwStatus json payload
	hwStatus := &types.DeviceHwStatus{}
	if err := json.NewDecoder(r.Body).Decode(hwStatus); err != nil {
		fmt.Printf("Error decoding DeviceHwStatus: %s\n", err)
		http.Error(w, http.StatusText(http.StatusBadRequest),
			http.StatusBadRequest)
		return
	}
	if err := deviceDb.Write("hw-status", deviceKey, hwStatus); err != nil {
		fmt.Println("deviceDb.Write", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// XXX created vs. updated?
	w.WriteHeader(http.StatusCreated)
}

// XXX lots of commonality with UpdateHwStatus
func UpdateSwStatus(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Method %s Host %s Proto %s\n", r.Method, r.Host,
		r.Proto)
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed),
			http.StatusMethodNotAllowed)
		return
	}
	cert := r.TLS.PeerCertificates[0]

	// XXX support rooted device certificates. Call validate on some chain?
	// XXX should that be our own trust chain?
	// Validating it is self-signed
	if !cert.IsCA || !reflect.DeepEqual(cert.Issuer, cert.Subject) {
		fmt.Printf("deviceCert not self-signed: Issuer %s, Subject %s, IsCa %s\n",
			cert.Issuer, cert.Subject, cert.IsCA)
		http.Error(w, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	// validate it has not expired
	now := time.Now()
	if now.Before(cert.NotBefore) {
		fmt.Printf("deviceCert too new: NotBefore %s, now %s\n",
			cert.NotBefore, now)
		http.Error(w, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	if now.After(cert.NotAfter) {
		fmt.Printf("deviceCert too old: NotAfter %s, now %s\n",
			cert.NotAfter, now)
		http.Error(w, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	hasher := sha256.New()
	hasher.Write(cert.Raw)
	deviceKey := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	fmt.Println("deviceKey:", deviceKey)

	// Look up in device database
	// a new or existing scribble driver, providing the directory
	// where it will be writing to, and a qualified logger if desired
	deviceDb, err := scribble.New("/var/tmp/zededa-device", nil)
	if err != nil {
		fmt.Println("scribble.New", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	device := types.DeviceDb{}
	if err := deviceDb.Read("ddb", deviceKey, &device); err != nil {
		fmt.Println("deviceDb.Read", err)
		http.Error(w, http.StatusText(http.StatusNotFound),
			http.StatusNotFound)
		return
	}
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		fmt.Println("Incorrect Content-Type " + contentType)
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType),
			http.StatusUnsupportedMediaType)
		return
	}
	contentLength := r.Header.Get("Content-Length")
	if contentLength == "" {
		fmt.Println("No Content-Length field")
		http.Error(w, http.StatusText(http.StatusLengthRequired),
			http.StatusLengthRequired)
		return
	}
	length, err := strconv.Atoi(contentLength)
	if err != nil {
		fmt.Println("Atoi", err)
		http.Error(w, http.StatusText(http.StatusBadRequest),
			http.StatusBadRequest)
		return
	}
	// XXX which max length? How many applications?
	if length > 4*4096 {
		fmt.Printf("Too large Content-Length %d\n", length)
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge),
			http.StatusRequestEntityTooLarge)
		return
	}

	// parsing DeviceSwStatus json payload
	swStatus := &types.DeviceSwStatus{}
	if err := json.NewDecoder(r.Body).Decode(swStatus); err != nil {
		fmt.Printf("Error decoding DeviceSwStatus: %s\n", err)
		http.Error(w, http.StatusText(http.StatusBadRequest),
			http.StatusBadRequest)
		return
	}
	fmt.Printf("DeviceSwStatus contains %d applications\n",
		len(swStatus.ApplicationStatus))
	for _, s := range swStatus.ApplicationStatus {
		fmt.Printf("SwStatus Name %s state %v activated %v\n",
			s.Name, s.State, s.Activated)
	}

	if err := deviceDb.Write("sw-status", deviceKey, swStatus); err != nil {
		fmt.Println("deviceDb.Write", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// XXX created vs. updated?
	w.WriteHeader(http.StatusCreated)
}
