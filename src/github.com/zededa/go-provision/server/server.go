package main

import (
	"bytes"
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
	"strings"
	"time"
)

var zedServerConfig types.ZedServerConfig

type ServerCertInfo struct {
	serverCert                  tls.Certificate
	ocspTimer                   int64 // periodic timer value
	timerBackoff                int64 // initialized to 1
	ocspResponse                *ocsp.Response
	ocspResponseBytes           []byte
	lastOcspUpdate, lastOcspUse time.Time
	t                           *time.Timer
}

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

	localServerCertName := dirName + "/intermediate-prov01.priv.sc.zededa.net.cert.pem"
	localServerKeyName := dirName + "/prov01.priv.sc.zededa.net.key.pem"
	globalServerCertName := dirName + "/intermediate-prov1.zededa.net.cert.pem"
	globalServerKeyName := dirName + "/prov1.zededa.net.key.pem"
	zedServerConfigFileName := dirName + "/zedserverconfig.json"

	http.HandleFunc("/rest/self-register", SelfRegister)
	http.HandleFunc("/rest/device-param", DeviceParam)
	http.HandleFunc("/rest/update-hw-status", UpdateHwStatus)
	http.HandleFunc("/rest/update-sw-status", UpdateSwStatus)
	http.HandleFunc("/rest/eid-register", EIDRegister)

	zcb, err := ioutil.ReadFile(zedServerConfigFileName)
	if err != nil {
		log.Fatal(err)
	}
	zedServerConfig = types.ZedServerConfig{}
	if err := json.Unmarshal(zcb, &zedServerConfig); err != nil {
		log.Fatal("Error decoding ZedServerConfig:\n", err)
	}

	localServerCert, err := tls.LoadX509KeyPair(localServerCertName,
		localServerKeyName)
	if err != nil {
		log.Fatal(err)
	}
	globalServerCert, err := tls.LoadX509KeyPair(globalServerCertName,
		globalServerKeyName)
	if err != nil {
		log.Fatal(err)
	}

	// Handling a local and a global cert for now
	serverCertInfo := make([]ServerCertInfo, 2)
	serverCertInfo[0] = ServerCertInfo{
		serverCert: globalServerCert, timerBackoff: 1}
	serverCertInfo[1] = ServerCertInfo{
		serverCert: localServerCert, timerBackoff: 1}

	getOcsp := func(sci *ServerCertInfo) bool {
		done := false
		response, responseBytes, err :=
			getOcspResponseBytes(&sci.serverCert)
		if err != nil {
			log.Println(err)
			return done
		}
		sci.ocspResponse = response
		sci.ocspResponseBytes = responseBytes
		now := time.Now()
		age := now.Unix() - sci.ocspResponse.ProducedAt.Unix()
		remain := sci.ocspResponse.NextUpdate.Unix() - now.Unix()
		log.Printf("OCSP age %d, remain %d\n", age, remain)
		// Check again after half the remaining time
		sci.ocspTimer = remain / 2
		if sci.ocspResponse.Status == ocsp.Good {
			log.Println("Certificate Status Good.")
			sci.ocspResponse = response
			sci.ocspResponseBytes = responseBytes
			done = true
			sci.lastOcspUpdate = now
		} else if sci.ocspResponse.Status == ocsp.Unknown {
			log.Println("Certificate Status Unknown")
		} else {
			log.Println("Certificate Status Revoked")
		}
		return done
	}

	done := false
	// XXX If ocsp01 is not reachable uncomment next line
	// done = true;
	// serverCertInfo[0].ocspTimer = 60000; serverCertInfo[1].ocspTimer = 60000
	for !done {
		done1 := getOcsp(&serverCertInfo[0])
		done2 := getOcsp(&serverCertInfo[1])
		done = done1 && done2
		if !done {
			time.Sleep(5 * time.Second)
			// XXX prov1.zededa.net points at ocsp.zededa.net which doesn't exist
			// done = true
		}
	}
	log.Printf("Setup global timer every %d seconds; local %d\n",
		serverCertInfo[0].ocspTimer,
		serverCertInfo[1].ocspTimer)

	var periodicOcsp func(sci *ServerCertInfo)
	periodicOcsp = func(sci *ServerCertInfo) {
		if sci.lastOcspUse.Before(sci.lastOcspUpdate) {
			sci.timerBackoff *= 2
			log.Printf("OCSP was not used. Backoff %d\n",
				sci.timerBackoff)
		}
		// If we get an updated success, then we use that for subsequent
		// stapling
		if done := getOcsp(sci); done {
			// Have an updated response to staple
			log.Printf("Got OCSP update\n")
		}
		sci.t = time.AfterFunc(
			time.Duration(sci.timerBackoff*sci.ocspTimer)*
				time.Second, func() { periodicOcsp(sci) })
	}
	// Start the timers
	for _, sci := range serverCertInfo {
		sci.t = time.AfterFunc(
			time.Duration(sci.timerBackoff*sci.ocspTimer)*
				time.Second, func() { periodicOcsp(&sci) })
		defer sci.t.Stop()
	}

	getCertificate := func(hello *tls.ClientHelloInfo) (*tls.Certificate,
		error) {
		fmt.Printf("getCertificate server %s local %v remote %v\n",
			hello.ServerName,
			hello.Conn.LocalAddr(), hello.Conn.RemoteAddr())
		var sci *ServerCertInfo
		if strings.Contains(hello.ServerName, ".priv.") {
			sci = &serverCertInfo[1]
		} else {
			sci = &serverCertInfo[0]
		}
		cert := sci.serverCert
		now := time.Now()
		sci.lastOcspUse = now
		// In case we didn't require a response on startup
		if sci.ocspResponseBytes == nil {
			return &cert, nil
		}
		// We staple the cert we have even if it is not Good
		age := now.Unix() - sci.ocspResponse.ProducedAt.Unix()
		remain := sci.ocspResponse.NextUpdate.Unix() - now.Unix()
		log.Printf("OCSP status %v, age %d, remain %d\n",
			sci.ocspResponse.Status, age, remain)
		if remain < 0 {
			// Force update now. Reset timerBackoff.
			log.Println("OCSP expired - force update.")
			if getOcsp(sci) {
				// Have an updated response to staple
			}
			sci.timerBackoff = 1
			sci.t = time.AfterFunc(
				time.Duration(sci.timerBackoff*sci.ocspTimer)*
					time.Second, func() { periodicOcsp(sci) })
		}
		cert.OCSPStaple = sci.ocspResponseBytes
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

	err = server.ListenAndServeTLS("", "")
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
	fmt.Printf("Connecting to OCSP at %s for %v\n",
		ocspServer, x509Cert.Subject)
	ocspRequestReader := bytes.NewReader(ocspRequest)
	resp, err := http.Post(ocspServer, "application/ocsp-request",
		ocspRequestReader)
	if err != nil {
		log.Println("http.Post ocsp", err)
		return nil, nil, err
	}
	defer resp.Body.Close()
	fmt.Printf("HTTP resp code %d %s\n",
		resp.StatusCode, http.StatusText(resp.StatusCode))
	if resp.StatusCode != http.StatusOK {
		log.Println("OCSP response code: ", resp.StatusCode)
		return nil, nil, errors.New("OCSP get failed: " +
			http.StatusText(resp.StatusCode))
	}
	ocspResponseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("getOcspResponseBytes ReadAll", err)
		return nil, nil, err
	}
	ocspResponse, err := ocsp.ParseResponse(ocspResponseBytes, x509Issuer)
	if err != nil {
		log.Println("ocsp.ParseResponse", err)
		return nil, nil, err
	}
	return ocspResponse, ocspResponseBytes, err
}

func SelfRegister(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Method %s Host %s Proto %s URL %s from %v\n",
		r.Method, r.Host, r.Proto, r.URL, r.RemoteAddr)
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed),
			http.StatusMethodNotAllowed)
		return
	}
	cert := r.TLS.PeerCertificates[0]
	// Validating it is self-signed
	if !cert.IsCA || !reflect.DeepEqual(cert.Issuer, cert.Subject) {
		errStr := fmt.Sprintf("onboardingCert not self-signed: Issuer %s, Subject %s, IsCa %s\n",
			cert.Issuer, cert.Subject, cert.IsCA)
		log.Println(errStr)
		http.Error(w, errStr, http.StatusUnauthorized)
		return
	}
	// validate it has not expired
	now := time.Now()
	if now.After(cert.NotAfter) {
		errStr := fmt.Sprintf("onboardingCert expired NotAfter %s, now %s\n",
			cert.NotAfter, now.UTC())
		log.Println(errStr)
		http.Error(w, errStr, http.StatusUnauthorized)
		return
	}
	if now.Before(cert.NotBefore) {
		errStr := fmt.Sprintf("onboardingCert too early NotBefore %s, now %s\n",
			cert.NotBefore, now.UTC())
		log.Println(errStr)
		http.Error(w, errStr, http.StatusUnauthorized)
		return
	}

	hasher := sha256.New()
	hasher.Write(cert.Raw)
	onboardingKey := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	fmt.Println("onboardingKey:", onboardingKey)

	// Look up in database
	// XXX create db and deviceDb and put in global vars!
	// a new or existing scribble driver, providing the directory
	// where it will be writing to, and a qualified logger if desired
	db, err := scribble.New("/var/tmp/zededa-onboarding", nil)
	if err != nil {
		fmt.Println("scribble.New", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	onboarding := types.OnboardingCert{}
	if err := db.Read("onboarding", onboardingKey, &onboarding); err != nil {
		fmt.Println("db.Read", err)
		http.Error(w, http.StatusText(http.StatusNotFound),
			http.StatusNotFound)
		return
	}
	userName := onboarding.UserName
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
				device.ClientAddr = r.RemoteAddr
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
	if onboarding.RemainingUse == 0 {
		fmt.Printf("onboardingCert already used. Registered at %s. LastUsed at %s\n",
			onboarding.RegTime, onboarding.LastUsedTime)
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

	// XXX need to pass this prefix to device. Use it to setup route to dbo1x0
	// XXX note that fd00::/8 route is used for all overlays. Might be
	// ok if we just add the global address route. XXX refcnt in zedrouter
	// XXX Also eidAllocationPrefixLen to allow arbitrary bit length
	// XXX need different value for AWS
	eidAllocationPrefix := []byte{0xFD} // Hard-coded for Zededa management overlay
	eidAllocationPrefixLen := len(eidAllocationPrefix)*8
	eidHashLen := 128 - eidAllocationPrefixLen

	hasher = sha256.New()
	fmt.Printf("iidData % x\n", iidData)
	hasher.Write(iidData)
	fmt.Printf("eidAllocationPrefix % x\n", eidAllocationPrefix)
	hasher.Write(eidAllocationPrefix)
	hasher.Write(publicDer)
	sum = hasher.Sum(nil)
	fmt.Printf("SUM: (len %d) % 2x\n", len(sum), sum)
	// Truncate to get EidHashLen by taking the first EidHashLen/8 bytes
	// from the left.
	eid := net.IP(append(eidAllocationPrefix, sum...)[0:16])
	fmt.Printf("EID: (len %d) %s\n", len(eid), eid)
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
		EidAllocationPrefix: eidAllocationPrefix,
		EidAllocationPrefixLen: eidAllocationPrefixLen, // XXX client and zedrouter.
		ClientAddr:   r.RemoteAddr,
	}
	err = deviceDb.Write("ddb", deviceKey, device)
	if err != nil {
		fmt.Println("deviceDb.Write", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}

	// Created in deviceDb under userName, so we decrement the remaining uses
	onboarding.RemainingUse--
	onboarding.LastUsedTime = time.Now()
	err = db.Write("onboarding", onboardingKey, onboarding)
	if err != nil {
		fmt.Println("db.Write", err)
		// Note we ignore error and RemainingUse is not updated; but we did
		// registed deviceCert. Alternative is to undo the deviceCert registration
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
}

func DeviceParam(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Method %s Host %s Proto %s URL %s from %v\n",
		r.Method, r.Host, r.Proto, r.URL, r.RemoteAddr)
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
		errStr := fmt.Sprintf("deviceCert not self-signed: Issuer %s, Subject %s, IsCa %s\n",
			cert.Issuer, cert.Subject, cert.IsCA)
		log.Println(errStr)
		http.Error(w, errStr, http.StatusUnauthorized)
		return
	}
	// validate it has not expired
	now := time.Now()
	if now.Before(cert.NotBefore) {
		errStr := fmt.Sprintf("deviceCert too early NotBefore %s, now %s\n",
			cert.NotBefore, now.UTC())
		log.Println(errStr)
		http.Error(w, errStr, http.StatusUnauthorized)
		return
	}
	if now.After(cert.NotAfter) {
		errStr := fmt.Sprintf("deviceCert expired NotAfter %s, now %s\n",
			cert.NotAfter, now.UTC())
		log.Println(errStr)
		http.Error(w, errStr, http.StatusUnauthorized)
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
	// Update ClientAddr since location could have changed; also ZedServers
	device.ClientAddr = r.RemoteAddr
	device.ZedServers = zedServerConfig

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
	fmt.Printf("Method %s Host %s Proto %s URL %s from %v\n",
		r.Method, r.Host, r.Proto, r.URL, r.RemoteAddr)
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
		errStr := fmt.Sprintf("deviceCert not self-signed: Issuer %s, Subject %s, IsCa %s\n",
			cert.Issuer, cert.Subject, cert.IsCA)
		log.Println(errStr)
		http.Error(w, errStr, http.StatusUnauthorized)
		return
	}
	// validate it has not expired
	now := time.Now()
	if now.Before(cert.NotBefore) {
		errStr := fmt.Sprintf("deviceCert too early NotBefore %s, now %s\n",
			cert.NotBefore, now.UTC())
		log.Println(errStr)
		http.Error(w, errStr, http.StatusUnauthorized)
		return
	}
	if now.After(cert.NotAfter) {
		errStr := fmt.Sprintf("deviceCert expired NotAfter %s, now %s\n",
			cert.NotAfter, now.UTC())
		log.Println(errStr)
		http.Error(w, errStr, http.StatusUnauthorized)
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
	fmt.Printf("Method %s Host %s Proto %s URL %s from %v\n",
		r.Method, r.Host, r.Proto, r.URL, r.RemoteAddr)
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
		errStr := fmt.Sprintf("deviceCert not self-signed: Issuer %s, Subject %s, IsCa %s\n",
			cert.Issuer, cert.Subject, cert.IsCA)
		log.Println(errStr)
		http.Error(w, errStr, http.StatusUnauthorized)
		return
	}
	// validate it has not expired
	now := time.Now()
	if now.Before(cert.NotBefore) {
		errStr := fmt.Sprintf("deviceCert too early NotBefore %s, now %s\n",
			cert.NotBefore, now.UTC())
		log.Println(errStr)
		http.Error(w, errStr, http.StatusUnauthorized)
		return
	}
	if now.After(cert.NotAfter) {
		errStr := fmt.Sprintf("deviceCert expired NotAfter %s, now %s\n",
			cert.NotAfter, now.UTC())
		log.Println(errStr)
		http.Error(w, errStr, http.StatusUnauthorized)
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
			s.DisplayName, s.State, s.Activated)
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

func EIDRegister(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Method %s Host %s Proto %s URL %s from %v\n",
		r.Method, r.Host, r.Proto, r.URL, r.RemoteAddr)
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed),
			http.StatusMethodNotAllowed)
		return
	}
	cert := r.TLS.PeerCertificates[0]
	// Validating it is self-signed
	if !cert.IsCA || !reflect.DeepEqual(cert.Issuer, cert.Subject) {
		errStr := fmt.Sprintf("onboardingCert not self-signed: Issuer %s, Subject %s, IsCa %s\n",
			cert.Issuer, cert.Subject, cert.IsCA)
		log.Println(errStr)
		http.Error(w, errStr, http.StatusUnauthorized)
		return
	}
	// validate it has not expired
	now := time.Now()
	if now.After(cert.NotAfter) {
		errStr := fmt.Sprintf("deviceCert expired NotAfter %s, now %s\n",
			cert.NotAfter, now.UTC())
		log.Println(errStr)
		http.Error(w, errStr, http.StatusUnauthorized)
		return
	}
	if now.Before(cert.NotBefore) {
		errStr := fmt.Sprintf("deviceCert too early NotBefore %s, now %s\n",
			cert.NotBefore, now.UTC())
		log.Println(errStr)
		http.Error(w, errStr, http.StatusUnauthorized)
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
	// Check we have a reasonable content-length
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
	// XXX what is the max length of the EIDRegister type?
	if length > 4096 {
		fmt.Printf("Too large Content-Length %d\n", length)
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge),
			http.StatusRequestEntityTooLarge)
		return
	}

	// parsing EIDRegister json payload
	register := &types.EIDRegister{}
	if err := json.NewDecoder(r.Body).Decode(register); err != nil {
		fmt.Printf("Error decoding EIDRegister: %s\n", err)
		http.Error(w, http.StatusText(http.StatusBadRequest),
			http.StatusBadRequest)
		return
	}
	// XXX write to /var/tmp/zededa-device/eid-app/.
	// XXX read first. Should we update? zed-lispcontroller doesn't react
	// to updates. A restart of a device will result in a re-register.
	// XXX compare types?
	// XXX get appKey
	appKey := fmt.Sprintf("%s:%d", register.UUID, register.IID)
	fmt.Println("appKey:", appKey)
	oldRegister := types.EIDRegister{}
	if err = deviceDb.Read("eid-app", appKey, &oldRegister); err == nil {
		// XXX always says not equal. Print comparison of components
		// if !reflect.DeepEqual(register, oldRegister) {
		if !reflect.DeepEqual(register.AppCert, oldRegister.AppCert) ||
		   !reflect.DeepEqual(register.AppPublicKey,
		   	oldRegister.AppPublicKey) ||
		   register.UUID != oldRegister.UUID ||
		   register.IID != oldRegister.IID ||
		   !reflect.DeepEqual(register.EID, oldRegister.EID) ||
		   register.EIDHashLen != oldRegister.EIDHashLen ||
		   !reflect.DeepEqual(register.LispMapServers,
			oldRegister.LispMapServers) {
			log.Printf("EIDRegister changed for key %s\n", appKey)
			http.Error(w, http.StatusText(http.StatusConflict),
				http.StatusConflict)
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
		}
		return
	}
	if err := deviceDb.Write("eid-app", appKey, register); err != nil {
		fmt.Println("deviceDb.Write", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
}
