package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/sha256"
        "encoding/pem"
        "encoding/base64"
	"encoding/json"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"time"
	"github.com/nanobox-io/golang-scribble"
        "github.com/zededa/go-provision/types"
)

// Assumes the config files are in dirName, which is /etc/zededa-server/
// by default
// The files are
//  intermediate-ca-chain.pem	Intermediate and root CA cert
//  server.cert.pem, server.key.pem	
//
func main() {
	args := os.Args[1:]
	if len(args) >1 {
		log.Fatal("Usage: " + os.Args[0] + "[<dirName>]")
	}
	dirName := "/etc/zededa-server/"
	if len(args) > 0 {
	   dirName = args[0]
	}

	serverCertName := dirName + "/server.cert.pem"
	serverKeyName := dirName + "/server.key.pem"
	rootCertName := dirName + "/intermediate-ca-chain.pem"

	http.HandleFunc("/rest/self-register", SelfRegister)
	http.HandleFunc("/rest/device-param", DeviceParam)

	caCert, err := ioutil.ReadFile(rootCertName)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
		ClientAuth: tls.RequireAnyClientCert,
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
		Addr:      ":8080",
		TLSConfig: tlsConfig,
	}

	err = server.ListenAndServeTLS(serverCertName, serverKeyName)
	if err != nil {
		log.Fatal(err)
	}
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
    fmt.Println("Content-Length", r.Header.Get("Content-Length"))
    fmt.Println("Content-Type", r.Header.Get("Content-Type"))
    contentType := r.Header.Get("Content-Type")
    if contentType != "application/json" {
          fmt.Println("Incorrect Content-Type " + contentType)
	  // XXX which code?
          http.Error(w, http.StatusText(http.StatusLengthRequired),
 	 	       http.StatusLengthRequired)
	  return
    }
    contentLength := r.Header.Get("Content-Length")
    if contentLength == "" {
	  fmt.Println("no Content-Length")
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
	  fmt.Println("Too large Content-Length %d", length)
          http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge),
 	 	       http.StatusRequestEntityTooLarge)
          return
    }
    
    // parsing RegisterCreate json payload
    rc := &types.RegisterCreate{}
    if err := json.NewDecoder(r.Body).Decode(rc); err != nil {
          fmt.Printf("Error decoding body: %s\n", err)
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
    }
    device := types.DeviceDb{}
    err = deviceDb.Read("ddb", deviceKey, &device)
    if err == nil && device.UserName == userName &&
       reflect.DeepEqual(device.DeviceCert, rc.PemCert) {
    	// Re-registering the same key with same value
	fmt.Println("Identical already exists in deviceDb since %s",
			       device.RegTime)
	device.ReRegisteredCount++
	err = deviceDb.Write("ddb", deviceKey, device )
	if err != nil {
	      fmt.Println("deviceDb.Write", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	return
    }
    if err == nil {
	fmt.Println("Different already exists in deviceDb since %s",
			       device.RegTime)
        http.Error(w, http.StatusText(http.StatusConflict),
 		       http.StatusConflict)
	return
    }
    if prov.RemainingUse == 0 {
	  fmt.Printf("Already used. Registered at %s. LastUsed at %s\n",
	  		       prov.RegTime, prov.LastUsedTime)
          http.Error(w, http.StatusText(http.StatusGone),
 	 	       http.StatusGone)
          return
    }
    deviceCert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
         fmt.Println("ParseCerticate", err)
      	 return
    }
    publicDer, err := x509.MarshalPKIXPublicKey(deviceCert.PublicKey)
    if err != nil {
         fmt.Println("MarshalPKIXPublicKey", err)
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
    lispInstance := uint32(1277)  // XXX should come from user's account info

    iidData := make([]byte, 4)
    binary.BigEndian.PutUint32(iidData, lispInstance)

    eidPrefix := []byte{0xFD} // Hard-coded for Zededa management overlay
    eidHashLen := 128 - len(eidPrefix) * 8

    // XXX temporary to get raw
    if true {
        hasher = sha256.New()
        hasher.Write(publicDer)
        sum := hasher.Sum(nil)
        fmt.Printf("RAW SUM: (len %d) % 2x\n", len(sum), sum)
        fmt.Printf("RAW2 SUM: % 2x\n", sha256.Sum256(publicDer))
    }
    hasher = sha256.New()
    fmt.Printf("iidData % x\n", iidData )
    hasher.Write(iidData)
    fmt.Printf("eidPrefix % x\n", eidPrefix )
    hasher.Write(eidPrefix)
    hasher.Write(publicDer)
    sum := hasher.Sum(nil)
    // Truncate to get EidHashLen by taking the first EidHashLen/8 bytes
    // from the left.
    fmt.Printf("SUM: (len %d) % 2x\n", len(sum), sum)
    eid := net.IP(append(eidPrefix, sum...)[0:16])
    fmt.Printf("EID: (len %d) %s\n", len(eid), eid)
    device = types.DeviceDb{
    	   DeviceCert: rc.PemCert,
	   DevicePublicKey: publicPem,
	   UserName: userName,
	   RegTime: time.Now(),
	   LispMapServers: []types.LispServerInfo{
	   		   { "ms1.zededa.net", "test123" },
	   		   { "ms2.zededa.net", "test2345" },
           },
	   LispInstance: lispInstance,
	   EID: eid,
	   EIDHashLen: uint8(eidHashLen),
	   }

    err = deviceDb.Write("ddb", deviceKey, device )
    if err != nil {
      fmt.Println("deviceDb.Write", err)
    }
    
    // Created in deviceDb under userName, so we decrement the remaining uses
    prov.RemainingUse--
    prov.LastUsedTime = time.Now()
    err = db.Write("prov", provKey, prov)
    if err != nil {
      fmt.Println("db.Write", err)
      return
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
     if err := deviceDb.Write("ddb", deviceKey, device ); err != nil {
        fmt.Println("deviceDb.Write", err)
     }
     w.Header().Set("Content-Type", "application/json")
     w.Write(res)

}

