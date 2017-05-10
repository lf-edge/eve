// Call as register <username> <cert pem filename> [<maxCount>]
// Record the username and pem file in the ProvisioningCert database

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/nanobox-io/golang-scribble"
	"github.com/zededa/go-provision/types"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"time"
)

func main() {
	args := os.Args[1:]
	if len(args) < 2 || len(args) > 3 {
		log.Fatal("Usage: " + os.Args[0] + " <userName> <certFile> [N]")
	}
	userName := args[0]
	certFile := args[1]
	maxCount := 1
	if len(args) > 2 {
		count, err := strconv.Atoi(args[2])
		if err != nil {
			log.Fatal(err)
		}
		maxCount = count
	}
	certBuf, err := ioutil.ReadFile(certFile)
	if err != nil {
		log.Fatal("ReadFile ", err)
	}
	// Want the sha256 sum of the DER of the private key as the name
	block, _ := pem.Decode(certBuf)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatal("failed to decode PEM block containing certificate. Type " +
			block.Type)
	}
	hasher := sha256.New()
	hasher.Write(block.Bytes)
	provKey := base64.StdEncoding.EncodeToString(hasher.Sum(nil))
	fmt.Println("provKey:", provKey)

	// a new or existing scribble driver, providing the directory
	// where it will be writing to, and a qualified logger if desired
	db, err := scribble.New("/var/tmp/zededa-prov", nil)
	if err != nil {
		fmt.Println("scribble.New", err)
	}

	// Add the ProvisioningCert to the database
	err = db.Write("prov", provKey,
		types.ProvisioningCert{Cert: certBuf, UserName: userName,
			RegTime: time.Now(), RemainingUse: maxCount})
	if err != nil {
		fmt.Println("db.Write", err)
	}
}
