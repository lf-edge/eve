// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//This is a test code for testing verifier(image verification)
//This code do all the work which is required to be done on cloud and device.
//we are copying image file,certificates in /var/tmp/zedmanager/downloads directory
//and signing the image
//we are generating a config file which contains image signature,hash,safename,downloadURL
//and certificate names...
//Then we are reading signature,certificate name, image sha from config file
//And finally we are verifying the image signature...
//NOTE:-Make one local directory /var/tmp/go_zededa
//and copy your certificates and image in the respective directories...
//use sudo to execute this program...

package main

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"strings"
)

type VerifierConfig struct {
	Safename         string
	DownloadURL      string
	ImageSha256      string
	CertificateChain []string
	ImageSignature   []byte
	SignatureKey     string
}

var config = VerifierConfig{}
var imgSha string
var safeName string

func main() {

	//Make local directories and copy
	//certificates and images there...

	localBaseDirname := "/var/tmp/go_zededa"
	localCertificateDirname := localBaseDirname + "/certificate"
	localImageDirname := localBaseDirname + "/img"

	if _, err := os.Stat(localBaseDirname); err != nil {
		if err := os.Mkdir(localBaseDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(localCertificateDirname); err != nil {
		if err := os.Mkdir(localCertificateDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := os.Stat(localImageDirname); err != nil {
		if err := os.Mkdir(localImageDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	//Check the required directories are there or not
	//if not  make them first...

	baseDirname := "/var/tmp/zedmanager/downloads"
	imageDirname := baseDirname + "/pending"
	certificateDirname := baseDirname + "/certificate"
	configDirname := baseDirname + "/config"
	rootCertDirname := "/opt/zededa/etc/"
	rootCertFileName := rootCertDirname + "/root-certificate.pem"

	if _, err := os.Stat(baseDirname); err != nil {
		if err := os.Mkdir(baseDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(imageDirname); err != nil {
		if err := os.Mkdir(imageDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := os.Stat(configDirname); err != nil {
		if err := os.Mkdir(configDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}

	//This code will be used in cloud
	//Make basic config file with given params
	//like downloadURL,certificate name
	//Later when we will calculate sha and signature
	//then this config file will be updated

	//read disk image from local file and compute sha256 of the image...
	diskImage, err := os.ReadFile(localImageDirname + "/cirros-0.3.5-x86_64-disk.img")

	//diskImage, err := os.ReadFile("/var/tmp/zedmanager/downloads/verified/e137062a4dfbb4c225971b67781bc52183d14517170e16a3841d16f962ae7470/http:__download.cirros-cloud.net_0.3.5_cirros-0.3.5-x86_64-disk.img.e137062a4dfbb4c225971b67781bc52183d14517170e16a3841d16f962ae7470")
	if err != nil {
		fmt.Println(err)
	}

	hasher := sha256.New()
	hasher.Write(diskImage)
	signhash := hasher.Sum(nil)
	imgSha = fmt.Sprintf("%x", signhash)

	//read server private key...
	var serverPrivateKey []byte
	if _, err := os.Stat(localCertificateDirname + "/server.key.pem"); err != nil {

		if err != nil {
			fmt.Println("err: ", err)
		}
		serverPrivateKey, err = os.ReadFile(localBaseDirname + "/server_private_key")
		if err != nil {
			fmt.Println(err)
		}

	} else {
		serverPrivateKey, err = os.ReadFile(localCertificateDirname + "/server.key.pem")
		err = os.WriteFile(localBaseDirname+"/server_private_key", serverPrivateKey, 0644)
		if err != nil {
			fmt.Println(err)
		}
	}

	//decode and parse the serverPrivate key
	//so that we can use it for signing...
	block, _ := pem.Decode(serverPrivateKey)
	if block == nil {
		panic("failed to decode serverPrivateKey block containing the private key")
	}
	privatekey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic("failed to parse the private key: " + err.Error())
	}

	//sign the hash of image with the private key of server...
	signature, err := rsa.SignPKCS1v15(rand.Reader, privatekey, crypto.SHA256, signhash)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println("Image signature: ",signature)

	//update the config file with image hash and signature...

	config.ImageSha256 = imgSha
	config.ImageSignature = signature

	UpdateConfigFile(config, configDirname)

	EndConfigFileCreation(configDirname)

	//copy the image file from
	//local directory to/var/tmp/zedmanager/downloads/pending...

	source := localImageDirname + "/cirros-0.3.5-x86_64-disk.img"
	destinationDir := imageDirname + "/" + imgSha
	destinationFile := destinationDir + "/" + safeName

	if _, err := os.Stat(destinationDir); err != nil {
		if err := os.Mkdir(destinationDir, 0700); err != nil {
			log.Fatal(err)
		}
	}

	in, err := os.Open(source)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(destinationFile)
	if err != nil {
		return
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return
	} else {
		//fmt.Println("file copied...")
	}

	//copy whole certificate file from local directory
	//to /var/zedmanager/downloads/certificate

	if _, err := os.Stat(certificateDirname); err != nil {

		err = os.Rename(localCertificateDirname, certificateDirname)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	InvokeDeviceCodeForVerification(configDirname, imageDirname, certificateDirname, rootCertFileName, signature)
}
func EndConfigFileCreation(configDirname string) {

	var certChain = []string{"intermediate.cert.pem"}
	var sigKey = "server.cert.pem"
	var downloadURL = "http://download.cirros-cloud.net/0.3.5/cirros-0.3.5-x86_64-disk.img"

	fmt.Println("imgSha: ", imgSha)
	safeName = urlToSafename(downloadURL, imgSha)
	config.Safename = safeName
	config.DownloadURL = downloadURL
	config.CertificateChain = certChain
	config.SignatureKey = sigKey
	//fmt.Println("config: " ,config)
	UpdateConfigFile(config, configDirname)

}

func UpdateConfigFile(config VerifierConfig, configDirname string) {

	b, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err, "json Marshal VerifyImageStatus")
	}
	//fmt.Println(b)

	err = os.WriteFile(configDirname+"/testCf.json", b, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func urlToSafename(url string, sha string) string {
	safename := strings.Replace(url, "/", "_", -1) + "." + sha
	return safename
}
func InvokeDeviceCodeForVerification(configDirname, imageDirname, certificateDirname, rootCertFileName string, signature []byte) {
	configFile := configDirname + "/testCf.json"
	cb, err := os.ReadFile(configFile)
	if err != nil {
		log.Printf("%s for %s\n", err, configFile)
	}
	var config = VerifierConfig{}
	if err := json.Unmarshal(cb, &config); err != nil {
		log.Printf("%s VerifyImageConfig file: %s\n", err, configFile)
	}

	//Read the server certificate
	//Decode it and parse it
	//And find out the puplic key and it's type
	//we will use this certificate for both cert chain verification
	//and signature verification...

	serverCertName := config.SignatureKey
	serverCertificate, err := os.ReadFile(certificateDirname + "/" + serverCertName)
	if err != nil {
		fmt.Println(err)
	}
	block, _ := pem.Decode(serverCertificate)
	if block == nil {
		panic("failed to decode serverCertificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	//Verify chain of certificates. Chain contains
	//root, server, intermediate certificates ...

	certificateNameInChain := config.CertificateChain

	//Create the set of root certificates...
	roots := x509.NewCertPool()

	//read the root cerificates from /usr/local/etc/zededa...
	rootCertificate, err := os.ReadFile(rootCertFileName)
	if err != nil {
		fmt.Println(err)
	}
	ok := roots.AppendCertsFromPEM(rootCertificate)
	if !ok {
		panic("failed to parse root certificate")
	}

	length := len(certificateNameInChain)
	fmt.Println("length: ", length)
	for c := 0; c < length; c++ {

		fmt.Println(certificateNameInChain[c])
		certNameFromChain, err := os.ReadFile(certificateDirname + "/" + certificateNameInChain[c])
		if err != nil {
			fmt.Println(err)
		}

		ok := roots.AppendCertsFromPEM(certNameFromChain)
		if !ok {
			panic("failed to parse root certificate")
		}
	}
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := cert.Verify(opts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	} else {
		fmt.Println("certificate verified")
	}

	//read disk image from zedmanager/downloads/pending directory
	//and compute sha256 of the image...

	destinationImgDir := imageDirname + "/" + imgSha + "/" + safeName
	diskImg, err := os.ReadFile(destinationImgDir)

	//diskImage, err := os.ReadFile("/var/tmp/zedmanager/downloads/verified/e137062a4dfbb4c225971b67781bc52183d14517170e16a3841d16f962ae7470/http:__download.cirros-cloud.net_0.3.5_cirros-0.3.5-x86_64-disk.img.e137062a4dfbb4c225971b67781bc52183d14517170e16a3841d16f962ae7470")
	if err != nil {
		fmt.Println(err)
	}

	hashe256 := sha256.New()
	hashe256.Write(diskImg)
	imageHash := hashe256.Sum(nil)
	imgSha256 := fmt.Sprintf("%x", imageHash)
	fmt.Println("imgSha256: ", imgSha256)

	//Read the signature from directory for now...later we will read it from config file...

	imgSig := config.ImageSignature
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println("signature after reading from config file: ",imgSig)

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:

		err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, imageHash, imgSig)
		if err != nil {
			fmt.Println("VerifyPKCS1v15 failed...")
		} else {
			fmt.Println("VerifyPKCS1v15 successful...")
		}

	case *dsa.PublicKey:

		fmt.Println("pub is of type DSA: ", pub)

	case *ecdsa.PublicKey:

		fmt.Println("pub is of type ecdsa: ", pub)
		imgSignature, err := base64.StdEncoding.DecodeString(string(imgSig))
		if err != nil {
			fmt.Println("DecodeString: ", err)
		}
		fmt.Printf("Decoded imgSignature (len %d): % x\n", len(imgSignature), imgSignature)
		rbytes := imgSignature[0:32]
		sbytes := imgSignature[32:]
		fmt.Printf("Decoded r %d s %d\n", len(rbytes), len(sbytes))
		r := new(big.Int)
		s := new(big.Int)
		r.SetBytes(rbytes)
		s.SetBytes(sbytes)
		fmt.Printf("Decoded r, s: %v, %v\n", r, s)
		ok := ecdsa.Verify(pub, imageHash, r, s)
		if !ok {
			fmt.Printf("ecdsa.Verify failed")
		}
		fmt.Printf("Signature verified\n")

	default:
		panic("unknown type of public key")
	}
}
