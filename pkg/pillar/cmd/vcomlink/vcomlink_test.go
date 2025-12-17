// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vcomlink

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/legacy/tpm2/credactivation"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/evetpm"
	vcom "github.com/lf-edge/eve/pkg/pillar/vcom/go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

const (
	address  = "127.0.0.1"
	port     = 9191
	waitTime = 1000 * time.Second
)

// vsock can be enabled by loading the vsock and vsock_loopback modules :
// $ cat /boot/config-$(uname -r) | grep CONFIG_VSOCKETS
// CONFIG_VSOCKETS=m
// CONFIG_VSOCKETS_DIAG=m
// CONFIG_VSOCKETS_LOOPBACK=m
// $ sudo modprobe vsock
// $ sudo modprobe vsock_loopback
// To test this locally then do:
// $ cd eve/tests/tpm
// $ ./prep-and-run.sh
// in another terminal window do:
// $ go test -c ../../../pkg/pillar/cmd/vcomlink
// $ go test -v -run TestValidGetPublic github.com/lf-edge/eve/pkg/pillar/cmd/vcomlink

func isVsockSupported() bool {
	_, err := os.Stat("/sys/module/vsock")
	return err == nil
}

func isVsockLoopbackSupported() bool {
	_, err := os.Stat("/sys/module/vsock_loopback")
	return err == nil
}

func tcpListener() (net.Listener, error) {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP socket: %v", err)
	}

	// Don't wait for TIME_WAIT sockets to be released.
	if err := unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return nil, fmt.Errorf("setsockopt SO_REUSEADDR error: %v", err)
	}
	if err := unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		return nil, fmt.Errorf("setsockopt SO_REUSEPORT error: %v", err)
	}

	addr := unix.SockaddrInet4{
		Port: port,
	}
	if err := unix.Bind(sock, &addr); err != nil {
		unix.Close(sock)
		return nil, fmt.Errorf("failed to bind TCP socket: %v", err)
	}
	if err := unix.Listen(sock, unix.SOMAXCONN); err != nil {
		unix.Close(sock)
		return nil, fmt.Errorf("failed to listen on TCP socket: %v", err)
	}

	f, err := net.FileListener(os.NewFile(uintptr(sock), fmt.Sprintf("eve_vsock_%d_listener", addr.Port)))
	if err != nil {
		unix.Close(sock)
		return nil, fmt.Errorf("failed to create file net listener: %v", err)
	}

	return f, nil
}

func tcpDial() (net.Conn, error) {
	ip := net.ParseIP(address).To4()
	if ip == nil {
		return nil, fmt.Errorf("Invalid IP address: %s", address)
	}
	addr := unix.SockaddrInet4{
		Port: port,
		Addr: [4]byte(ip),
	}
	sockfd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("Error creating socket: %v", err)
	}
	err = unix.Connect(sockfd, &addr)
	if err != nil {
		unix.Close(sockfd)
		return nil, fmt.Errorf("Error connecting to server: %v", err)
	}

	f, err := net.FileConn(os.NewFile(uintptr(sockfd), "tcp_dial"))
	if err != nil {
		unix.Close(sockfd)
		return nil, fmt.Errorf("Error creating file connection: %v", err)
	}

	return f, nil
}

func vsockDial(cid, port uint32) (net.Conn, error) {
	addr := unix.SockaddrVM{
		CID:  cid,
		Port: port,
	}

	sockfd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("error creating VSOCK socket: %v", err)
	}
	err = unix.Connect(sockfd, &addr)
	if err != nil {
		unix.Close(sockfd)
		return nil, fmt.Errorf("error connecting to VSOCK server: %v", err)
	}

	return &VSOCKConn{fd: sockfd}, nil
}

func vsockClientTCPTransport() *http.Transport {
	return &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return tcpDial() // Use tcpDial as the connection handler
		},
	}
}

func vsockClientVsockTransport() *http.Transport {
	return &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return vsockDial(unix.VMADDR_CID_LOCAL, hostVPort) // Use vsockDial as the connection handler
		},
	}
}

func getClient() *http.Client {
	if isVsockSupported() && isVsockLoopbackSupported() {
		return &http.Client{
			Transport: vsockClientVsockTransport(),
			Timeout:   waitTime,
		}
	}
	return &http.Client{
		Transport: vsockClientTCPTransport(),
		Timeout:   waitTime,
	}
}

func TestMain(m *testing.M) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "vcomlink_test", os.Getpid())

	if !evetpm.SimTpmAvailable() {
		fmt.Println("TPM not available, skipping test")
		os.Exit(0)
	}

	// make sure TPM is prepare it before running the test.
	err := evetpm.SimTpmWaitForTpmReadyState()
	if err != nil {
		fmt.Printf("Failed to wait for TPM ready state: %v", err)
		os.Exit(1)
	}

	// use sim tpm for testing
	tpmDevicePath = evetpm.SimTpmPath

	// set vsock addr to loopback
	cidAddr = unix.VMADDR_CID_LOCAL
	if isVsockSupported() && isVsockLoopbackSupported() {
		log.Noticeln("VSOCK is supported, using VSOCK transport")
		go startVcomServer(vsockNetListener)
	} else {
		log.Noticeln("VSOCK is not supported, using TCP transport")
		go startVcomServer(tcpListener)
	}
	time.Sleep(2 * time.Second)

	res := m.Run()
	os.Exit(res)
}

func TestValidGetPublic(t *testing.T) {
	request := vcom.TpmRequestGetPub{
		Index: uint32(vcom.TpmEKHandle),
	}
	out, err := proto.Marshal(&request)
	if err != nil {
		t.Fatalf("error when marshalling request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://vsock/tpm/getpub", bytes.NewBuffer(out))
	if err != nil {
		t.Fatalf("error when creating request: %v", err)
	}
	resp, err := getClient().Do(req)
	if err != nil {
		t.Fatalf("error when sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("error when reading response body: %v", err)
	}
	var tpmResp vcom.TpmResponseGetPub
	err = proto.Unmarshal(body, &tpmResp)
	if err != nil {
		t.Fatalf("error when unmarshalling response body: %v", err)
	}

	if len(tpmResp.Public) == 0 {
		t.Fatalf("expected non-empty EK, got empty string")
	}

	alg := tpm2.Algorithm(tpmResp.Algorithm)

	fmt.Printf("TPM EK: %x...\n", tpmResp.Public[:16])
	fmt.Printf("TPM EK Algorithm: %s\n", alg.String())
	fmt.Printf("TPM EK Attributes: %s\n", decodeKeyAttr(tpmResp.Attributes))
}

func TestValidGetEkCert(t *testing.T) {
	getOwnerCred = func() (string, error) {
		return "", nil
	}

	request := vcom.TpmRequestReadNv{
		Index: vcom.TpmEKCertHandle,
	}
	out, err := proto.Marshal(&request)
	if err != nil {
		t.Fatalf("error when marshalling request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://vsock/tpm/readnv", bytes.NewBuffer(out))
	if err != nil {
		t.Fatalf("error when creating request: %v", err)
	}
	resp, err := getClient().Do(req)
	if err != nil {
		t.Fatalf("error when sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("error when reading response body: %v", err)
	}
	var tpmResp vcom.TpmResponseReadNv
	err = proto.Unmarshal(body, &tpmResp)
	if err != nil {
		t.Fatalf("error when unmarshalling response body: %v", err)
	}

	if len(tpmResp.Data) == 0 {
		t.Fatalf("expected non-empty EK cert, got empty")
	}

	cert, err := x509.ParseCertificate(tpmResp.Data)
	if err != nil {
		t.Fatalf("failed to parse EK cert: %v", err)
	}

	fmt.Printf("TPM EK cert issuer: %s\n", cert.Issuer)
	fmt.Printf("TPM EK URL: %s\n", cert.IssuingCertificateURL)

	for _, url := range cert.IssuingCertificateURL {
		fmt.Printf("Downloading issuing CA cert from URL: %s\n", url)

		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("failed to download issuing CA cert: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("failed to download issuing CA cert, status code: %d", resp.StatusCode)
		}

		caCertData, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("failed to read issuing CA cert response body: %v", err)
		}

		caCert, err := x509.ParseCertificate(caCertData)
		if err != nil {
			t.Fatalf("failed to parse issuing CA cert: %v", err)
		}

		// This is hacky, in real world we might want to form a cert chain
		if err := cert.CheckSignatureFrom(caCert); err != nil {
			fmt.Printf("failed to verify EK cert against issuing CA cert: %v", err)
		} else {
			fmt.Println("EK cert verified successfully against issuing CA cert")
		}
	}
}

func TestValidSigner(t *testing.T) {
	getOwnerCred = func() (string, error) {
		return "", nil
	}

	// get the key public key first
	pubRequest := vcom.TpmRequestGetPub{
		Index: uint32(vcom.TpmAIKHandle),
	}
	out, err := proto.Marshal(&pubRequest)
	if err != nil {
		t.Fatalf("error when marshalling request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://vsock/tpm/getpub", bytes.NewBuffer(out))
	if err != nil {
		t.Fatalf("error when creating request: %v", err)
	}
	pubResp, err := getClient().Do(req)
	if err != nil {
		t.Fatalf("error when sending request: %v", err)
	}
	defer pubResp.Body.Close()

	if pubResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", pubResp.StatusCode)
	}
	body, err := io.ReadAll(pubResp.Body)
	if err != nil {
		t.Fatalf("error when reading response body: %v", err)
	}
	var tpmRespPub vcom.TpmResponseGetPub
	err = proto.Unmarshal(body, &tpmRespPub)
	if err != nil {
		t.Fatalf("error when unmarshalling response body: %v", err)
	}

	dataToSign := []byte("test data")
	signRequest := vcom.TpmRequestSign{
		Index: uint32(vcom.TpmAIKHandle),
		Data:  dataToSign,
	}
	out, err = proto.Marshal(&signRequest)
	if err != nil {
		t.Fatalf("error when marshalling request: %v", err)
	}
	req, err = http.NewRequest(http.MethodPost, "http://vsock/tpm/sign", bytes.NewBuffer(out))
	if err != nil {
		t.Fatalf("error when creating request: %v", err)
	}
	signResp, err := getClient().Do(req)
	if err != nil {
		t.Fatalf("error when sending request: %v", err)
	}
	defer signResp.Body.Close()

	if signResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", signResp.StatusCode)
	}

	body, err = io.ReadAll(signResp.Body)
	if err != nil {
		t.Fatalf("error when reading response body: %v", err)
	}
	var tpmRespSign vcom.TpmResponseSign
	err = proto.Unmarshal(body, &tpmRespSign)
	if err != nil {
		t.Fatalf("error when unmarshalling response body: %v", err)
	}

	// get data digest for verification
	dataHash := crypto.SHA256.New()
	dataHash.Write(dataToSign)
	dataDigest := dataHash.Sum(nil)

	// decode the TPM wire format to crypto.PublicKey
	signer, err := tpm2.DecodePublic(tpmRespPub.Public)
	if err != nil {
		t.Fatalf("failed to decode public key: %v", err)
	}
	signerPub, err := signer.Key()
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}

	// check the signature if RSA
	if tpmRespSign.RsaSignature != nil {
		sinerPub := signerPub.(*rsa.PublicKey)
		err = rsa.VerifyPKCS1v15(sinerPub, crypto.SHA256, dataDigest[:], tpmRespSign.RsaSignature)
		if err != nil {
			t.Fatalf("failed to verify signature: %v", err)
		}

		fmt.Printf("Signature verified successfully using RSA public key\n")
	}

	// check the signature if ECDA
	if tpmRespSign.EccSignatureR != nil && tpmRespSign.EccSignatureS != nil {
		sinerPub := signerPub.(*ecdsa.PublicKey)
		EccSignatureR := new(big.Int).SetBytes(tpmRespSign.EccSignatureR)
		EccSignatureS := new(big.Int).SetBytes(tpmRespSign.EccSignatureS)
		if !ecdsa.Verify(sinerPub, dataDigest, EccSignatureR, EccSignatureS) {
			t.Fatalf("failed to verify signature")
		}

		fmt.Printf("Signature verified successfully using ECDSA public key\n")
	}
}

func TestValidActivateCred(t *testing.T) {
	getOwnerCred = func() (string, error) {
		return "", nil
	}

	paramsRequest := vcom.TpmRequestActivateCredParams{
		Index: uint32(vcom.TpmAIKHandle),
	}
	out, err := proto.Marshal(&paramsRequest)
	if err != nil {
		t.Fatalf("error when marshalling request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://vsock/tpm/activatecredparams", bytes.NewBuffer(out))
	if err != nil {
		t.Fatalf("error when creating request: %v", err)
	}
	signResp, err := getClient().Do(req)
	if err != nil {
		t.Fatalf("error when sending request: %v", err)
	}
	defer signResp.Body.Close()

	if signResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", signResp.StatusCode)
	}

	body, err := io.ReadAll(signResp.Body)
	if err != nil {
		t.Fatalf("error when reading response body: %v", err)
	}
	var tpmRespACParams vcom.TpmResponseActivateCredParams
	err = proto.Unmarshal(body, &tpmRespACParams)
	if err != nil {
		t.Fatalf("error when unmarshalling response body: %v", err)
	}

	// decode back EK pub to a format we can work with
	ekPub, err := tpm2.DecodePublic(tpmRespACParams.Ek)
	if err != nil {
		t.Fatalf("failed to decode EK public key: %v", err)
	}

	// decode back AIK name to a format we can work with
	name, err := tpm2.DecodeName(bytes.NewBuffer(tpmRespACParams.AikName))
	if err != nil {
		t.Fatalf("failed to decode AIK name: %v", err)
	}
	aikPub, err := tpm2.DecodePublic(tpmRespACParams.AikPub)
	if err != nil {
		t.Fatalf("failed to decode AIK public key: %v", err)
	}

	// Verify the name matches the AIK
	nameHash, err := name.Digest.Alg.Hash()
	if err != nil {
		t.Fatalf("failed to get AIK hash algorithm: %v", err)
	}
	p, err := aikPub.Encode()
	if err != nil {
		t.Fatalf("failed to encode AIK public key: %v", err)
	}
	aikPubHash := nameHash.New()
	aikPubHash.Write(p)
	aikPubDigest := aikPubHash.Sum(nil)
	if !bytes.Equal(name.Digest.Value, aikPubDigest) {
		t.Fatalf("AIK name does not match AIK public key")
	}

	// Verify the AIK is a restricted signing key
	if (aikPub.Attributes&tpm2.FlagFixedTPM) != tpm2.FlagFixedTPM ||
		(aikPub.Attributes&tpm2.FlagRestricted) != tpm2.FlagRestricted ||
		(aikPub.Attributes&tpm2.FlagFixedParent) != tpm2.FlagFixedParent ||
		(aikPub.Attributes&tpm2.FlagSensitiveDataOrigin) != tpm2.FlagSensitiveDataOrigin {
		t.Fatalf("AIK is not a restricted signing key")
	}

	// Generate a credential
	credential := make([]byte, 32)
	rand.Read(credential)
	encKey, err := ekPub.Key()
	if err != nil {
		t.Fatalf("failed to get EK key: %v", err)
	}
	symBlockSize := int(ekPub.RSAParameters.Symmetric.KeyBits) / 8
	credBlob, encryptedSecret, err := credactivation.Generate(name.Digest, encKey, symBlockSize, credential)
	if err != nil {
		t.Fatalf("failed to generate credential: %v", err)
	}

	// send the to activate the credential
	credGen := vcom.TpmRequestGeneratedCred{
		Cred:     credBlob,
		Secret:   encryptedSecret,
		AikIndex: uint32(vcom.TpmAIKHandle),
	}
	out, err = proto.Marshal(&credGen)
	if err != nil {
		t.Fatalf("error when marshalling request: %v", err)
	}
	req, err = http.NewRequest(http.MethodPost, "http://vsock/tpm/activatecred", bytes.NewBuffer(out))
	if err != nil {
		t.Fatalf("error when creating request: %v", err)
	}
	credResp, err := getClient().Do(req)
	if err != nil {
		t.Fatalf("error when sending request: %v", err)
	}
	defer credResp.Body.Close()

	if credResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", credResp.StatusCode)
	}

	body, err = io.ReadAll(credResp.Body)
	if err != nil {
		t.Fatalf("error when reading response body: %v", err)
	}
	var tpmResp vcom.TpmResponseActivatedCred
	err = proto.Unmarshal(body, &tpmResp)
	if err != nil {
		t.Fatalf("error when unmarshalling response body: %v", err)
	}

	if !bytes.Equal(credential, tpmResp.Secret) {
		t.Fatalf("failed to verify the secret")
	}

	fmt.Printf("%-21s %x\n", "Credential:", credential)
	fmt.Printf("%-21s %x\n", "Recovered credential:", tpmResp.Secret)
	fmt.Printf("Credential activation successful, we can trust the AIK\n")
}

func TestValidCertifyKey(t *testing.T) {
	getOwnerCred = func() (string, error) {
		return "", nil
	}

	// get AIK public key
	pubRequest := vcom.TpmRequestGetPub{
		Index: uint32(vcom.TpmAIKHandle),
	}
	out, err := proto.Marshal(&pubRequest)
	if err != nil {
		t.Fatalf("error when marshalling request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://vsock/tpm/getpub", bytes.NewBuffer(out))
	if err != nil {
		t.Fatalf("error when creating request: %v", err)
	}
	pubResp, err := getClient().Do(req)
	if err != nil {
		t.Fatalf("error when sending request: %v", err)
	}
	defer pubResp.Body.Close()

	if pubResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", pubResp.StatusCode)
	}

	body, err := io.ReadAll(pubResp.Body)
	if err != nil {
		t.Fatalf("error when reading response body: %v", err)
	}
	var tpmPubResp vcom.TpmResponseGetPub
	err = proto.Unmarshal(body, &tpmPubResp)
	if err != nil {
		t.Fatalf("error when unmarshalling response body: %v", err)
	}
	if len(tpmPubResp.Public) == 0 {
		t.Fatalf("expected non-empty public key, got empty string")
	}

	pub, err := tpm2.DecodePublic(tpmPubResp.Public)
	if err != nil {
		t.Fatalf("failed to decode public key: %v", err)
	}
	pubKey, err := pub.Key()
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}

	request := vcom.TpmRequestCertify{
		Index: uint32(vcom.TpmEcdhHandle),
	}
	out, err = proto.Marshal(&request)
	if err != nil {
		t.Fatalf("error when marshalling request: %v", err)
	}

	req, err = http.NewRequest(http.MethodPost, "http://vsock/tpm/certifykey", bytes.NewBuffer(out))
	if err != nil {
		t.Fatalf("error when creating request: %v", err)
	}
	resp, err := getClient().Do(req)
	if err != nil {
		t.Fatalf("error when sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", resp.StatusCode)
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("error when reading response body: %v", err)
	}
	var tpmResp vcom.TpmResponseCertify
	err = proto.Unmarshal(body, &tpmResp)
	if err != nil {
		t.Fatalf("error when unmarshalling response body: %v", err)
	}

	sigDecoded, err := tpm2.DecodeSignature(bytes.NewBuffer(tpmResp.Sig))
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}

	attestHash := sha256.Sum256(tpmResp.Attest)
	if err := rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), crypto.SHA256, attestHash[:], sigDecoded.RSA.Signature); err != nil {
		t.Fatalf("failed to verify signature: %v", err)
	}

	t.Logf("Successfully certified key with AIK and verified signature.")
}

func decodeKeyAttr(attr uint32) string {
	flags := map[string]int{
		"FlagFixedTPM":            0x00000002,
		"FlagStClear":             0x00000004,
		"FlagFixedParent":         0x00000010,
		"FlagSensitiveDataOrigin": 0x00000020,
		"FlagUserWithAuth":        0x00000040,
		"FlagAdminWithPolicy":     0x00000080,
		"FlagNoDA":                0x00000400,
		"FlagRestricted":          0x00010000,
		"FlagDecrypt":             0x00020000,
		"FlagSign":                0x00040000,
	}

	attrStr := make([]string, 0)
	for k, v := range flags {
		if attr&uint32(v) != 0 {
			attrStr = append(attrStr, k)
		}
	}

	if len(attrStr) == 0 {
		return "NO ATTRIBUTES"
	}

	if len(attrStr) == 1 {
		return attrStr[0]
	}

	return strings.Join(attrStr, " | ")
}
