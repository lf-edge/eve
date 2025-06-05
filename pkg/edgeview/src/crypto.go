// Copyright (c) 2022-2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/gorilla/websocket"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"golang.org/x/crypto/ssh"
)

const hashBytesNum = 32 // Hmac Sha256 Hash is 32 bytes fixed

var (
	nonceOpEncrption bool
	nonceHash        [32]byte         // JWT Nonce with Sha256Sum for encryption
	viBytes          [16]byte         // vi 16 bytes data for encryption
	jwtNonce         string           // JWT session Nonce for authentication
	clientAuthType   types.EvAuthType // edgeview client authentication type
	evSSHPrivateKey  string           // path to Edgeview SSH private key
	ecPrivateKeyPEM  string           // EC private key in PEM format
	ecPublicKeyPEM   []byte           // EC public key in PEM format
)

// authentication/encryption wrapper for messages
type envelopeMsg struct {
	Message    []byte             `json:"message"`
	Sha256Hash [hashBytesNum]byte `json:"sha256Hash"`
	Signature  []byte             // Field to store the cert auth signature
}

// LoadPublicKey loads a public key from a PEM file and determines its type (RSA or EC)
func LoadPublicKey(pemData string) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	var pubKey interface{}
	var err error

	switch block.Type {
	case "PUBLIC KEY":
		pubKey, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		pubKey = cert.PublicKey
	default:
		return nil, errors.New("unsupported PEM block type: " + block.Type)
	}

	if err != nil {
		return nil, err
	}

	switch key := pubKey.(type) {
	case *ecdsa.PublicKey:
		return key, nil
	case *rsa.PublicKey:
		return key, nil
	default:
		return nil, errors.New("unknown public key type")
	}
}

// signWithRSAPrivateKey signs the message using the provided RSA private key
func signWithRSAPrivateKey(msg []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hashed := sha256.Sum256(msg)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// verifyWithRSAPublicKey verifies the signature using the RSA public key
func verifyWithRSAPublicKey(message, signature []byte, publicKey *rsa.PublicKey) bool {
	hashed := sha256.Sum256(message)
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	return err == nil
}

// verifyCertSignedData verifies the signed data using the EC public key
func verifyCertSignedData(msg *envelopeMsg, publicKeyPEM string) bool {
	publicKey, err := LoadPublicKey(publicKeyPEM)
	if err != nil {
		log.Errorf("failed to load public key: %v", err)
		return false
	}

	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		log.Functionf("verifyCertSignedData: Parsed RSA public key")
		return verifyWithRSAPublicKey(msg.Message, msg.Signature, key)
	case *ecdsa.PublicKey:
		log.Functionf("verifyCertSignedData: Parsed ECDSA public key")
		return verifyWithECPublicKey(msg.Message, msg.Signature, key)
	default:
		log.Errorf("unknown public key type: %T", publicKey)
		return false
	}
}

// verifyWithECPublicKey verifies the signature using the provided EC public key
func verifyWithECPublicKey(msg, signature []byte, publicKey *ecdsa.PublicKey) bool {
	hashed := sha256.Sum256(msg)

	// Split the signature into r and s
	r := big.NewInt(0).SetBytes(signature[:len(signature)/2])
	s := big.NewInt(0).SetBytes(signature[len(signature)/2:])

	return ecdsa.Verify(publicKey, hashed[:], r, s)
}

// sign with JWT nonce on message data and send through websocket
// when write websocket message, if authentication is enabled, only client
// side sending Edgeview command need to sign the message.
func addEnvelopeAndWriteWss(msg []byte, isText bool, clientAuthNeeded bool) error {
	var jdata []byte
	var err error
	if clientAuthNeeded {
		if clientAuthType == types.EvAuthTypeControllerCert {
			// Edgeview client from the controller side
			jdata = signClientCertAuthenData(msg, ecPrivateKeyPEM)
		} else if clientAuthType == types.EvAuthTypeSSHRsaKeys {
			// Edgeview client from the remote user with SSH key
			jdata, err = signClientSSHKeyAuthenData(msg, []byte(evSSHPrivateKey))
			if err != nil {
				return fmt.Errorf("addEnvelopeAndWriteWss: signClientSSHKeyAuthenData failed %v", err)
			}
		} else {
			jdata = addEvelopeToData(msg)
		}
	} else {
		jdata = addEvelopeToData(msg)
	}
	if jdata == nil {
		err := fmt.Errorf("add envelope message failed")
		return err
	}

	var msgType int
	if isText {
		msgType = websocket.TextMessage
	} else {
		msgType = websocket.BinaryMessage
	}
	// for websocket write, the requirement is that: Applications are responsible for
	// ensuring that no more than one goroutine calls the write methods.
	// we do grab the mutex before write in this function, and another place is
	// in function sendKeepalive() which the packet is only sent to dispatcher.
	wssWrMutex.Lock()
	err = websocketConn.WriteMessage(msgType, jdata)
	wssWrMutex.Unlock()
	return err
}

func addEvelopeToData(msg []byte) []byte {
	if nonceOpEncrption {
		return encryptData(msg)
	}
	return signAuthenData(msg)
}

func signAuthenData(msg []byte) []byte {
	jmsg := envelopeMsg{
		Message: msg,
	}

	h := hmac.New(sha256.New, []byte(jwtNonce))
	_, _ = h.Write(jmsg.Message)
	hash := h.Sum(nil)
	n := copy(jmsg.Sha256Hash[:], hash)
	if len(hash) != hashBytesNum || n != hashBytesNum {
		log.Errorf("Hash copy bytes not correct: %d", n)
		return nil
	}

	jdata, err := json.Marshal(jmsg)
	if err != nil {
		log.Errorf("json marshal error: %v", err)
		return nil
	}
	return jdata
}

func encryptData(msg []byte) []byte {
	eMsg, err := encryptEvMsg(msg)
	if err != nil {
		log.Errorf("encrypt failed %v", err)
		return nil
	}
	jmsg := envelopeMsg{
		Message:    eMsg,
		Sha256Hash: sha256.Sum256(msg),
	}

	jdata, err := json.Marshal(jmsg)
	if err != nil {
		log.Errorf("json marshal error: %v", err)
		return nil
	}
	return jdata
}

// returns isJson, verifyOK and payload data
func verifyEnvelopeData(data []byte, checkClientAuth bool) (bool, bool, []byte, string) {
	var envelope envelopeMsg
	var keyComment string
	err := json.Unmarshal(data, &envelope)
	if err != nil {
		return false, false, nil, keyComment
	}

	// all the text message from client side set this checkClientAuth flag to true
	// we only authenticate the Edgeview commands from the client side
	if clientAuthType != types.EvAuthTypeUnspecified && checkClientAuth {
		if len(envelope.Signature) == 0 {
			errTypeStr := "Private Ceritificate, "
			if clientAuthType == types.EvAuthTypeSSHRsaKeys {
				errTypeStr = "SSH private key,\n"
			}
			log.Errorf("Signature is empty")
			_ = addEnvelopeAndWriteWss([]byte("Edgeview requires client authentication signing by "+errTypeStr+verifyFailed), true, false)
			return true, false, nil, keyComment
		}

		var isValid bool
		if clientAuthType == types.EvAuthTypeControllerCert {
			isValid = verifyCertSignedData(&envelope, string(ecPublicKeyPEM))
		} else if clientAuthType == types.EvAuthTypeSSHRsaKeys {
			evSSHPubKeys := getEdgeviewSSHPublicKeys()
			if len(evSSHPubKeys) == 0 {
				log.Errorf("Edgeview SSH public key is empty")
				_ = addEnvelopeAndWriteWss([]byte("Edgeview SSH public key is empty.\n"+verifyFailed), true, false)
				return true, false, nil, keyComment
			}
			// handle multiple public keys, need to verify from one of them
			for i, evSSHPubKey := range evSSHPubKeys {
				if i > 2 { // only support up to 3 ssh public keys
					break
				}
				isValid = verifySSHKeySignedData(&envelope, evSSHPubKey)
				if isValid {
					keyComment, err = ExtractCommentFromSSHPublicKey(evSSHPubKey)
					if err != nil {
						log.Errorf("failed to extract comment from SSH public key: %v", err)
						keyComment = "" // Optionally reset keyComment if the error occurs
					}
					break
				}
			}
		}
		if !isValid {
			log.Errorf("Signature verification failed")
			_ = addEnvelopeAndWriteWss([]byte("Edgeview client signed message not valid.\n"+verifyFailed), true, false)
			return true, false, nil, keyComment
		}
		log.Functionf("verifyEnvelopeData: Signature verification success")
		return true, true, envelope.Message, keyComment
	}

	if nonceOpEncrption {
		ok, msg := decryptEvMsg(envelope.Message)
		if !ok {
			return true, false, nil, keyComment
		}
		shaSum := sha256.Sum256(msg)
		if !bytes.Equal(envelope.Sha256Hash[:], shaSum[:]) {
			return true, false, nil, keyComment
		}
		return true, true, msg, keyComment
	}

	h := hmac.New(sha256.New, []byte(jwtNonce))
	_, _ = h.Write(envelope.Message)
	if !bytes.Equal(envelope.Sha256Hash[:], h.Sum(nil)) {
		return true, false, nil, keyComment
	}

	return true, true, envelope.Message, keyComment
}

func encryptEvMsg(msg []byte) ([]byte, error) {
	block, err := aes.NewCipher(nonceHash[:])
	if err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, viBytes[:])
	cipherText := make([]byte, len(msg))
	cfb.XORKeyStream(cipherText, msg)
	return cipherText, nil
}

func decryptEvMsg(data []byte) (bool, []byte) {
	block, err := aes.NewCipher(nonceHash[:])
	if err != nil {
		return false, nil
	}
	cfb := cipher.NewCFBDecrypter(block, viBytes[:])
	plainText := make([]byte, len(data))
	cfb.XORKeyStream(plainText, data)
	return true, plainText
}

func encryptVarInit(jdata types.EvjwtInfo) {
	jwtNonce = jdata.Key
	nonceOpEncrption = jdata.Enc
	if nonceOpEncrption {
		nonceHash = sha256.Sum256([]byte(jdata.Key))
		viBytes = md5.Sum([]byte(jdata.Key))
	}
}

// signClientSSHKeyAuthenData signs the message using the provided SSH private key
func signClientSSHKeyAuthenData(msg []byte, privateKeyPEM []byte) ([]byte, error) {
	jmsg := envelopeMsg{
		Message: msg,
	}

	// Decode the PEM block
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("block is nil")
	} else if block.Type != "RSA PRIVATE KEY" && block.Type != "OPENSSH PRIVATE KEY" && block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key PEM data, type: %s", block.Type)
	}

	// Parse the private key
	privateKey, err := loadPrivateKey(string(privateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v, only SSH RSA or ECC key types are supported", err)
	}

	// Sign the message based on the private key type
	var signature []byte
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		signature, err = signWithRSAPrivateKey(msg, key)
		if err != nil {
			return nil, fmt.Errorf("failed to sign with RSA private key: %v", err)
		}
	case *ecdsa.PrivateKey:
		signature, _, _, err = signWithECPrivateKey(msg, key)
		if err != nil {
			return nil, fmt.Errorf("failed to sign with ECDSA private key: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported private key type: %T, only SSH RSA or ECC keys are supported", privateKey)
	}

	// Add the signature to the envelope message
	jmsg.Signature = signature

	// Marshal the envelope message to JSON
	jdata, err := json.Marshal(jmsg)
	if err != nil {
		return nil, fmt.Errorf("json marshal error: %v", err)
	}
	return jdata, nil
}

// verifySSHKeySignedData verifies the signature using the SSH public key
func verifySSHKeySignedData(msg *envelopeMsg, publicSSHKey string) bool {
	// Convert the SSH public key to PEM format
	pemBytes, err := publicKeyToPEM([]byte(publicSSHKey))
	if err != nil {
		log.Errorf("publicKeyToPEM failed: %v", err)
		return false
	}

	// Decode the PEM block
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		log.Errorf("failed to decode PEM block containing public key")
		return false
	}

	message := msg.Message
	signedData := msg.Signature

	// Handle different public key types based on block.Type
	switch block.Type {
	case "RSA PUBLIC KEY":
		// Parse the RSA public key
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Errorf("verifySSHKeySignedData: ParsePKIXPublicKey failed for RSA: %v", err)
			return false
		}
		switch pubKey := pubKey.(type) {
		case *rsa.PublicKey:
			log.Tracef("verifySSHKeySignedData: Parsed RSA public key, verifying")
			return verifyWithRSAPublicKey(message, signedData, pubKey)
		default:
			log.Errorf("unsupported RSA public key type: %T, only SSH RSA or ECC key types are supported", pubKey)
			return false
		}

	case "PUBLIC KEY":
		// Parse the ECC public key
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Errorf("verifySSHKeySignedData: ParsePKIXPublicKey failed for ECC: %v", err)
			return false
		}
		switch pubKey := pubKey.(type) {
		case *ecdsa.PublicKey:
			log.Tracef("verifySSHKeySignedData: Parsed ECDSA public key, verifying")
			return verifyWithECPublicKey(message, signedData, pubKey)
		default:
			log.Errorf("unsupported ECC public key type: %T, only SSH RSA or ECC key types are supported", pubKey)
			return false
		}

	default:
		log.Errorf("unsupported public key type: %s", block.Type)
		return false
	}
}

func publicKeyToPEM(publicSSHKey []byte) ([]byte, error) {
	// Parse the SSH public key
	sshPublicKey, _, _, _, err := ssh.ParseAuthorizedKey(publicSSHKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH public key: %v", err)
	}

	// Ensure the SSH public key implements the CryptoPublicKey interface
	cryptoKey, ok := sshPublicKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errors.New("failed to convert SSH public key to crypto public key")
	}

	// Extract the crypto.PublicKey
	cryptoPubKey := cryptoKey.CryptoPublicKey()

	// Check the type of the public key (RSA or ECC)
	var pemBlock *pem.Block
	switch key := cryptoPubKey.(type) {
	case *rsa.PublicKey:
		x509EncodedPubKey, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal RSA public key: %v", err)
		}
		pemBlock = &pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509EncodedPubKey,
		}
	case *ecdsa.PublicKey:
		x509EncodedPubKey, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ECC public key: %v", err)
		}
		pemBlock = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: x509EncodedPubKey,
		}
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", cryptoPubKey)
	}

	// Encode the X.509 SubjectPublicKeyInfo structure in PEM format
	pemBytes := pem.EncodeToMemory(pemBlock)
	return pemBytes, nil
}

// getEdgeviewSSHPublicKeys reads multiple SSH public keys from a single string
func getEdgeviewSSHPublicKeys() []string {
	// Split the keysString by newline to get individual keys
	var validKeys []string
	configitems := getConfigItems()
	items, ok := configitems.GlobalSettings[types.EdgeviewPublicKeys]
	if ok && items.StrValue != "" {
		keys := strings.Split(items.StrValue, "\n")

		// Remove any empty strings from the slice
		for _, key := range keys {
			trimmedKey := strings.TrimSpace(key)
			if trimmedKey != "" {
				validKeys = append(validKeys, trimmedKey)
			}
		}
	}
	return validKeys
}

// getEdgeviewClientPrivateKey - Edgeview client mounts the private-key path inside the container
func getEdgeviewClientPrivateKey() string {
	privateKeyPath := "/clientauth/privatekey"
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		fmt.Printf("Failed to read private key file: %v\n", err)
		return ""
	}
	return string(privateKeyBytes)
}

// ExtractCommentFromSSHPublicKey extracts the comment from an SSH public key string
// to be used in logging the user-info of the Edgeview command
func ExtractCommentFromSSHPublicKey(publicSSHKey string) (string, error) {
	// Parse the SSH public key
	_, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(publicSSHKey))
	if err != nil {
		return "", fmt.Errorf("failed to parse SSH public key: %v", err)
	}
	return comment, nil
}

// signWithECPrivateKey signs the message using the provided EC private key
func signWithECPrivateKey(msg []byte, privateKey *ecdsa.PrivateKey) ([]byte, *big.Int, *big.Int, error) {
	hashed := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
	if err != nil {
		return nil, nil, nil, err
	}

	// Concatenate r and s to form the signature
	signature := append(etpm.EccIntToBytes(privateKey.Curve, r), etpm.EccIntToBytes(privateKey.Curve, s)...)
	return signature, r, s, nil
}

func signClientCertAuthenData(msg []byte, ecPrivateKey string) []byte {
	jmsg := envelopeMsg{
		Message: msg,
	}

	privateKey, err := loadPrivateKey(ecPrivateKey)
	if err != nil {
		log.Errorf("failed to load private key: %v", err)
		return nil
	}

	var signature []byte
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		signature, err = signWithRSAPrivateKey(jmsg.Message, key)
		if err != nil {
			log.Errorf("failed to sign message: %v", err)
			return nil
		}
	case *ecdsa.PrivateKey:
		signature, _, _, err = signWithECPrivateKey(jmsg.Message, key)
		if err != nil {
			log.Errorf("failed to sign message: %v", err)
			return nil
		}
	default:
		log.Errorf("Unknown private key type: %T", privateKey)
		return nil
	}

	jmsg.Signature = signature

	jdata, err := json.Marshal(jmsg)
	if err != nil {
		log.Errorf("json marshal error: %v", err)
		return nil
	}
	return jdata
}

// loadPrivateKey loads an EC or RSA private key from a PEM file
func loadPrivateKey(pemData string) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || !strings.Contains(block.Type, "PRIVATE KEY") { // it can be "EC PRIVATE KEY" or "OPENSSH PRIVATE KEY"
		blockType := "unknown"
		if block != nil {
			blockType = block.Type
		}
		return nil, errors.New("failed to decode PEM block containing private key certificate, type: " + blockType)
	}

	var privateKey interface{}
	var err error

	switch block.Type {
	case "PRIVATE KEY":
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			privateKey, err = x509.ParseECPrivateKey(block.Bytes)
		}
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "OPENSSH PRIVATE KEY":
		// Use ssh package to parse OpenSSH private key
		privateKey, err = ssh.ParseRawPrivateKey([]byte(pemData))
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	// Assert the type of the private key
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return key, nil
	case *ecdsa.PrivateKey:
		return key, nil
	default:
		fmt.Printf("Unknown private key type: %T\n", privateKey)
		return nil, errors.New("unknown private key type")
	}
}
