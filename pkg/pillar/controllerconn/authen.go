// Copyright (c) 2020-2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// tls.go contains helper functions for manipulating with AuthContainer in controllerconn.

package controllerconn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	zauth "github.com/lf-edge/eve-api/go/auth"
	zcert "github.com/lf-edge/eve-api/go/certs"
	zcommon "github.com/lf-edge/eve-api/go/evecommon"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"google.golang.org/protobuf/proto"
)

const (
	hashSha256Len16 = 16 // senderCertHash size of 16
	hashSha256Len32 = 32 // size of 32 bytes
)

// RemoveAndVerifyAuthContainer is used to check that a correct authentication is
// present when expected.
// Modifies SendRetval received from SendOnAllIntf or SendOnIntf:
//   - SendRetval.RespContent is unwrapped to contain the content of the AuthContainer
//   - SendRetval.Status is potentially updated to reflect the result of auth verification
//
// If skipVerify we remove the envelope but do not verify the signature.
func (c *Client) RemoveAndVerifyAuthContainer(sendRV *SendRetval, skipVerify bool) error {
	var reqURL string
	if strings.HasPrefix(sendRV.ReqURL, "http:") {
		reqURL = sendRV.ReqURL
	} else {
		if strings.HasPrefix(sendRV.ReqURL, "https:") {
			reqURL = sendRV.ReqURL
		} else {
			reqURL = "https://" + sendRV.ReqURL
		}
	}
	if !c.v2API {
		return nil
	}
	contents, status, err := c.removeAndVerifyAuthContainer(sendRV.RespContents, skipVerify)
	if status != types.SenderStatusNone {
		sendRV.Status = status
	}
	if err != nil {
		var envelopeErr bool
		if sendRV.Status == types.SenderStatusHashSizeError ||
			sendRV.Status == types.SenderStatusAlgoFail {
			// server may not support V2 envelope
			envelopeErr = true
		}
		c.log.Errorf("RemoveAndVerifyAuthContainer verify auth error %v, "+
			"V2 server %v, content len %d, url %s, senderStatus %v",
			err, !envelopeErr, len(contents), reqURL, sendRV.Status)
		if c.AgentMetrics != nil {
			c.AgentMetrics.RecordFailure(c.log, "", reqURL, 0, 0, true)
		}
		return err
	}
	sendRV.RespContents = contents
	c.log.Tracef("RemoveAndVerifyAuthContainer verify auth ok, url %s", reqURL)
	return nil
}

// given an envelope protobuf received from controller, verify the authentication
// If skipVerify we parse the envelope but do not verify the content.
func (c *Client) removeAndVerifyAuthContainer(
	authContainerBytes []byte, skipVerify bool) ([]byte, types.SenderStatus, error) {
	senderSt := types.SenderStatusNone
	sm := &zauth.AuthContainer{}
	err := proto.Unmarshal(authContainerBytes, sm)
	if err != nil {
		c.log.Errorf(
			"removeAndVerifyAuthContainer: can not unmarshal authen content, %v\n", err)
		return nil, senderSt, err
	}

	if !skipVerify { // no verify for /certs itself
		senderSt, err = c.VerifyAuthContainer(sm)
		if err != nil { // already logged
			return nil, senderSt, err
		}
	}
	c.log.Tracef("removeAndVerifyAuthContainer: ok\n")
	return sm.ProtectedPayload.GetPayload(), senderSt, nil
}

// VerifyAuthContainerHeader verifies correctness of algorithm fields in header
func (c *Client) VerifyAuthContainerHeader(sm *zauth.AuthContainer) (
	types.SenderStatus, error) {
	err := c.LoadSavedServerSigningCert()
	if err != nil {
		return types.SenderStatusNone, err
	}
	if len(sm.GetSenderCertHash()) != hashSha256Len16 &&
		len(sm.GetSenderCertHash()) != hashSha256Len32 {
		err := fmt.Errorf("VerifyAuthContainerHeader: unexpected senderCertHash length (%d)",
			len(sm.GetSenderCertHash()))
		c.log.Error(err)
		return types.SenderStatusHashSizeError, err
	}

	switch sm.Algo {
	case zcommon.HashAlgorithm_HASH_ALGORITHM_SHA256_32BYTES:
		if bytes.Compare(sm.GetSenderCertHash(), c.serverSigningCertHash) != 0 {
			c.log.Errorf("VerifyAuthContainerHeader: local server cert hash (%d)"+
				"does not match in authen (%d): %v, %v",
				len(c.serverSigningCertHash), len(sm.GetSenderCertHash()),
				c.serverSigningCertHash, sm.GetSenderCertHash())
			err := fmt.Errorf("VerifyAuthContainerHeader: local server cert hash " +
				"does not match in authen (32 bytes)")
			return types.SenderStatusCertMiss, err
		}
	case zcommon.HashAlgorithm_HASH_ALGORITHM_SHA256_16BYTES:
		if bytes.Compare(sm.GetSenderCertHash(), c.serverSigningCertHash[:hashSha256Len16]) != 0 {
			c.log.Errorf("VerifyAuthContainerHeader: local server cert hash (%d)"+
				"does not match in authen (%d): %v, %v",
				len(c.serverSigningCertHash), len(sm.GetSenderCertHash()),
				c.serverSigningCertHash, sm.GetSenderCertHash())
			err := fmt.Errorf("VerifyAuthContainerHeader: local server cert hash " +
				"does not match in authen (16 bytes)")
			return types.SenderStatusCertMiss, err
		}
	default:
		err := fmt.Errorf("VerifyAuthContainerHeader: hash algorithm is not supported")
		c.log.Error(err)
		return types.SenderStatusAlgoFail, err
	}

	return types.SenderStatusNone, nil
}

// VerifyAuthContainer verifies the integrity of the payload inside AuthContainer.
func (c *Client) VerifyAuthContainer(sm *zauth.AuthContainer) (types.SenderStatus, error) {
	status, err := c.VerifyAuthContainerHeader(sm)
	if err != nil {
		return status, err
	}
	// Verify payload integrity
	data := sm.ProtectedPayload.GetPayload()
	hash := c.computeSha(data)
	err = c.verifyAuthSig(sm.GetSignatureHash(), hash)
	if err != nil {
		err = fmt.Errorf("VerifyAuthContainer: verifyAuthSig error %v\n", err)
		c.log.Error(err)
		return types.SenderStatusSignVerifyFail, err
	}
	return types.SenderStatusNone, nil
}

// LoadSavedServerSigningCert loads server (i.e. controller) signing
// certificate stored in the file into a Client's internal variable.
func (c *Client) LoadSavedServerSigningCert() error {
	if c.serverSigningCert != nil {
		// Already loaded
		return nil
	}
	certBytes, err := os.ReadFile(types.ServerSigningCertFileName)
	if err != nil {
		c.log.Errorf("loadSavedServerSigningCert: can not read in server cert file, %v\n", err)
		return err
	}
	err = c.LoadServerSigningCert(certBytes)
	if err != nil {
		c.log.Errorf("loadServerSigningCert: can not load save server cert, %v\n", err)
		return err
	}
	return nil
}

// ClearServerCert - zero out cached server (controller) certs.
func (c *Client) ClearServerCert() {
	c.serverSigningCert = nil
	c.serverSigningCertHash = nil
}

// verify the signed data with controller certificate public key
func (c *Client) verifyAuthSig(signature []byte, hash []byte) error {

	c.log.Tracef("verifyAuthsig sigdata (len %d) %v\n", len(hash), hash)

	switch pub := c.serverSigningCert.PublicKey.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash, signature)
		if err != nil {
			return err
		}
		c.log.Tracef("verifyAuthSig: verify rsa ok\n")
	case *ecdsa.PublicKey:
		sigHalflen, err := c.ecdsakeyBytes(pub)
		if err != nil {
			return err
		}
		rbytes := signature[0:sigHalflen]
		sbytes := signature[sigHalflen:]
		r := new(big.Int)
		s := new(big.Int)
		r.SetBytes(rbytes)
		s.SetBytes(sbytes)
		ok := ecdsa.Verify(pub, hash, r, s)
		if !ok {
			return errors.New("ecdsa image signature verification failed")
		}
		c.log.Tracef("verifyAuthSig: verify ecdsa ok\n")
	default:
		c.log.Errorf("verifyAuthSig: unknown type of public key %T\n", pub)
		return errors.New("unknown type of public key")
	}
	return nil
}

// AddAuthentication adds an AuthContainer and signs it
func (c *Client) AddAuthentication(b *bytes.Buffer, useOnboard bool) (*bytes.Buffer, error) {
	var data []byte
	if b != nil {
		data = b.Bytes()
	}
	body := zauth.AuthBody{
		Payload: data,
	}
	sm := zauth.AuthContainer{}
	sm.ProtectedPayload = &body

	cert, err := c.getMyDevCert(useOnboard)
	if err != nil {
		c.log.Tracef("addAuthenticate: get client cert failed\n")
		return nil, err
	}

	// assign our certificate hash of 32 bytes
	if useOnboard {
		sm.SenderCertHash = c.onBoardCertHash
		sm.SenderCert = c.onBoardCertBytes
		if len(sm.SenderCert) == 0 {
			err := fmt.Errorf("addAuthentication: SenderCert empty")
			c.log.Errorf("addAuthenticate: get sender cert failed, %v\n", err)
			return nil, err
		}
		c.log.Tracef("addAuthenticate: onboard senderCert size %d\n", len(sm.SenderCert))
	} else {
		sm.SenderCertHash = c.deviceCertHash
	}
	if sm.SenderCertHash == nil {
		err := fmt.Errorf("addAuthentication: SenderCertHash empty")
		return nil, err
	}

	sig, err := c.signAuthData(data, cert)
	if err != nil {
		c.log.Tracef("addAuthenticate: sign auth data error %v\n", err)
		return nil, err
	}
	sm.SignatureHash = sig
	sm.Algo = zcommon.HashAlgorithm_HASH_ALGORITHM_SHA256_32BYTES

	data2, err := proto.Marshal(&sm)
	if err != nil {
		c.log.Tracef("addAuthenticate: auth marshal error %v\n", err)
		return nil, err
	}

	size := int64(proto.Size(&sm))
	buf := bytes.NewBuffer(data2)
	c.log.Tracef("addAuthenticate: payload size %d, sig %v\n", size, sig)
	return buf, nil
}

func (c *Client) getMyDevCert(isOnboard bool) (tls.Certificate, error) {
	var cert tls.Certificate
	var err error
	if isOnboard {
		if c.onBoardCert == nil {
			cert, err = tls.LoadX509KeyPair(types.OnboardCertName,
				types.OnboardKeyName)
			if err != nil {
				c.log.Tracef("getMyDevCert: get onboard cert error %v\n", err)
				return cert, err
			}

			onboardCertpem, err := os.ReadFile(types.OnboardCertName)
			if err != nil {
				c.log.Tracef("getMyDevCert: get onboard certbytes error %v\n", err)
				return cert, err
			}
			c.onBoardCertBytes = []byte(base64.StdEncoding.EncodeToString(onboardCertpem))

			// device side of cert hash is calculated from the x509 cert, not from PEM bytes
			c.onBoardCertHash, err = c.certToSha256(cert)
			if err != nil {
				return cert, err
			}
			c.onBoardCert = &cert
			c.log.Tracef("getMyDevCert: onboard cert with hash %v\n",
				string(c.onBoardCertHash))
		} else {
			cert = *c.onBoardCert
		}
	} else {
		if c.deviceCert == nil {
			cert, err = GetClientCert()
			if err != nil {
				c.log.Errorf("getMyDevCert: get client cert error %v\n", err)
				return cert, err
			}

			// device side of cert hash is calculated from the x509 cert, not from PEM bytes
			c.deviceCertHash, err = c.certToSha256(cert)
			if err != nil {
				return cert, err
			}
			c.deviceCert = &cert
			c.log.Tracef("getMyDevCert: device cert with hash %v\n",
				string(c.deviceCertHash))
		} else {
			cert = *c.deviceCert
		}
	}
	return cert, nil
}

// sign hash'ed data with certificate private key
func (c *Client) signAuthData(sigdata []byte, cert tls.Certificate) ([]byte, error) {
	c.log.Tracef("sending sigdata (len %d) %v\n", len(sigdata), sigdata)
	hash := c.computeSha(sigdata)

	var sigres []byte
	switch key := cert.PrivateKey.(type) {
	default:
		err := fmt.Errorf("signAuthData: privatekey default, type %T", key)
		return nil, err
	case etpm.TpmPrivateKey:
		r, s, err := etpm.TpmSign(hash)
		if err != nil {
			c.log.Errorf("signAuthData: tpmSign error %v\n", err)
			return nil, err
		}
		c.log.Tracef("r.bytes %d s.bytes %d\n", len(r.Bytes()),
			len(s.Bytes()))
		sigres, err = c.RSCombinedBytes(r.Bytes(), s.Bytes(), key.PublicKey.(*ecdsa.PublicKey))
		if err != nil {
			return nil, err
		}
		c.log.Tracef("signAuthData: tpm sigres (len %d): %x\n", len(sigres), sigres)
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, hash)
		if err != nil {
			c.log.Errorf("signAuthData: ecdsa sign error %v\n", err)
			return nil, err
			//ctx.log.Fatal("ecdsa.Sign: ", err)
		}
		c.log.Tracef("r.bytes %d s.bytes %d\n", len(r.Bytes()),
			len(s.Bytes()))
		sigres, err = c.RSCombinedBytes(r.Bytes(), s.Bytes(), &key.PublicKey)
		if err != nil {
			return nil, err
		}
		c.log.Tracef("signAuthData: ecdas sigres (len %d): %x\n",
			len(sigres), sigres)
	}
	return sigres, nil
}

// RSCombinedBytes - combine r & s into fixed length bytes
func (c *Client) RSCombinedBytes(rBytes, sBytes []byte, pubKey *ecdsa.PublicKey) ([]byte, error) {
	keySize, err := c.ecdsakeyBytes(pubKey)
	if err != nil {
		c.log.Errorf("RSCombinedBytes: ecdsa key bytes error %v", err)
		return nil, err
	}
	rsize := len(rBytes)
	ssize := len(sBytes)
	if rsize > keySize || ssize > keySize {
		errStr := fmt.Sprintf("RSCombinedBytes: error. keySize %d, rSize %d, sSize %d", keySize, rsize, ssize)
		return nil, errors.New(errStr)
	}

	// basically the size is 32 bytes. the r and s needs to be both left padded to two 32 bytes slice
	// into a single signature buffer
	buffer := make([]byte, keySize*2)
	startPos := keySize - rsize
	copy(buffer[startPos:], rBytes)
	startPos = keySize*2 - ssize
	copy(buffer[startPos:], sBytes)
	return buffer[:], nil
}

// SaveServerSigningCert saves server (i.e. controller) signing certificate into the persist
// partition.
func (c *Client) SaveServerSigningCert(certByte []byte) error {
	err := fileutils.WriteRename(types.ServerSigningCertFileName, certByte)
	if err != nil {
		err = fmt.Errorf("failed to write %v: %w", types.ServerSigningCertFileName, err)
		c.log.Errorf("SaveServerSignCert: %v", err)
		return err
	}
	// Clear cached
	c.ClearServerCert()
	return nil
}

// LoadServerSigningCert loads server (i.e. controller) signing certificate
// from bytes and into a Client's internal variable.
func (c *Client) LoadServerSigningCert(certByte []byte) error {
	// decode the certificate
	block, _ := pem.Decode(certByte)
	if block == nil {
		err := errors.New("certificate decode fail")
		c.log.Errorf("UpdateServerCert: %v", err)
		return err
	}

	// parse the certificate
	leafCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		err = fmt.Errorf("certificate parse fail: %w", err)
		c.log.Errorf("UpdateServerCert: %v", err)
		return err
	}

	// store the certificate
	c.serverSigningCert = leafCert

	// store the certificate hash
	c.serverSigningCertHash = c.computeSha(certByte)
	return nil
}

// the controller lookup prefers the hash computed from x509 cert
func (c *Client) certToSha256(cert tls.Certificate) ([]byte, error) {
	if len(cert.Certificate) == 0 {
		err := fmt.Errorf("certToSha256: no cert entry")
		return nil, err
	}

	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		c.log.Functionf("certToSha256: parse cert entry err %v\n", err)
		return nil, err
	}

	return c.computeSha(parsedCert.Raw), nil
}

func (c *Client) ecdsakeyBytes(pubKey *ecdsa.PublicKey) (int, error) {
	curveBits := pubKey.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	if keyBytes%8 > 0 {
		errStr := fmt.Sprintf("ecdsa pubkey size error, curveBits %d", curveBits)
		return 0, errors.New(errStr)
	}
	return keyBytes, nil
}

// computeSha - Compute sha256 on data
func (c *Client) computeSha(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	hash := h.Sum(nil)
	return hash
}

// VerifyProtoSigningCertChain - unmarshal and verify the content of ZControllerCert
// received from the controller. The function combines the unmarshalling of ZControllerCert
// with VerifySigningCertChain().
// Returns content of the signing certificate and the verification error/nil value.
func (c *Client) VerifyProtoSigningCertChain(content []byte) ([]byte, error) {
	sm := &zcert.ZControllerCert{}
	err := proto.Unmarshal(content, sm)
	if err != nil {
		errStr := fmt.Sprintf("unmarshal error, %v", err)
		c.log.Errorln("VerifySigningCertChain: " + errStr)
		return nil, errors.New(errStr)
	}
	return c.VerifySigningCertChain(sm.Certs)
}

// VerifySigningCertChain - verify signing certificate chain from controller
// Returns content of the signing certificate and the verification error/nil value.
func (c *Client) VerifySigningCertChain(certs []*zcert.ZCert) ([]byte, error) {
	// prepare intermediate certs and validate the payload
	var sigCertBytes []byte
	var keyCnt, signKeyCnt int
	interm := x509.NewCertPool()
	for _, cert := range certs {
		keyCnt++
		switch cert.Type {
		case zcert.ZCertType_CERT_TYPE_CONTROLLER_INTERMEDIATE:
			ok := interm.AppendCertsFromPEM(cert.GetCert())
			if !ok {
				errStr := fmt.Sprintf("intermediate cert append fail")
				c.log.Errorln("VerifySigningCertChain: " + errStr)
				return nil, errors.New(errStr)
			}

		case zcert.ZCertType_CERT_TYPE_CONTROLLER_SIGNING:
			signKeyCnt++
			if signKeyCnt > 1 {
				errStr := fmt.Sprintf("received more than one signing cert")
				c.log.Errorln("VerifySigningCertChain: " + errStr)
				return nil, errors.New(errStr)
			}
			sigCertBytes = cert.GetCert()

		case zcert.ZCertType_CERT_TYPE_CONTROLLER_ECDH_EXCHANGE:
			// nothing to do

		default:
			errStr := fmt.Sprintf("unknown certificate type(%d) received", cert.Type)
			c.log.Errorln("VerifySigningCertChain: " + errStr)
			return nil, errors.New(errStr)
		}
	}

	c.log.Tracef("VerifySigningCertChain: key count %d\n", keyCnt)
	if signKeyCnt == 0 {
		errStr := fmt.Sprintf("failed to acquire signing cert")
		c.log.Errorln("VerifySigningCertChain: " + errStr)
		return nil, errors.New(errStr)
	}

	// verify signature of certificates
	for _, cert := range certs {
		if cert.Type == zcert.ZCertType_CERT_TYPE_CONTROLLER_SIGNING ||
			cert.Type == zcert.ZCertType_CERT_TYPE_CONTROLLER_ECDH_EXCHANGE {
			certByte := cert.GetCert()
			if err := c.verifySignature(certByte, interm); err != nil {
				errStr := fmt.Sprintf("signature verification fail")
				c.log.Errorln("VerifySigningCertChain: " + errStr)
				return nil, err
			}
		}
	}
	c.log.Tracef("VerifySigningCertChain: success\n")
	return sigCertBytes, nil
}

func (c *Client) verifySignature(certByte []byte, interm *x509.CertPool) error {

	block, _ := pem.Decode(certByte)
	if block == nil {
		errStr := fmt.Sprintf("certificate block decode fail")
		c.log.Errorln("verifySignature: " + errStr)
		return errors.New(errStr)
	}

	leafcert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		errStr := fmt.Sprintf("certificate parse fail, %v", err)
		c.log.Errorln("verifySignature: " + errStr)
		return errors.New(errStr)
	}

	// Get the root certificate from file
	signingRoots := x509.NewCertPool()
	caCert, err := os.ReadFile(types.RootCertFileName)
	if err != nil {
		errStr := fmt.Sprintf("root certificate read fail, %v", err)
		c.log.Errorln("verifySignature: " + errStr)
		return err
	}
	if !signingRoots.AppendCertsFromPEM(caCert) {
		errStr := fmt.Sprintf("root certificate append fail, %s",
			types.RootCertFileName)
		c.log.Errorln("verifySignature: " + errStr)
		return errors.New(errStr)
	}

	opts := x509.VerifyOptions{
		Roots: signingRoots,
		// for signing, not to verify the server name
		Intermediates: interm,
	}
	if _, err := leafcert.Verify(opts); err != nil {
		errStr := fmt.Sprintf("signature verification fail, %v", err)
		c.log.Errorln("verifySignature: " + errStr)
		return errors.New(errStr)
	}
	return nil
}
