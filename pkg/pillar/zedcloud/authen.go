// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Common code to communicate to zedcloud

package zedcloud

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
	"io/ioutil"
	"math/big"
	"mime"
	"net/http"
	"os"

	"github.com/golang/protobuf/proto"
	zauth "github.com/lf-edge/eve/api/go/auth"
	zcert "github.com/lf-edge/eve/api/go/certs"
	zcommon "github.com/lf-edge/eve/api/go/evecommon"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

const (
	hashSha256Len16 = 16 // senderCertHash size of 16
	hashSha256Len32 = 32 // size of 32 bytes
)

// given an envelope protobuf received from controller, verify the authentication
func verifyAuthentication(ctx *ZedCloudContext, c []byte, skipVerify bool) ([]byte, types.SenderResult, error) {
	senderSt := types.SenderStatusNone
	sm := &zauth.AuthContainer{}
	err := proto.Unmarshal(c, sm)
	if err != nil {
		log.Errorf("verifyAuthentication: can not unmarshal authen content, %v\n", err)
		return nil, senderSt, err
	}

	data := sm.AuthPayload.GetPayload()
	if !skipVerify { // no verify for /certs itself
		if len(sm.GetSenderCertHash()) != hashSha256Len16 &&
			len(sm.GetSenderCertHash()) != hashSha256Len32 {
			log.Errorf("verifyAuthentication: senderCertHash length %d\n",
				len(sm.GetSenderCertHash()))
			err := fmt.Errorf("verifyAuthentication: senderCertHash length error")
			return nil, types.SenderStatusHashSizeError, err
		}

		if ctx.serverSigningCert == nil {
			err := getServerSigingCert(ctx)
			if err != nil {
				log.Errorf("verifyAuthentication: can not get server cert, %v\n", err)
				return nil, senderSt, err
			}
		}

		switch sm.Algo {
		case zcommon.HashAlgorithm_HASH_ALGORITHM_SHA256_32BYTES:
			if bytes.Compare(sm.GetSenderCertHash(), ctx.serverSigningCertHash) != 0 {
				err := fmt.Errorf("verifyAuthentication: local server cert hash 32bytes does not match in authen")
				log.Errorf("verifyAuthentication: local server cert hash(%d) does not match in authen (%d) %v, %v",
					len(ctx.serverSigningCertHash), len(sm.GetSenderCertHash()), ctx.serverSigningCertHash, sm.GetSenderCertHash())
				return nil, types.SenderStatusCertMiss, err
			}
		case zcommon.HashAlgorithm_HASH_ALGORITHM_SHA256_16BYTES:
			if bytes.Compare(sm.GetSenderCertHash(), ctx.serverSigningCertHash[:hashSha256Len16]) != 0 {
				err := fmt.Errorf("verifyAuthentication: local server cert hash 16bytes does not match in authen")
				log.Errorf("verifyAuthentication: local server cert hash(%d) does not match in authen (%d) %v, %v",
					len(ctx.serverSigningCertHash), len(sm.GetSenderCertHash()), ctx.serverSigningCertHash, sm.GetSenderCertHash())
				return nil, types.SenderStatusCertMiss, err
			}
		default:
			log.Errorf("verifyAuthentication: hash algorithm is not supported\n")
			err := fmt.Errorf("verifyAuthentication: hash algorithm is not supported")
			return nil, types.SenderStatusAlgoFail, err
		}

		hash := ComputeSha(data)
		err = verifyAuthSig(sm.GetSignatureHash(), ctx.serverSigningCert, hash)
		if err != nil {
			log.Errorf("verifyAuthentication: verifyAuthSig error %v\n", err)
			return nil, types.SenderStatusSignVerifyFail, err
		}
		log.Debugf("verifyAuthentication: ok\n")
	}
	return data, senderSt, nil
}

func getServerSigingCert(ctx *ZedCloudContext) error {
	certBytes, err := ioutil.ReadFile(types.ServerSigningCertFileName)
	if err != nil {
		log.Errorf("getServerSigningCert: can not read in server cert file, %v\n", err)
		return err
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		err := fmt.Errorf("getServerSigningCert: can not get client Cert")
		return err
	}

	sCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Errorf("getServerSigningCert: can not parse cert %v\n", err)
		return err
	}

	// hash verify using PEM bytes from cloud
	ctx.serverSigningCertHash = ComputeSha(certBytes)
	ctx.serverSigningCert = sCert

	return nil
}

// ClearCloudCert - zero out cached cloud certs in client zedcloudCtx
func ClearCloudCert(ctx *ZedCloudContext) {
	ctx.serverSigningCert = nil
	ctx.serverSigningCertHash = nil
}

// verify the signed data with cloud certificate public key
func verifyAuthSig(signature []byte, cert *x509.Certificate, hash []byte) error {

	log.Debugf("verifyAuthsig sigdata (len %d) %v\n", len(hash), hash)

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash, signature)
		if err != nil {
			return err
		}
		log.Debugf("verifyAuthSig: verify rsa ok\n")
	case *ecdsa.PublicKey:

		sigHalflen, err := ecdsakeyBytes(pub)
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
		log.Debugf("verifyAuthSig: verify ecdsa ok\n")
	default:
		log.Errorf("verifyAuthSig: unknown type of public key %T\n", pub)
		return errors.New("unknown type of public key")
	}
	return nil
}

// add an authentication envelope protobuf when sending http POST
func addAuthentication(ctx *ZedCloudContext, b *bytes.Buffer, useOnboard bool) (*bytes.Buffer, error) {
	var data []byte
	if b != nil {
		data = b.Bytes()
	}
	body := zauth.AuthBody{
		Payload: data,
	}
	sm := zauth.AuthContainer{}
	sm.AuthPayload = &body

	cert, err := getMyDevCert(ctx, useOnboard)
	if err != nil {
		log.Debugf("addAuthenticate: get client cert failed\n")
		return nil, err
	}

	// assign our certificate hash of 32 bytes
	if useOnboard {
		sm.SenderCertHash = ctx.onBoardCertHash
		sm.SenderCert = ctx.onBoardCertBytes
		if len(sm.SenderCert) == 0 {
			err := fmt.Errorf("addAuthentication: SenderCert empty")
			log.Errorf("addAuthenticate: get sender cert failed, %v\n", err)
			return nil, err
		}
		log.Debugf("addAuthenticate: onboard senderCert size %d\n", len(sm.SenderCert))
	} else {
		sm.SenderCertHash = ctx.deviceCertHash
	}
	if sm.SenderCertHash == nil {
		err := fmt.Errorf("addAuthentication: SenderCertHash empty")
		return nil, err
	}

	sig, err := signAuthData(data, cert)
	if err != nil {
		log.Debugf("addAuthenticate: sign auth data error %v\n", err)
		return nil, err
	}
	sm.SignatureHash = sig
	sm.Algo = zcommon.HashAlgorithm_HASH_ALGORITHM_SHA256_32BYTES

	data2, err := proto.Marshal(&sm)
	if err != nil {
		log.Debugf("addAuthenticate: auth marshal error %v\n", err)
		return nil, err
	}

	size := int64(proto.Size(&sm))
	buf := bytes.NewBuffer(data2)
	log.Debugf("addAuthenticate: payload size %d, sig %v\n", size, sig)
	return buf, nil
}

func getMyDevCert(ctx *ZedCloudContext, isOnboard bool) (tls.Certificate, error) {
	var cert tls.Certificate
	var err error
	if isOnboard {
		if ctx.onBoardCert == nil {
			cert, err = tls.LoadX509KeyPair(types.OnboardCertName,
				types.OnboardKeyName)
			if err != nil {
				log.Debugf("getMyDevCert: get onboard cert error %v\n", err)
				return cert, err
			}

			onboardCertpem, err := ioutil.ReadFile(types.OnboardCertName)
			if err != nil {
				log.Debugf("getMyDevCert: get onboard certbytes error %v\n", err)
				return cert, err
			}
			ctx.onBoardCertBytes = []byte(base64.StdEncoding.EncodeToString(onboardCertpem))

			// device side of cert hash is calculated from the x509 cert, not from PEM bytes
			ctx.onBoardCertHash, err = certToSha256(cert)
			if err != nil {
				return cert, err
			}
			ctx.onBoardCert = &cert
			log.Debugf("getMyDevCert: onboard cert with hash %v\n", string(ctx.onBoardCertHash))
		} else {
			cert = *ctx.onBoardCert
		}
	} else {
		if ctx.deviceCert == nil {
			cert, err = GetClientCert()
			if err != nil {
				log.Errorf("getMyDevCert: get client cert error %v\n", err)
				return cert, err
			}

			// device side of cert hash is calculated from the x509 cert, not from PEM bytes
			ctx.deviceCertHash, err = certToSha256(cert)
			if err != nil {
				return cert, err
			}
			ctx.deviceCert = &cert
			log.Debugf("getMyDevCert: device cert with hash %v\n", string(ctx.deviceCertHash))
		} else {
			cert = *ctx.deviceCert
		}
	}
	return cert, nil
}

// sign hash'ed data with certificate private key
func signAuthData(sigdata []byte, cert tls.Certificate) ([]byte, error) {
	log.Debugf("sending sigdata (len %d) %v\n", len(sigdata), sigdata)
	hash := ComputeSha(sigdata)

	var sigres []byte
	switch key := cert.PrivateKey.(type) {
	default:
		err := fmt.Errorf("signAuthData: privatekey default, type %T", key)
		return nil, err
	case etpm.TpmPrivateKey:
		r, s, err := etpm.TpmSign(hash)
		if err != nil {
			log.Errorf("signAuthData: tpmSign error %v\n", err)
			return nil, err
		}
		log.Debugf("r.bytes %d s.bytes %d\n", len(r.Bytes()),
			len(s.Bytes()))
		sigres = RSCombinedBytes(r.Bytes(), s.Bytes())
		log.Debugf("signAuthData: tpm sigres (len %d): %x\n", len(sigres), sigres)
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, hash)
		if err != nil {
			log.Errorf("signAuthData: ecdsa sign error %v\n", err)
			return nil, err
			//log.Fatal("ecdsa.Sign: ", err)
		}
		log.Debugf("r.bytes %d s.bytes %d\n", len(r.Bytes()),
			len(s.Bytes()))
		sigres = RSCombinedBytes(r.Bytes(), s.Bytes())
		log.Debugf("signAuthData: ecdas sigres (len %d): %x\n",
			len(sigres), sigres)
	}
	return sigres, nil
}

// RSCombinedBytes - combine r & s into fixed length bytes
func RSCombinedBytes(rBytes, sBytes []byte) []byte {
	rsize := len(rBytes)
	ssize := len(sBytes)
	size := rsize
	if ssize > rsize {
		size = ssize
	}
	if size%8 > 0 {
		size = getUpperMultiOf8(size)
	}

	// basically the size is 32 bytes. the r and s needs to be both left padded to two 32 bytes slice
	// into a single signature buffer
	buffer := make([]byte, size*2)
	startPos := size - rsize
	copy(buffer[startPos:], rBytes)
	startPos = size*2 - ssize
	copy(buffer[startPos:], sBytes)
	return buffer[:]
}

func ecdsakeyBytes(pubKey *ecdsa.PublicKey) (int, error) {
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

func getUpperMultiOf8(size int) int {
	newsize := 8
	for {
		if newsize >= size {
			break
		}
		newsize += 8
	}
	return newsize
}

// ComputeSha - Compute sha256 on data
func ComputeSha(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	hash := h.Sum(nil)
	return hash
}

func checkMimeProtoType(r *http.Response) bool {
	if r == nil {
		return false
	}
	var ctTypeProtoStr = "application/x-proto-binary"
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return false
	}
	mimeType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}

	return mimeType == ctTypeProtoStr
}

// VerifySigningCertChain - verify signing certificate chain from controller
func VerifySigningCertChain(ctx *ZedCloudContext, content []byte) ([]byte, error) {
	sm := &zcert.ZControllerCert{}
	err := proto.Unmarshal(content, sm)
	if err != nil {
		log.Errorf("SaveCertsToFile: Unmarshal err %v\n", err)
		return nil, err
	}

	var block *pem.Block
	var leafcert *x509.Certificate
	var certByte []byte
	var keyCnt int
	interm := x509.NewCertPool()
	for _, cert := range sm.GetCerts() {
		keyCnt++
		if cert.Type == zcert.ZCertType_CERT_TYPE_CONTROLLER_INTERMEDIATE {
			ok := interm.AppendCertsFromPEM(cert.GetCert())
			if !ok {
				err := fmt.Errorf("VerifySigningCertChain: fail to append intermediate certs")
				return nil, err
			}
			log.Debugf("VerifySigningCertChain: get intermediate cert %d, len %d\n",
				keyCnt, len(cert.GetCert()))
		} else if cert.Type == zcert.ZCertType_CERT_TYPE_CONTROLLER_SIGNING {
			if len(certByte) > 0 {
				err := fmt.Errorf("VerifySigningCertChain: received more than one leaf cert")
				return nil, err
			}
			certByte = cert.GetCert()
			block, _ = pem.Decode(certByte)
			if block == nil {
				err := fmt.Errorf("VerifySigningCertChain: can not get cert block")
				return nil, err
			}
			leafcert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Errorf("VerifySigningCertChain: fail to parse certificate %v\n", err)
				return nil, err
			}
			log.Debugf("VerifySigningCertChain: get signing cert %d, len %d\n",
				keyCnt, len(cert.GetCert()))
		} else if cert.Type == zcert.ZCertType_CERT_TYPE_CONTROLLER_ECDH_EXCHANGE {
			// skip for the CONTROLLER_ECDH_EXECHANGE cert type here, not for signing purpose
			log.Debugf("VerifySigningCertChain: ECDH_EXCHANGE type, ignore cert %d, len %d\n",
				keyCnt, len(cert.GetCert()))
		} else {
			err := fmt.Errorf("VerifySigningCertChain: received cert with unknown type %d", cert.Type)
			return nil, err
		}
	}

	log.Debugf("VerifySigningCertChain: key count %d\n", keyCnt)
	if leafcert == nil {
		err := fmt.Errorf("VerifySigningCertChain: fail to acquire leaf cert")
		return nil, err
	}

	// Get the root certificate from file
	signingRoots := x509.NewCertPool()
	caCert1, err := ioutil.ReadFile(types.RootCertFileName)
	if err != nil {
		return nil, err
	}
	if !signingRoots.AppendCertsFromPEM(caCert1) {
		errStr := fmt.Sprintf("Failed to append certs from %s", types.RootCertFileName)
		log.Errorf(errStr)
		return nil, errors.New(errStr)
	}

	opts := x509.VerifyOptions{
		Roots: signingRoots,
		// for signing, not to verify the server name
		Intermediates: interm,
	}
	if _, err := leafcert.Verify(opts); err != nil {
		log.Errorf("VerifySigningCertChain: fail to verify the cert chain %v\n", err)
		return nil, err
	}

	// save this cert and hash to serverSigningCert and serverSigingCertHash
	ctx.serverSigningCertHash = ComputeSha(certByte)
	block, _ = pem.Decode(certByte)
	if block == nil {
		err := fmt.Errorf("VerifySigningCertChain: can not get client Cert")
		return nil, err
	}
	sCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Errorf("VerifySigningCertChain: can not parse cert %v", err)
		return nil, err
	}
	ctx.serverSigningCert = sCert

	log.Debugf("VerifySigningCertChain: success\n")
	return certByte, nil
}

// UseV2API - check the controller cert file and use V2 api if it exist
// by default it is running V2, unless /config/Force-API-V1 file exists
func UseV2API() bool {
	_, err := os.Stat(types.APIV1FileName)
	if err == nil {
		return false
	}
	return true
}

// URLPathString - generate url for either v1 or v1 API path
func URLPathString(server string, isV2api, isHTTP bool, devUUID uuid.UUID, action string) string {
	var urlstr string
	if !isV2api {
		urlstr = server + "/api/v1/edgedevice/" + action
	} else {
		urlstr = server + "/api/v2/edgedevice/"
		if devUUID != nilUUID {
			urlstr = urlstr + "id/" + devUUID.String() + "/"
		}
		urlstr = urlstr + action
	}
	if isHTTP {
		return "http://" + urlstr
	}
	return urlstr
}

// the cloud controller lookup prefers the hash computed from x509 cert
func certToSha256(cert tls.Certificate) ([]byte, error) {
	if len(cert.Certificate) == 0 {
		err := fmt.Errorf("certToSha256: no cert entry")
		return nil, err
	}

	c, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		log.Infof("certToSha256: parse cert entry err %v\n", err)
		return nil, err
	}

	return ComputeSha(c.Raw), nil
}
