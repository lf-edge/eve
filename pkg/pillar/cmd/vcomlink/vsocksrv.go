// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vcomlink

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/eve/pkg/pillar/vcom"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

const (
	messageMaxSize = 64 * 1024 // 64KB
	hostVPort      = 2000
	backLogSize    = unix.SOMAXCONN
	readTimeout    = 30 // seconds
	writeTimeout   = 30 // seconds
)

// CID address for the host, this will get overridden in tests.
var cidAddr = unix.VMADDR_CID_HOST

// SocketListener is a function that listens on a socket and returns a net
// listener, we use this to abstract the socket creation for testing.
type SocketListener func() (net.Listener, error)

func vsockNetListener() (net.Listener, error) {
	sock, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create vsock socket: %v", err)
	}

	addr := &unix.SockaddrVM{
		CID:  uint32(cidAddr),
		Port: hostVPort,
	}
	if err := unix.Bind(sock, addr); err != nil {
		unix.Close(sock)
		return nil, fmt.Errorf("failed to bind vsock socket: %v", err)
	}
	if err := unix.Listen(sock, backLogSize); err != nil {
		unix.Close(sock)
		return nil, fmt.Errorf("failed to listen on vsock socket: %v", err)
	}

	log.Noticef("Listening on vsock CID %d, port %d", addr.CID, addr.Port)
	return &VSOCKListener{fd: sock, addr: addr}, nil
}

func startVcomServer(listener SocketListener) {
	l, err := listener()
	if err != nil {
		log.Errorf("failed to listen: %v", err)
		return
	}
	defer l.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/tpm/getpub", handleGetPub)
	mux.HandleFunc("/tpm/sign", handleSigner)
	mux.HandleFunc("/tpm/readnv", handleReadNV)
	mux.HandleFunc("/tpm/activatecred", handleActivateCred)
	mux.HandleFunc("/tpm/activatecredparams", handleActivateCredParams)

	http.Serve(l, mux)
}

func handleActivateCredParams(w http.ResponseWriter, r *http.Request) {
	payload, err := getPayload(w, r)
	if err != nil {
		log.Errorf("%v", err.Error())
		return
	}

	var request vcom.TpmRequestActivateCredParams
	if err := proto.Unmarshal(payload, &request); err != nil {
		log.Error(handleHTTPError(w, http.StatusBadRequest, "failed to unmarshal request: %v", err))
		return
	}
	ek, aik, name, err := tpmGetActivateCredentialParams(tpmutil.Handle(request.Index))
	if err != nil {
		log.Error(handleHTTPError(w, http.StatusInternalServerError, "failed to get activate credential params: %v", err))
		return
	}

	resp := vcom.TpmResponseActivateCredParams{
		Ek:      ek,
		AikPub:  aik,
		AikName: name,
	}
	out, err := proto.Marshal(&resp)
	if err != nil {
		log.Error(handleHTTPError(w, http.StatusInternalServerError, "failed to marshal response: %v", err))
		return
	}

	w.Header().Add("Content-Type", "application/x-proto-binary")
	w.WriteHeader(http.StatusOK)
	w.Write(out)
}

func handleActivateCred(w http.ResponseWriter, r *http.Request) {
	payload, err := getPayload(w, r)
	if err != nil {
		log.Errorf("%v", err.Error())
		return
	}

	var request vcom.TpmRequestGeneratedCred
	if err := proto.Unmarshal(payload, &request); err != nil {
		log.Error(handleHTTPError(w, http.StatusBadRequest, "failed to unmarshal request: %v", err))
		return
	}
	recoveredCred, err := tpmActivateCredential(tpmutil.Handle(request.AikIndex), request.Cred, request.Secret)
	if err != nil {
		log.Error(handleHTTPError(w, http.StatusInternalServerError, "failed to activate credential: %v", err))
		return
	}

	resp := vcom.TpmResponseActivatedCred{
		Secret: recoveredCred,
	}
	out, err := proto.Marshal(&resp)
	if err != nil {
		log.Error(handleHTTPError(w, http.StatusInternalServerError, "failed to marshal response: %v", err))
		return
	}

	w.Header().Add("Content-Type", "application/x-proto-binary")
	w.WriteHeader(http.StatusOK)
	w.Write(out)
}

func handleReadNV(w http.ResponseWriter, r *http.Request) {
	payload, err := getPayload(w, r)
	if err != nil {
		log.Errorf("failed to get payload : %s", err.Error())
		return
	}

	var request vcom.TpmRequestReadNv
	if err := proto.Unmarshal(payload, &request); err != nil {
		log.Error(handleHTTPError(w, http.StatusBadRequest, "failed to unmarshal request: %v", err))
		return
	}
	data, err := tpmReadNV(tpmutil.Handle(request.Index))
	if err != nil {
		log.Error(handleHTTPError(w, http.StatusInternalServerError, "failed to read NV: %v", err))
		return
	}

	response := vcom.TpmResponseReadNv{
		Data: data,
	}
	out, err := proto.Marshal(&response)
	if err != nil {
		log.Error(handleHTTPError(w, http.StatusInternalServerError, "failed to marshal response: %v", err))
		return
	}

	w.Header().Add("Content-Type", "application/x-proto-binary")
	w.WriteHeader(http.StatusOK)
	w.Write(out)
}

func handleSigner(w http.ResponseWriter, r *http.Request) {
	payload, err := getPayload(w, r)
	if err != nil {
		log.Errorf("%v", err.Error())
		return
	}

	var request vcom.TpmRequestSign
	if err := proto.Unmarshal(payload, &request); err != nil {
		log.Error(handleHTTPError(w, http.StatusBadRequest, "failed to unmarshal request: %v", err))
		return
	}
	sig, err := tpmSign(tpmutil.Handle(request.Index), request.Data)
	if err != nil {
		log.Error(handleHTTPError(w, http.StatusInternalServerError, "failed to sign data: %v", err))
		return
	}

	response := vcom.TpmResponseSign{
		Algorithm: sig.Alg.String(),
	}
	if sig.RSA != nil {
		if sig.RSA.Signature == nil {
			log.Error(handleHTTPError(w, http.StatusInternalServerError, "failed to sign data, null rsa signature"))
			return
		}
		response.RsaSignature = sig.RSA.Signature
		response.RsaHash = sig.RSA.HashAlg.String()
	}
	if sig.ECC != nil {
		if sig.ECC.R == nil || sig.ECC.S == nil {
			log.Error(handleHTTPError(w, http.StatusInternalServerError, "failed to sign data, null ecc signature"))
			return
		}
		response.EccSignatureR = sig.ECC.R.Bytes()
		response.EccSignatureS = sig.ECC.S.Bytes()
		response.EccHash = sig.ECC.HashAlg.String()
	}
	out, err := proto.Marshal(&response)
	if err != nil {
		log.Error(handleHTTPError(w, http.StatusInternalServerError, "failed to marshal response: %v", err))
		return
	}

	w.Header().Add("Content-Type", "application/x-proto-binary")
	w.WriteHeader(http.StatusOK)
	w.Write(out)
}

func handleGetPub(w http.ResponseWriter, r *http.Request) {
	payload, err := getPayload(w, r)
	if err != nil {
		log.Errorf("%v", err.Error())
		return
	}

	var request vcom.TpmRequestGetPub
	if err := proto.Unmarshal(payload, &request); err != nil {
		log.Error(handleHTTPError(w, http.StatusBadRequest, "failed to unmarshal request: %v", err))
		return
	}
	pub, err := tpmGetPub(tpmutil.Handle(request.Index))
	if err != nil {
		log.Error(handleHTTPError(w, http.StatusInternalServerError, "failed to get public key: %v", err))
		return
	}

	pubBytes, err := pub.Encode()
	if err != nil {
		log.Error(handleHTTPError(w, http.StatusInternalServerError, "failed to encode public key: %v", err))
		return
	}
	response := vcom.TpmResponseGetPub{
		Public:     pubBytes,
		Algorithm:  uint32(pub.Type),
		Attributes: uint32(pub.Attributes),
	}
	out, err := proto.Marshal(&response)
	if err != nil {
		log.Error(handleHTTPError(w, http.StatusInternalServerError, "failed to marshal response: %v", err))
		return
	}

	w.Header().Add("Content-Type", "application/x-proto-binary")
	w.WriteHeader(http.StatusOK)
	w.Write(out)
}

func getPayload(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.Method != http.MethodPost {
		err := fmt.Sprintf("Method %s not allowed", r.Method)
		http.Error(w, err, http.StatusMethodNotAllowed)
		return nil, errors.New(err)
	}

	// One larger to make sure we detect too large below.
	payload, err := io.ReadAll(io.LimitReader(r.Body, messageMaxSize+1))
	if err != nil {
		err := fmt.Sprintf("failed to read request body: %v", err)
		http.Error(w, err, http.StatusInternalServerError)
		return nil, errors.New(err)
	}

	if len(payload) >= messageMaxSize {
		err := fmt.Sprintf("request too large: %d", len(payload))
		http.Error(w, err, http.StatusBadRequest)
		return nil, errors.New(err)
	}

	return payload, nil
}

func handleHTTPError(w http.ResponseWriter, httpCode int, format string, a ...any) string {
	err := fmt.Sprintf(format, a...)
	http.Error(w, err, httpCode)
	return err
}
