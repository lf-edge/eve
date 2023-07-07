// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/gorilla/websocket"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const hashBytesNum = 32 // Hmac Sha256 Hash is 32 bytes fixed

var (
	nonceOpEncrption bool
	nonceHash        [32]byte // JWT Nonce with Sha256Sum for encryption
	viBytes          [16]byte // vi 16 bytes data for encryption
	jwtNonce         string   // JWT session Nonce for authentication
)

// authentication/encryption wrapper for messages
type envelopeMsg struct {
	Message    []byte             `json:"message"`
	Sha256Hash [hashBytesNum]byte `json:"sha256Hash"`
}

// sign with JWT nonce on message data and send through websocket
func addEnvelopeAndWriteWss(msg []byte, isText bool) error {
	var jdata []byte
	if nonceOpEncrption {
		jdata = encryptData(msg)
	} else {
		jdata = signAuthenData(msg)
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
	err := websocketConn.WriteMessage(msgType, jdata)
	wssWrMutex.Unlock()
	return err
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
func verifyEnvelopeData(data []byte) (bool, bool, []byte) {
	var envelope envelopeMsg
	err := json.Unmarshal(data, &envelope)
	if err != nil {
		return false, false, nil
	}

	if nonceOpEncrption {
		ok, msg := decryptEvMsg(envelope.Message)
		if !ok {
			return true, false, nil
		}
		shaSum := sha256.Sum256(msg)
		if !bytes.Equal(envelope.Sha256Hash[:], shaSum[:]) {
			return true, false, nil
		}
		return true, true, msg
	}

	h := hmac.New(sha256.New, []byte(jwtNonce))
	_, _ = h.Write(envelope.Message)
	if !bytes.Equal(envelope.Sha256Hash[:], h.Sum(nil)) {
		log.Noticef("Verify failed")
		return true, false, nil
	}

	return true, true, envelope.Message
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
