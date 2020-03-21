// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Common routines for cipher information handling
// across multiple agents

package utils

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/cmd/tpmmgr"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// PrepareCipherCred : fill-in the plain-text credentials
func PrepareCipherCred(id, password string) zconfig.CredentialBlock {
	cred := zconfig.CredentialBlock{}
	if len(id) != 0 || len(password) != 0 {
		cred.Identity = id
		cred.Password = password
	}
	return cred
}

// GetCipherCredentials : decrypt credential block
func GetCipherCredentials(agentName string, status types.CipherBlockStatus,
	cred zconfig.CredentialBlock) (types.CipherBlockStatus, zconfig.CredentialBlock, error) {
	cipherBlock := new(types.CipherBlockStatus)
	*cipherBlock = status
	if !cipherBlock.IsCipher {
		return handleCipherBlockCredError(agentName, cipherBlock, cred, nil)
	}
	log.Infof("%s, cipherblock decryption, using cipher-context: %s\n",
		cipherBlock.Key(), cipherBlock.CipherContextID)
	if len(cipherBlock.Error) != 0 {
		errStr := fmt.Sprintf("%s, cipherblock is not ready, %s",
			cipherBlock.Key(), cipherBlock.Error)
		log.Errorln(errStr)
		err := errors.New(errStr)
		return handleCipherBlockCredError(agentName, cipherBlock, cred, err)
	}
	clearBytes, err := tpmmgr.DecryptCipherBlock(*cipherBlock)
	if err != nil {
		log.Errorf("%s, cipherblock decryption failed, %v\n",
			cipherBlock.Key(), err)
		return handleCipherBlockCredError(agentName, cipherBlock, cred, err)
	}
	if err := proto.Unmarshal(clearBytes, &cred); err != nil {
		log.Errorf("%s, credential unmarshall failed, %v\n",
			cipherBlock.Key(), err)
		return handleCipherBlockCredError(agentName, cipherBlock, cred, err)
	}
	if err == nil {
		log.Infof("%s, cipherblock decryption successful\n",
			cipherBlock.Key())
	}
	return *cipherBlock, cred, err
}

// GetCipherData : decrypt plain text
func GetCipherData(agentName string, status types.CipherBlockStatus,
	data *string) (types.CipherBlockStatus, *string, error) {
	cipherBlock := new(types.CipherBlockStatus)
	*cipherBlock = status
	if !cipherBlock.IsCipher {
		return handleCipherBlockError(agentName, cipherBlock, data, nil)
	}
	log.Infof("%s, cipherblock decryption, using cipher-context: %s\n",
		cipherBlock.Key(), cipherBlock.CipherContextID)
	if len(cipherBlock.Error) != 0 {
		errStr := fmt.Sprintf("%s, cipherblock is not ready, %s",
			cipherBlock.Key(), cipherBlock.Error)
		log.Errorln(errStr)
		err := errors.New(errStr)
		return handleCipherBlockError(agentName, cipherBlock, data, err)
	}
	clearBytes, err := tpmmgr.DecryptCipherBlock(*cipherBlock)
	if err != nil {
		log.Errorf("%s, cipherblock decryption failed, %v\n",
			cipherBlock.Key(), err)
		return handleCipherBlockError(agentName, cipherBlock, data, err)
	}
	clearText := base64.StdEncoding.EncodeToString(clearBytes)
	return *cipherBlock, &clearText, err
}

// incase, processing fails for cipher information received from controller,
// try to return valid plain-text data for further processing

// for credential block
func handleCipherBlockCredError(agentName string, status *types.CipherBlockStatus,
	cred zconfig.CredentialBlock, err error) (types.CipherBlockStatus, zconfig.CredentialBlock, error) {
	if err != nil {
		errStr := fmt.Sprintf("%v", err)
		status.SetErrorInfo(agentName, errStr)
		// we have already captured the error info above
		// for valid cred info, reset the error to proceed
		if len(cred.Identity) != 0 || len(cred.Password) != 0 {
			err = nil
		}
	}
	return *status, cred, err
}

// for plain text data
func handleCipherBlockError(agentName string, status *types.CipherBlockStatus,
	data *string, err error) (types.CipherBlockStatus, *string, error) {
	if err != nil {
		errStr := fmt.Sprintf("%v", err)
		status.SetErrorInfo(agentName, errStr)
		// we have already captured the error info above
		// for valid data, reset the error to proceed
		if data != nil {
			err = nil
		}
	}
	return *status, data, err
}
