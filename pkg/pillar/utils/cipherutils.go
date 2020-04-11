// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Common routines for cipher information handling
// across multiple agents

package utils

import (
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"

	"github.com/golang/protobuf/proto"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/cmd/tpmmgr"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// GetCipherCredentials : decrypt encryption block
func GetCipherCredentials(agentName string, status types.CipherBlockStatus) (types.CipherBlockStatus,
	zconfig.EncryptionBlock, error) {
	cipherBlock := new(types.CipherBlockStatus)
	*cipherBlock = status
	var decBlock zconfig.EncryptionBlock
	if !cipherBlock.IsCipher {
		return handleCipherBlockCredError(agentName, cipherBlock, decBlock, nil)
	}
	log.Infof("%s, cipherblock decryption, using cipher-context: %s\n",
		cipherBlock.Key(), cipherBlock.CipherContextID)
	if len(cipherBlock.Error) != 0 {
		errStr := fmt.Sprintf("%s, cipherblock is not ready, %s",
			cipherBlock.Key(), cipherBlock.Error)
		log.Errorln(errStr)
		err := errors.New(errStr)
		return handleCipherBlockCredError(agentName, cipherBlock, decBlock, err)
	}
	clearBytes, err := tpmmgr.DecryptCipherBlock(*cipherBlock)
	if err != nil {
		log.Errorf("%s, cipherblock decryption failed, %v\n",
			cipherBlock.Key(), err)
		return handleCipherBlockCredError(agentName, cipherBlock, decBlock, err)
	}
	if err := proto.Unmarshal(clearBytes, &decBlock); err != nil {
		log.Errorf("%s, encryption block unmarshall failed, %v\n",
			cipherBlock.Key(), err)
		return handleCipherBlockCredError(agentName, cipherBlock, decBlock, err)
	}
	if err == nil {
		log.Infof("%s, cipherblock decryption successful\n",
			cipherBlock.Key())
	}
	return *cipherBlock, decBlock, err
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
// for encryption block
func handleCipherBlockCredError(agentName string, status *types.CipherBlockStatus,
	decBlock zconfig.EncryptionBlock, err error) (types.CipherBlockStatus, zconfig.EncryptionBlock, error) {
	if err != nil {
		errStr := fmt.Sprintf("%v", err)
		status.SetErrorInfo(agentName, errStr)
		// we have already captured the error info above
		// for valid encryption block info, reset the error to proceed
		if !reflect.DeepEqual(decBlock, zconfig.EncryptionBlock{}) {
			err = nil
		}
	}
	return *status, decBlock, err
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
