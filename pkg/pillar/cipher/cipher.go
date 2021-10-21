// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Common routines for cipher information handling
// across multiple agents

package cipher

import (
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"

	"github.com/golang/protobuf/proto"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func getEncryptionBlock(
	zconfigDecBlockPtr *zconfig.EncryptionBlock) types.EncryptionBlock {
	var decBlock types.EncryptionBlock
	decBlock.DsAPIKey = zconfigDecBlockPtr.DsAPIKey
	decBlock.DsPassword = zconfigDecBlockPtr.DsPassword
	decBlock.WifiUserName = zconfigDecBlockPtr.WifiUserName
	decBlock.WifiPassword = zconfigDecBlockPtr.WifiPassword
	decBlock.ProtectedUserData = zconfigDecBlockPtr.ProtectedUserData
	return decBlock
}

// GetCipherCredentials : decrypt encryption block
func GetCipherCredentials(ctx *DecryptCipherContext,
	status types.CipherBlockStatus) (types.CipherBlockStatus, types.EncryptionBlock, error) {
	cipherBlock := new(types.CipherBlockStatus)
	*cipherBlock = status
	var decBlock types.EncryptionBlock
	if !cipherBlock.IsCipher {
		// Should not be called if IsCipher is not set
		return handleCipherBlockCredError(ctx, cipherBlock,
			decBlock, nil, types.Invalid)
	}
	ctx.Log.Functionf("%s, cipherblock decryption, using cipher-context: %s\n",
		cipherBlock.Key(), cipherBlock.CipherContextID)
	if len(cipherBlock.Error) != 0 {
		errStr := fmt.Sprintf("%s, cipherblock is not ready, %s",
			cipherBlock.Key(), cipherBlock.Error)
		ctx.Log.Errorln(errStr)
		err := errors.New(errStr)
		return handleCipherBlockCredError(ctx, cipherBlock,
			decBlock, err, types.NotReady)
	}
	clearBytes, err := DecryptCipherBlock(ctx, *cipherBlock)
	if err != nil {
		ctx.Log.Errorf("%s, cipherblock decryption failed, %v\n",
			cipherBlock.Key(), err)
		return handleCipherBlockCredError(ctx, cipherBlock,
			decBlock, err, types.DecryptFailed)
	}

	var zconfigDecBlock zconfig.EncryptionBlock
	err = proto.Unmarshal(clearBytes, &zconfigDecBlock)
	if err != nil {
		ctx.Log.Errorf("%s, encryption block unmarshall failed, %v\n",
			cipherBlock.Key(), err)
		return handleCipherBlockCredError(ctx, cipherBlock,
			decBlock, err, types.UnmarshalFailed)
	}
	ctx.Log.Functionf("%s, cipherblock decryption successful", cipherBlock.Key())
	decBlock = getEncryptionBlock(&zconfigDecBlock)
	ctx.AgentMetrics.RecordSuccess(ctx.Log)
	return *cipherBlock, decBlock, err
}

// GetCipherData : decrypt plain text
func GetCipherData(ctx *DecryptCipherContext, status types.CipherBlockStatus,
	data *string) (types.CipherBlockStatus, *string, error) {
	cipherBlock := new(types.CipherBlockStatus)
	*cipherBlock = status
	if !cipherBlock.IsCipher {
		return handleCipherBlockError(ctx.AgentName, cipherBlock, data, nil)
	}
	ctx.Log.Functionf("%s, cipherblock decryption, using cipher-context: %s\n",
		cipherBlock.Key(), cipherBlock.CipherContextID)
	if len(cipherBlock.Error) != 0 {
		errStr := fmt.Sprintf("%s, cipherblock is not ready, %s",
			cipherBlock.Key(), cipherBlock.Error)
		ctx.Log.Errorln(errStr)
		err := errors.New(errStr)
		return handleCipherBlockError(ctx.AgentName, cipherBlock, data, err)
	}
	clearBytes, err := DecryptCipherBlock(ctx, *cipherBlock)
	if err != nil {
		ctx.Log.Errorf("%s, cipherblock decryption failed, %v\n",
			cipherBlock.Key(), err)
		return handleCipherBlockError(ctx.AgentName, cipherBlock, data, err)
	}
	clearText := base64.StdEncoding.EncodeToString(clearBytes)
	return *cipherBlock, &clearText, err
}

// incase, processing fails for cipher information received from controller,
// try to return valid plain-text data for further processing
// for encryption block
func handleCipherBlockCredError(ctx *DecryptCipherContext, status *types.CipherBlockStatus,
	decBlock types.EncryptionBlock, err error, errtype types.CipherError) (types.CipherBlockStatus, types.EncryptionBlock, error) {

	ctx.AgentMetrics.RecordFailure(ctx.Log, errtype)
	if err != nil {
		status.SetErrorNow(err.Error())
		// we have already captured the error info above
		// for valid encryption block info, reset the error to proceed
		if !reflect.DeepEqual(decBlock, types.EncryptionBlock{}) {
			err = nil
		}
	}
	return *status, decBlock, err
}

// for plain text data
func handleCipherBlockError(agentName string, status *types.CipherBlockStatus,
	data *string, err error) (types.CipherBlockStatus, *string, error) {
	if err != nil {
		status.SetErrorNow(err.Error())
		// we have already captured the error info above
		// for valid data, reset the error to proceed
		if data != nil {
			err = nil
		}
	}
	return *status, data, err
}
