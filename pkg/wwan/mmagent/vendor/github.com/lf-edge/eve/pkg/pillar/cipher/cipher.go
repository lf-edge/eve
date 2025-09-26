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

	zcommon "github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"google.golang.org/protobuf/proto"
)

func getEncryptionBlock(
	zconfigDecBlockPtr *zcommon.EncryptionBlock) types.EncryptionBlock {
	var decBlock types.EncryptionBlock
	decBlock.DsAPIKey = zconfigDecBlockPtr.DsAPIKey
	decBlock.DsPassword = zconfigDecBlockPtr.DsPassword
	decBlock.WifiUserName = zconfigDecBlockPtr.WifiUserName
	decBlock.WifiPassword = zconfigDecBlockPtr.WifiPassword
	decBlock.CellularNetUsername = zconfigDecBlockPtr.CellularNetUsername
	decBlock.CellularNetPassword = zconfigDecBlockPtr.CellularNetPassword
	decBlock.CellularNetAttachUsername = zconfigDecBlockPtr.CellularNetAttachUsername
	decBlock.CellularNetAttachPassword = zconfigDecBlockPtr.CellularNetAttachPassword
	decBlock.ProtectedUserData = zconfigDecBlockPtr.ProtectedUserData
	decBlock.ClusterToken = zconfigDecBlockPtr.ClusterToken
	decBlock.GzipRegistrationManifestYaml = zconfigDecBlockPtr.GzipRegistrationManifestYaml
	return decBlock
}

// GetCipherCredentials : decrypt encryption block
func GetCipherCredentials(ctx *DecryptCipherContext,
	status types.CipherBlockStatus) (types.CipherBlockStatus, types.EncryptionBlock, error) {
	var decBlock types.EncryptionBlock
	cipherBlock, clearBytes, err := GetCipherMarshalledData(ctx, status)
	if err != nil {
		return handleCipherBlockCredError(ctx, &cipherBlock,
			decBlock, err, types.DecryptFailed)
	}

	var zconfigDecBlock zcommon.EncryptionBlock
	err = UnmarshalCipherData(ctx, clearBytes, &zconfigDecBlock)
	if err != nil {
		ctx.Log.Errorf("%s, encryption block unmarshall failed, %v\n",
			cipherBlock.Key(), err)
		return handleCipherBlockCredError(ctx, &cipherBlock,
			decBlock, err, types.UnmarshalFailed)
	}
	ctx.Log.Functionf("%s, cipherblock decryption successful", cipherBlock.Key())
	decBlock = getEncryptionBlock(&zconfigDecBlock)
	ctx.AgentMetrics.RecordSuccess(ctx.Log)
	return cipherBlock, decBlock, err
}

// GetCipherMarshalledData : decrypt encryption block, without assuming the proto
// encoding data is zcommon.EncryptionBlock, since the data before encryption may have
// its own data structure, it is up to the caller to unmarshal the data using
// 'UnmarshalCipherData' function. Future use cases may not need to add a new
// item in the EncryptionBLock.
func GetCipherMarshalledData(ctx *DecryptCipherContext,
	status types.CipherBlockStatus) (types.CipherBlockStatus, []byte, error) {
	cipherBlock := new(types.CipherBlockStatus)
	*cipherBlock = status
	var decBlock types.EncryptionBlock
	if !cipherBlock.IsCipher {
		// Should not be called if IsCipher is not set
		cblock, _, err := handleCipherBlockCredError(ctx, cipherBlock,
			decBlock, nil, types.Invalid)
		return cblock, nil, err
	}
	ctx.Log.Functionf("%s, cipherblock decryption, using cipher-context: %s\n",
		cipherBlock.Key(), cipherBlock.CipherContextID)
	if len(cipherBlock.Error) != 0 {
		errStr := fmt.Sprintf("%s, cipherblock is not ready, %s",
			cipherBlock.Key(), cipherBlock.Error)
		ctx.Log.Errorln(errStr)
		err := errors.New(errStr)
		cblock, _, err := handleCipherBlockCredError(ctx, cipherBlock,
			decBlock, err, types.NotReady)
		return cblock, nil, err
	}
	clearBytes, err := DecryptCipherBlock(ctx, *cipherBlock)
	if err != nil {
		ctx.Log.Errorf("%s, cipherblock decryption failed, %v\n",
			cipherBlock.Key(), err)
		cblock, _, err := handleCipherBlockCredError(ctx, cipherBlock,
			decBlock, nil, types.Invalid)
		return cblock, nil, err
	}

	return *cipherBlock, clearBytes, err
}

// UnmarshalCipherData generalizes the unmarshalling of cipher data into different Go data structures.
func UnmarshalCipherData(ctx *DecryptCipherContext, clearBytes []byte, out proto.Message) error {
	err := proto.Unmarshal(clearBytes, out)
	if err != nil {
		ctx.Log.Errorf("encryption block unmarshall failed, %v\n", err)
		return fmt.Errorf("failed to unmarshal cipher block: %w", err)
	}
	ctx.Log.Functionf("cipherblock decryption successful")
	return nil
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

// in case processing fails for cipher information received from controller,
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
