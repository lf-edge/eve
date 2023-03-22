// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

// all things related to running remote attestation with the Controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"

	eventlog "github.com/cshari-zededa/eve-tpm2-tools/eventlog"
	"github.com/lf-edge/eve/api/go/attest"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	zattest "github.com/lf-edge/eve/pkg/pillar/attest"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/vault"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	"google.golang.org/protobuf/proto"
)

const (
	attestWdName            = agentName + "attest"
	eventLogBinarySizeLimit = 2048  // 2KB
	maxQuotePayloadSize     = 63488 // 62KB
)

// TpmAgentImpl implements zattest.TpmAgent interface
type TpmAgentImpl struct{}

// VerifierImpl implements zattest.Verifier interface
type VerifierImpl struct{}

// WatchdogImpl implements zattest.Watchdog interface
type WatchdogImpl struct{}

// Attest Information Context
type attestContext struct {
	zedagentCtx                   *zedagentContext
	attestFsmCtx                  *zattest.Context
	pubAttestNonce                pubsub.Publication
	pubEncryptedKeyFromController pubsub.Publication
	//Nonce for the current attestation cycle
	Nonce []byte
	//Quote for the current attestation cycle
	InternalQuote *types.AttestQuote
	//Data to be escrowed with Controller
	EscrowData []byte
	//Indicates that we can skip escrow send
	SkipEscrow bool
	//Iteration keeps track of retry count
	Iteration int
	// Started indicates that attest module was started
	Started bool
	//EventLogEntries are the TPM EventLog entries
	EventLogEntries []eventlog.Event
	//EventLogParseErr stores any error that happened during EventLog parsing
	EventLogParseErr error
}

const (
	watchdogInterval  = 15
	retryTimeInterval = 15
	//EventLogPath is the TPM measurement log aka TPM event log
	EventLogPath = "/sys/kernel/security/tpm0/binary_bios_measurements"
)

// One shot send, if fails, return an error to the state machine to retry later
func trySendToController(attestReq *attest.ZAttestReq, attestCtx *attestContext) (zedcloud.SendRetval, error) {
	log.Noticef("trySendToController type %d", attestReq.ReqType)
	data, err := proto.Marshal(attestReq)
	if err != nil {
		log.Fatal("SendInfoProtobufStr proto marshaling error: ", err)
	}

	buf := bytes.NewBuffer(data)
	size := int64(proto.Size(attestReq))
	attestURL := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API,
		devUUID, "attest")
	ctxWork, cancel := zedcloud.GetContextForAllIntfFunctions(zedcloudCtx)
	defer cancel()
	const bailOnHTTPErr = true
	const withNetTracing = false
	rv, err := zedcloud.SendOnAllIntf(ctxWork, zedcloudCtx, attestURL, size, buf,
		attestCtx.Iteration, bailOnHTTPErr, withNetTracing)
	if err != nil || len(rv.RespContents) == 0 {
		// Error case handled below
	} else {
		err = zedcloud.RemoveAndVerifyAuthContainer(zedcloudCtx, &rv, false)
	}
	switch rv.Status {
	case types.SenderStatusCertMiss, types.SenderStatusCertInvalid:
		// trigger to acquire new controller certs from cloud
		log.Noticef("%s trigger", rv.Status.String())
		triggerControllerCertEvent(attestCtx.zedagentCtx)
	}
	return rv, err
}

// setAttestErrorAndTriggerInfo sets errorDescription on zattest.Context,
// triggers publishing of device info
func setAttestErrorAndTriggerInfo(ctx *zattest.Context, errorDescription types.ErrorDescription) {
	ctx.SetErrorDescription(errorDescription)
	attestCtx, ok := ctx.OpaqueCtx.(*attestContext)
	if !ok {
		log.Fatalf("[ATTEST] Unexpected type from opaque ctx: %T",
			ctx.OpaqueCtx)
	}
	triggerPublishDevInfo(attestCtx.zedagentCtx)
}

// SendNonceRequest implements SendNonceRequest method of zattest.Verifier
func (server *VerifierImpl) SendNonceRequest(ctx *zattest.Context) error {
	if ctx.OpaqueCtx == nil {
		log.Fatalf("[ATTEST] Uninitialized access to OpaqueCtx")
	}
	attestCtx, ok := ctx.OpaqueCtx.(*attestContext)
	if !ok {
		log.Fatalf("[ATTEST] Unexpected type from opaque ctx: %T",
			ctx.OpaqueCtx)
	}
	if len(attestCtx.Nonce) > 0 {
		//Clear existing nonce before attempting another nonce request
		unpublishAttestNonce(attestCtx)
		attestCtx.Nonce = nil
	}
	var attestReq = &attest.ZAttestReq{}

	// bail if V2API is not supported
	if !zedcloud.UseV2API() {
		return zattest.ErrNoVerifier
	}

	attestReq.ReqType = attest.ZAttestReqType_ATTEST_REQ_NONCE

	//Increment Iteration for interface rotation
	attestCtx.Iteration++
	log.Tracef("Sending Nonce request %v", attestReq)

	rv, err := trySendToController(attestReq, attestCtx)
	if err != nil || rv.Status != types.SenderStatusNone {
		errorDescription := types.ErrorDescription{
			Error: fmt.Sprintf("[ATTEST] Error %v, senderStatus %v",
				err, rv.Status),
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrControllerReqFailed
	}

	attestResp := &attest.ZAttestResponse{}
	if err := proto.Unmarshal(rv.RespContents, attestResp); err != nil {
		errorDescription := types.ErrorDescription{
			Error: fmt.Sprintf("[ATTEST] Error %v in Unmarshaling nonce response", err),
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrControllerReqFailed
	}

	respType := attestResp.GetRespType()
	if respType != attest.ZAttestRespType_ATTEST_RESP_NONCE {
		errorDescription := types.ErrorDescription{
			Error: fmt.Sprintf("[ATTEST] Got %v, but want %v",
				respType, attest.ZAttestRespType_ATTEST_RESP_NONCE),
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrControllerReqFailed
	}

	if nonceResp := attestResp.GetNonce(); nonceResp == nil {
		errorDescription := types.ErrorDescription{
			Error: "[ATTEST] Got empty nonce response",
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrControllerReqFailed
	} else {
		attestCtx.Nonce = nonceResp.GetNonce()
		ctx.ClearError()
		triggerPublishDevInfo(attestCtx.zedagentCtx)
	}

	return nil
}

func combineBiosFields(biosVendor, biosVersion, biosReleaseDate string) string {
	biosStr := ""
	if biosVendor != "" {
		biosStr = biosVendor
	}
	if biosVersion != "" {
		if biosStr != "" {
			biosStr = biosStr + "-" + biosVersion
		} else {
			biosStr = biosVersion
		}

	}
	if biosReleaseDate != "" {
		if biosStr != "" {
			biosStr = biosStr + "-" + biosReleaseDate
		} else {
			biosStr = biosReleaseDate
		}
	}
	return biosStr
}

// encodeVersions fetches EVE, UEFI versions
func encodeVersions(quoteMsg *attest.ZAttestQuote) error {
	quoteMsg.Versions = make([]*attest.AttestVersionInfo, 0)
	eveVersion := new(attest.AttestVersionInfo)
	eveVersion.VersionType = attest.AttestVersionType_ATTEST_VERSION_TYPE_EVE
	eveRelease, err := os.ReadFile(types.EveVersionFile)
	if err != nil {
		return err
	}
	eveVersion.Version = strings.TrimSpace(string(eveRelease))
	quoteMsg.Versions = append(quoteMsg.Versions, eveVersion)

	//GetDeviceBios returns empty values on ARM64, check for them
	bVendor, bVersion, bReleaseDate := hardware.GetDeviceBios(log)
	biosVendor := strings.TrimSpace(bVendor)
	biosVersion := strings.TrimSpace(bVersion)
	biosReleaseDate := strings.TrimSpace(bReleaseDate)
	biosStr := combineBiosFields(biosVendor, biosVersion, biosReleaseDate)
	if biosStr != "" {
		uefiVersion := new(attest.AttestVersionInfo)
		uefiVersion.VersionType = attest.AttestVersionType_ATTEST_VERSION_TYPE_FIRMWARE
		uefiVersion.Version = biosStr
		quoteMsg.Versions = append(quoteMsg.Versions, uefiVersion)
		log.Functionf("quoteMsg.Versions %s %s", eveVersion.Version, uefiVersion.Version)
	}
	return nil
}

// encodePCRValues encodes PCR values from types.AttestQuote into attest.ZAttestQuote
func encodePCRValues(internalQuote *types.AttestQuote, quoteMsg *attest.ZAttestQuote) error {
	quoteMsg.PcrValues = make([]*attest.TpmPCRValue, 0)
	for _, pcr := range internalQuote.PCRs {
		pcrValue := new(attest.TpmPCRValue)
		pcrValue.Index = uint32(pcr.Index)
		switch pcr.Algo {
		case types.PCRExtendHashAlgoSha1:
			pcrValue.HashAlgo = attest.TpmHashAlgo_TPM_HASH_ALGO_SHA1
		case types.PCRExtendHashAlgoSha256:
			pcrValue.HashAlgo = attest.TpmHashAlgo_TPM_HASH_ALGO_SHA256
		default:
			return fmt.Errorf("Unknown Hash Algo in PCR Digest %d",
				pcr.Index)
		}
		pcrValue.Value = pcr.Digest
		quoteMsg.PcrValues = append(quoteMsg.PcrValues, pcrValue)
	}
	//XXX Check for TPM platform, and if so, insist on non-empty quoteMsg.PCRValues
	return nil
}

// SendAttestQuote implements SendAttestQuote method of zattest.Verifier
func (server *VerifierImpl) SendAttestQuote(ctx *zattest.Context) error {
	if ctx.OpaqueCtx == nil {
		log.Fatalf("[ATTEST] Uninitialized access to OpaqueCtx")
	}
	attestCtx, ok := ctx.OpaqueCtx.(*attestContext)
	if !ok {
		log.Fatalf("[ATTEST] Unexpected type from opaque ctx: %T",
			ctx.OpaqueCtx)
	}
	var attestReq = &attest.ZAttestReq{}

	// bail if V2API is not supported
	if !zedcloud.UseV2API() {
		return zattest.ErrNoVerifier
	}

	attestReq.ReqType = attest.ZAttestReqType_ATTEST_REQ_QUOTE
	//XXX Fill GPS info, Version, Eventlog fields later
	quote := &attest.ZAttestQuote{
		AttestData: attestCtx.InternalQuote.Quote,
		Signature:  attestCtx.InternalQuote.Signature,
	}

	if err := encodePCRValues(attestCtx.InternalQuote, quote); err != nil {
		errorDescription := types.ErrorDescription{
			Error: fmt.Sprintf("[ATTEST] encodePCRValues failed with err %v", err),
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrControllerReqFailed
	}

	if err := encodeVersions(quote); err != nil {
		errorDescription := types.ErrorDescription{
			Error: fmt.Sprintf("[ATTEST] encodeVersions failed with err %v", err),
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrControllerReqFailed
	}

	attestReq.Quote = quote

	if attestCtx.EventLogParseErr == nil {
		//On some platforms, either the kernel does not export TPM Eventlog
		//or the TPM does not have SHA256 bank enabled for PCRs. We populate
		//eventlog if we are able to parse eventlog successfully
		encodeEventLog(attestCtx, attestReq.Quote)

		if len(attestReq.Quote.EventLog) > 0 && proto.Size(attestReq) > maxQuotePayloadSize {
			log.Errorf("[ATTEST] attestReq size too much (%d) will remove large binaries", proto.Size(attestReq))
			cleanupEventLog(attestReq.Quote)
		}
	}

	//Increment Iteration for interface rotation
	attestCtx.Iteration++
	log.Tracef("Sending Quote request")
	recordAttestationTry(attestCtx.zedagentCtx)

	rv, err := trySendToController(attestReq, attestCtx)
	if err != nil || rv.Status != types.SenderStatusNone {
		errorDescription := types.ErrorDescription{
			Error: fmt.Sprintf("[ATTEST] Error %v, senderStatus %v",
				err, rv.Status),
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrControllerReqFailed
	}

	attestResp := &attest.ZAttestResponse{}
	if err := proto.Unmarshal(rv.RespContents, attestResp); err != nil {
		errorDescription := types.ErrorDescription{
			Error: fmt.Sprintf("[ATTEST] Error %v in Unmarshaling quote response", err),
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrControllerReqFailed
	}

	respType := attestResp.GetRespType()
	if respType != attest.ZAttestRespType_ATTEST_RESP_QUOTE_RESP {
		errorDescription := types.ErrorDescription{
			Error: fmt.Sprintf("[ATTEST] Got %v, but want %v",
				respType, attest.ZAttestRespType_ATTEST_RESP_QUOTE_RESP),
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrControllerReqFailed
	}

	var quoteResp *attest.ZAttestQuoteResp
	if quoteResp = attestResp.GetQuoteResp(); quoteResp == nil {
		errorDescription := types.ErrorDescription{
			Error: "[ATTEST] Got empty quote response",
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrControllerReqFailed
	}
	quoteRespCode := quoteResp.GetResponse()
	switch quoteRespCode {
	case attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_INVALID:
		errorDescription := types.ErrorDescription{
			Error: "[ATTEST] Invalid response code",
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrControllerReqFailed
	case attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_SUCCESS:
		//Retrieve integrity token
		storeIntegrityToken(quoteResp.GetIntegrityToken())
		log.Notice("[ATTEST] Attestation successful, processing keys given by Controller")
		publishedStorageKeys := 0
		if encryptedKeys := quoteResp.GetKeys(); encryptedKeys != nil {
			for _, sk := range encryptedKeys {
				encryptedKeyType := sk.GetKeyType()
				encryptedKey := sk.GetKey()
				if encryptedKeyType == attest.AttestVolumeKeyType_ATTEST_VOLUME_KEY_TYPE_VSK {
					// it is not expected and may affect vaultmgr cleanup
					if len(encryptedKey) == 0 {
						log.Errorf("[ATTEST] received empty Controller-given encrypted key")
						continue
					}
					publishEncryptedKeyFromController(attestCtx, encryptedKey)
					log.Noticef("[ATTEST] published Controller-given encrypted key")
					publishedStorageKeys++
				}
			}
		}
		// if no storage keys come from the controller
		// then send empty key instead to vaultmgr
		// it is expected on first communication with the controller
		// to receive no keys
		if publishedStorageKeys == 0 {
			log.Noticeln("[ATTEST] no storage keys received from controller")
			publishEncryptedKeyFromController(attestCtx, nil)
		}
		ctx.ClearError()
		triggerPublishDevInfo(attestCtx.zedagentCtx)
		return nil
	case attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_NONCE_MISMATCH:
		errorDescription := types.ErrorDescription{
			Error: "[ATTEST] Nonce Mismatch",
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrNonceMismatch
	case attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_NO_CERT_FOUND:
		errorDescription := types.ErrorDescription{
			Error: "[ATTEST] Controller yet to receive signing cert",
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrNoCertYet
	case attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_QUOTE_FAILED:
		errorDescription := types.ErrorDescription{
			Error: "[ATTEST] Quote Mismatch",
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrQuoteMismatch
	default:
		errorDescription := types.ErrorDescription{
			Error: "[ATTEST] Unknown quoteRespCode %v",
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrControllerReqFailed
	}
}

// SendAttestEscrow implements SendAttestEscrow method of zattest.Verifier
func (server *VerifierImpl) SendAttestEscrow(ctx *zattest.Context) error {
	if ctx.OpaqueCtx == nil {
		log.Fatalf("[ATTEST] Uninitialized access to OpaqueCtx")
	}
	attestCtx, ok := ctx.OpaqueCtx.(*attestContext)
	if !ok {
		log.Fatalf("[ATTEST] Unexpected type from opaque ctx: %T",
			ctx.OpaqueCtx)
	}
	// bail if V2API is not supported
	if !zedcloud.UseV2API() {
		return zattest.ErrNoVerifier
	}
	if attestCtx.SkipEscrow {
		log.Notice("[ATTEST] Escrow successful skipped")
		return nil
	}
	if attestCtx.EscrowData == nil {
		errorDescription := types.ErrorDescription{Error: "[ATTEST] No escrow data"}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrNoEscrowData
	}

	escrowMsg := &attest.AttestStorageKeys{}
	escrowMsg.Keys = make([]*attest.AttestVolumeKey, 0)
	key := new(attest.AttestVolumeKey)
	key.KeyType = attest.AttestVolumeKeyType_ATTEST_VOLUME_KEY_TYPE_VSK
	key.Key = attestCtx.EscrowData
	escrowMsg.Keys = append(escrowMsg.Keys, key)
	if b, err := readIntegrityToken(); err == nil {
		escrowMsg.IntegrityToken = b
	}
	var attestReq = &attest.ZAttestReq{}
	attestReq.ReqType = attest.ZAttestReqType_Z_ATTEST_REQ_TYPE_STORE_KEYS
	attestReq.StorageKeys = escrowMsg

	//Increment Iteration for interface rotation
	attestCtx.Iteration++
	log.Noticef("[ATTEST] Sending Escrow data len %d", len(key.Key))

	rv, err := trySendToController(attestReq, attestCtx)
	if err != nil || rv.Status != types.SenderStatusNone {
		errorDescription := types.ErrorDescription{
			Error: fmt.Sprintf("[ATTEST] Error %v, senderStatus %v", err, rv.Status),
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrControllerReqFailed
	}
	attestResp := &attest.ZAttestResponse{}
	if err := proto.Unmarshal(rv.RespContents, attestResp); err != nil {
		errorDescription := types.ErrorDescription{
			Error: fmt.Sprintf("[ATTEST] Error %v in Unmarshaling storage keys response", err),
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrControllerReqFailed
	}

	respType := attestResp.GetRespType()
	if respType != attest.ZAttestRespType_Z_ATTEST_RESP_TYPE_STORE_KEYS {
		errorDescription := types.ErrorDescription{
			Error: fmt.Sprintf("[ATTEST] Got %v, but want %v",
				respType, attest.ZAttestRespType_Z_ATTEST_RESP_TYPE_STORE_KEYS),
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrControllerReqFailed
	}

	var escrowResp *attest.AttestStorageKeysResp
	if escrowResp = attestResp.GetStorageKeysResp(); escrowResp == nil {
		errorDescription := types.ErrorDescription{
			Error: "[ATTEST] Got empty storage keys response",
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrControllerReqFailed
	}
	escrowRespCode := escrowResp.GetResponse()
	switch escrowRespCode {
	case attest.AttestStorageKeysResponseCode_ATTEST_STORAGE_KEYS_RESPONSE_CODE_INVALID:
		errorDescription := types.ErrorDescription{
			Error: "[ATTEST] Invalid response code",
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrControllerReqFailed
	case attest.AttestStorageKeysResponseCode_ATTEST_STORAGE_KEYS_RESPONSE_CODE_ITOKEN_MISMATCH:
		errorDescription := types.ErrorDescription{
			Error: "[ATTEST] Integrity Token Mismatch",
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrITokenMismatch
	case attest.AttestStorageKeysResponseCode_ATTEST_STORAGE_KEYS_RESPONSE_CODE_SUCCESS:
		log.Notice("[ATTEST] Escrow successful")
		ctx.ClearError()
		triggerPublishDevInfo(attestCtx.zedagentCtx)
		// we sent storage keys successfully
		// and do not allow to clean vault
		if err := vault.DisallowVaultCleanup(); err != nil {
			log.Errorf("cannot disallow vault cleanup: %s", err)
		}
		return nil
	default:
		errorDescription := types.ErrorDescription{
			Error: fmt.Sprintf("[ATTEST] Unknown escrowRespCode %v", escrowRespCode),
		}
		log.Error(errorDescription.Error)
		setAttestErrorAndTriggerInfo(ctx, errorDescription)
		return zattest.ErrControllerReqFailed
	}
}

// SendInternalQuoteRequest implements SendInternalQuoteRequest method of zattest.TpmAgent
func (agent *TpmAgentImpl) SendInternalQuoteRequest(ctx *zattest.Context) error {
	if ctx.OpaqueCtx == nil {
		log.Fatalf("[ATTEST] Uninitialized access to OpaqueCtx")
	}
	attestCtx, ok := ctx.OpaqueCtx.(*attestContext)
	if !ok {
		log.Fatalf("[ATTEST] Unexpected type from opaque ctx: %T",
			ctx.OpaqueCtx)
	}

	//Clear existing quote before requesting a new one
	if attestCtx.InternalQuote != nil {
		log.Functionf("[ATTEST] Clearing current quote, before requesting a new one")
		attestCtx.InternalQuote = nil
	}
	publishAttestNonce(attestCtx)
	return nil
}

// PunchWatchdog implements PunchWatchdog method of zattest.Watchdog
func (wd *WatchdogImpl) PunchWatchdog(ctx *zattest.Context) error {
	log.Trace("[ATTEST] Punching watchdog")
	ctx.PubSub.StillRunning(attestWdName, warningTime, errorTime)
	return nil
}

// parseTpmEventLog parses TPM Event Log and stores it given attestContext
// any error during parsing is stored in EventLogParseErr
func parseTpmEventLog(attestCtx *attestContext) {
	events, err := eventlog.ParseEvents(EventLogPath)
	attestCtx.EventLogEntries = events
	attestCtx.EventLogParseErr = err
	if err != nil {
		log.Errorf("[ATTEST] Eventlog parsing error %v", err)
	}
}

func encodeEventLog(attestCtx *attestContext, quoteMsg *attest.ZAttestQuote) error {
	quoteMsg.EventLog = make([]*attest.TpmEventLogEntry, 0)
	for _, event := range attestCtx.EventLogEntries {
		tpmEventLog := new(attest.TpmEventLogEntry)
		tpmEventLog.Index = uint32(event.Sequence)
		tpmEventLog.PcrIndex = uint32(event.Index)
		tpmEventLog.Digest = new(attest.TpmEventDigest)
		tpmEventLog.Digest.HashAlgo = attest.TpmHashAlgo_TPM_HASH_ALGO_SHA256
		tpmEventLog.Digest.Digest = event.Sha256Digest()
		tpmEventLog.EventDataBinary = event.Data
		tpmEventLog.EventBinarySize = uint32(len(event.Data))
		tpmEventLog.EventType = uint32(event.Typ)
		//Do not populate EventDataString for now because of possible size exceed

		quoteMsg.EventLog = append(quoteMsg.EventLog, tpmEventLog)
	}
	return nil
}

// cleanupEventLog removes event binary data from EventLog which exceed size limit
func cleanupEventLog(quoteMsg *attest.ZAttestQuote) {
	for _, el := range quoteMsg.EventLog {
		if el.EventBinarySize > eventLogBinarySizeLimit {
			el.EventDataBinary = nil
		}
	}
}

// initialize attest pubsub trigger handlers and channels
func attestModuleInitialize(ctx *zedagentContext) error {
	zattest.RegisterExternalIntf(&TpmAgentImpl{}, &VerifierImpl{}, &WatchdogImpl{})

	if ctx.attestCtx == nil {
		ctx.attestCtx = &attestContext{}
	}

	c, err := zattest.New(ctx.ps, log, retryTimeInterval, watchdogInterval, ctx.attestCtx)
	if err != nil {
		log.Errorf("[ATTEST] Error %v while initializing attestation FSM", err)
		return err
	}
	ctx.attestCtx.attestFsmCtx = c
	pubAttestNonce, err := ctx.ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.AttestNonce{},
		})
	if err != nil {
		log.Fatal(err)
	}
	ctx.attestCtx.pubAttestNonce = pubAttestNonce
	pubEncryptedKeyFromController, err := ctx.ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.EncryptedVaultKeyFromController{},
		})
	if err != nil {
		log.Fatal(err)
	}
	ctx.attestCtx.pubEncryptedKeyFromController = pubEncryptedKeyFromController
	parseTpmEventLog(ctx.attestCtx)
	return nil
}

// start the task threads
func attestModuleStart(ctx *zedagentContext) error {
	log.Function("[ATTEST] Starting attestation task")
	if ctx.attestCtx == nil {
		return fmt.Errorf("No attest module context")
	}
	if ctx.attestCtx.attestFsmCtx == nil {
		return fmt.Errorf("No state machine context found")
	}
	log.Functionf("Creating %s at %s", "attestFsmCtx.EnterEventLoop",
		agentlog.GetMyStack())
	go ctx.attestCtx.attestFsmCtx.EnterEventLoop()
	ctx.attestCtx.Started = true
	zattest.Kickstart(ctx.attestCtx.attestFsmCtx)

	// Add .touch file to watchdog config
	ctx.ps.RegisterFileWatchdog(attestWdName)
	return nil
}

// pubsub functions
func handleAttestQuoteCreate(ctxArg interface{}, key string,
	quoteArg interface{}) {
	handleAttestQuoteImpl(ctxArg, key, quoteArg)
}

func handleAttestQuoteModify(ctxArg interface{}, key string,
	quoteArg interface{}, oldQuoteArg interface{}) {
	handleAttestQuoteImpl(ctxArg, key, quoteArg)
}

func handleAttestQuoteImpl(ctxArg interface{}, key string,
	quoteArg interface{}) {

	//Store quote received in state machine
	ctx, ok := ctxArg.(*zedagentContext)
	if !ok {
		log.Fatalf("[ATTEST] Unexpected ctx type %T", ctxArg)
	}

	quote, ok := quoteArg.(types.AttestQuote)
	if !ok {
		log.Fatalf("[ATTEST] Unexpected pub type %T", quoteArg)
	}

	if ctx.attestCtx == nil {
		log.Fatalf("[ATTEST] Uninitialized access to attestCtx")
	}

	//Deepcopy quote into InternalQuote
	attestCtx := ctx.attestCtx
	attestCtx.InternalQuote = &types.AttestQuote{}
	buf, _ := json.Marshal(&quote)
	json.Unmarshal(buf, attestCtx.InternalQuote)

	if attestCtx.attestFsmCtx == nil {
		log.Fatalf("[ATTEST] Uninitialized access to attestFsmCtx")
	}
	//Trigger event on the state machine
	zattest.InternalQuoteRecvd(attestCtx.attestFsmCtx)

	log.Functionf("handleAttestQuoteImpl done for %s", quote.Key())
	return
}

func handleAttestQuoteDelete(ctxArg interface{}, key string, quoteArg interface{}) {
	//Delete quote received in state machine

	ctx, ok := ctxArg.(*zedagentContext)
	if !ok {
		log.Fatalf("[ATTEST] Unexpected ctx type %T", ctxArg)
	}

	quote, ok := quoteArg.(types.AttestQuote)
	if !ok {
		log.Fatalf("[ATTEST] Unexpected pub type %T", quoteArg)
	}

	if ctx.attestCtx == nil {
		log.Fatalf("[ATTEST] Uninitialized access to attestCtx")
	}

	attestCtx := ctx.attestCtx
	if attestCtx.InternalQuote == nil {
		log.Warnf("[ATTEST] Delete received while InternalQuote is unpopulated, ignoring")
		return
	}

	if attestCtx.attestFsmCtx == nil {
		log.Fatalf("[ATTEST] Uninitialized access to attestFsmCtx")
	}

	if reflect.DeepEqual(quote.Nonce, attestCtx.InternalQuote.Nonce) {
		attestCtx.InternalQuote = nil
	} else {
		log.Warnf("[ATTEST] Nonce didn't match, ignoring incoming delete")
	}
	log.Functionf("handleAttestQuoteDelete done for %s", quote.Key())
	return
}

func handleEncryptedKeyFromDeviceCreate(ctxArg interface{}, key string,
	vaultKeyArg interface{}) {
	handleEncryptedKeyFromDeviceImpl(ctxArg, key, vaultKeyArg)
}

func handleEncryptedKeyFromDeviceModify(ctxArg interface{}, key string,
	vaultKeyArg interface{}, oldStatusArg interface{}) {
	handleEncryptedKeyFromDeviceImpl(ctxArg, key, vaultKeyArg)
}

func handleEncryptedKeyFromDeviceDelete(ctxArg interface{}, key string,
	vaultKeyArg interface{}) {
	handleEncryptedKeyFromDeviceImpl(ctxArg, key, vaultKeyArg)
}

func handleEncryptedKeyFromDeviceImpl(ctxArg interface{}, key string,
	vaultKeyArg interface{}) {

	//Store quote received in state machine
	ctx, ok := ctxArg.(*zedagentContext)
	if !ok {
		log.Fatalf("[ATTEST] Unexpected ctx type %T", ctxArg)
	}

	vaultKey, ok := vaultKeyArg.(types.EncryptedVaultKeyFromDevice)
	if !ok {
		log.Fatalf("[ATTEST] Unexpected pub type %T", vaultKeyArg)
	}
	log.Noticef("handleEncryptedKeyFromDeviceImpl len %d",
		len(vaultKey.EncryptedVaultKey))

	if ctx.attestCtx == nil {
		log.Fatalf("[ATTEST] Uninitialized access to attestCtx")
	}

	if vaultKey.Name != types.DefaultVaultName {
		log.Warnf("Ignoring unknown vault %s", vaultKey.Name)
		return
	}
	attestCtx := ctx.attestCtx
	attestCtx.EscrowData = vaultKey.EncryptedVaultKey
	attestCtx.SkipEscrow = false
	if len(attestCtx.EscrowData) == 0 {
		attestCtx.SkipEscrow = true
	}

	if attestCtx.attestFsmCtx == nil {
		log.Fatalf("[ATTEST] Uninitialized access to attestFsmCtx")
	}
	if !attestCtx.Started {
		log.Warnf("Skip triggering attest state machine before entering main loop")
		return
	}
	//Trigger event on the state machine
	zattest.InternalEscrowDataRecvd(attestCtx.attestFsmCtx)
}

func publishAttestNonce(ctx *attestContext) {
	nonce := types.AttestNonce{
		Nonce:     ctx.Nonce,
		Requester: agentName,
	}
	key := nonce.Key()
	log.Tracef("[ATTEST] publishAttestNonce %s", key)
	pub := ctx.pubAttestNonce
	pub.Publish(key, nonce)
	log.Tracef("[ATTEST] publishAttestNonce done for %s", key)
}

func publishEncryptedKeyFromController(ctx *attestContext, encryptedVaultKey []byte) {
	sK := types.EncryptedVaultKeyFromController{
		Name:              types.DefaultVaultName,
		EncryptedVaultKey: encryptedVaultKey,
	}
	key := sK.Key()
	log.Tracef("[ATTEST] publishEncryptedKeyFromController %s", key)
	pub := ctx.pubEncryptedKeyFromController
	pub.Publish(key, sK)
	log.Tracef("[ATTEST] publishEncryptedKeyFromController done for %s", key)
}

func unpublishAttestNonce(ctx *attestContext) {
	nonce := types.AttestNonce{
		Nonce:     ctx.Nonce,
		Requester: agentName,
	}
	pub := ctx.pubAttestNonce
	key := nonce.Key()
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("[ATTEST] unpublishAttestNonce(%s) not found", key)
		return
	}
	pub.Unpublish(key)
	items := pub.GetAll()
	if len(items) > 0 {
		for _, item := range items {
			nonce := item.(types.AttestNonce)
			log.Errorf("[ATTEST] Stale nonce item found, %s", nonce.Key())
		}
		log.Fatal("[ATTEST] Stale nonce items found after unpublishing")
	}
	log.Tracef("[ATTEST] unpublishAttestNonce done for %s", key)
}

// helper to set IntegrityToken
func storeIntegrityToken(token []byte) {
	if len(token) == 0 {
		log.Warnf("[ATTEST] Received empty integrity token")
	}
	err := os.WriteFile(types.ITokenFile, token, 644)
	if err != nil {
		log.Fatalf("Failed to store integrity token, err: %v", err)
	}
}

// helper to get IntegrityToken
func readIntegrityToken() ([]byte, error) {
	return os.ReadFile(types.ITokenFile)
}

// trigger restart event in attesation FSM
func restartAttestation(zedagentCtx *zedagentContext) error {
	if zedagentCtx.attestCtx == nil {
		log.Fatalf("[ATTEST] Uninitialized access to attestCtx")
	}
	attestCtx := zedagentCtx.attestCtx
	if attestCtx.attestFsmCtx == nil {
		log.Fatalf("[ATTEST] Uninitialized access to attestFsmCtx")
	}
	//Trigger event on the state machine
	zattest.RestartAttestation(attestCtx.attestFsmCtx)
	return nil
}
