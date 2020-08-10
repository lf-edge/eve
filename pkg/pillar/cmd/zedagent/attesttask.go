// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

// all things related to running remote attestation with the Controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/lf-edge/eve/api/go/attest"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	zattest "github.com/lf-edge/eve/pkg/pillar/attest"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"reflect"
)

//TpmAgentImpl implements zattest.TpmAgent interface
type TpmAgentImpl struct{}

//VerifierImpl implements zattest.Verifier interface
type VerifierImpl struct{}

//WatchdogImpl implements zattest.Watchdog interface
type WatchdogImpl struct{}

// Attest Information Context
type attestContext struct {
	zedagentCtx    *zedagentContext
	attestFsmCtx   *zattest.Context
	pubAttestNonce pubsub.Publication
	//Nonce for the current attestation cycle
	Nonce []byte
	//Quote for the current attestation cycle
	InternalQuote *types.AttestQuote
	//Iteration keeps track of retry count
	Iteration int
}

const (
	watchdogInterval  = 15
	retryTimeInterval = 15
)

//One shot send, if fails, return an error to the state machine to retry later
func trySendToController(attestReq *attest.ZAttestReq, iteration int) (*http.Response, []byte, types.SenderResult, error) {
	data, err := proto.Marshal(attestReq)
	if err != nil {
		log.Fatal("SendInfoProtobufStr proto marshaling error: ", err)
	}

	buf := bytes.NewBuffer(data)
	size := int64(proto.Size(attestReq))
	attestURL := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API,
		devUUID, "attest")
	return zedcloud.SendOnAllIntf(&zedcloudCtx, attestURL,
		size, buf, iteration, true)
}

//SendNonceRequest implements SendNonceRequest method of zattest.Verifier
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
		return zattest.ErrControllerReqFailed
	}

	attestReq.ReqType = attest.ZAttestReqType_ATTEST_REQ_NONCE

	//Increment Iteration for interface rotation
	attestCtx.Iteration++
	log.Debugf("Sending Nonce request %v", attestReq)

	_, contents, senderStatus, err := trySendToController(attestReq, attestCtx.Iteration)
	if err != nil || senderStatus != types.SenderStatusNone {
		log.Errorf("[ATTEST] Error %v, senderStatus %v",
			err, senderStatus)
		return zattest.ErrControllerReqFailed
	}

	attestResp := &attest.ZAttestResponse{}
	if err := proto.Unmarshal(contents, attestResp); err != nil {
		log.Errorf("[ATTEST] Error %v in Unmarshaling nonce response", err)
		return zattest.ErrControllerReqFailed
	}

	respType := attestResp.GetRespType()
	if respType != attest.ZAttestRespType_ATTEST_RESP_NONCE {
		log.Errorf("[ATTEST] Got %v, but want %v",
			respType, attest.ZAttestRespType_ATTEST_RESP_NONCE)
		return zattest.ErrControllerReqFailed
	}

	if nonceResp := attestResp.GetNonce(); nonceResp == nil {
		log.Errorf("[ATTEST] Got empty nonce response")
		return zattest.ErrControllerReqFailed
	} else {
		attestCtx.Nonce = nonceResp.GetNonce()
	}

	return nil
}

//encodePCRValues encodes PCR values from types.AttestQuote into attest.ZAttestQuote
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

//SendAttestQuote implements SendAttestQuote method of zattest.Verifier
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
		return zattest.ErrControllerReqFailed
	}

	attestReq.ReqType = attest.ZAttestReqType_ATTEST_REQ_QUOTE
	//XXX Fill GPS info, Version, Eventlog fields later
	quote := &attest.ZAttestQuote{
		AttestData: attestCtx.InternalQuote.Quote,
		Signature:  attestCtx.InternalQuote.Signature,
	}

	if err := encodePCRValues(attestCtx.InternalQuote, quote); err != nil {
		log.Errorf("[ATTEST] encodePCRValues failed with err %v", err)
		return zattest.ErrControllerReqFailed
	}

	attestReq.Quote = quote

	//Increment Iteration for interface rotation
	attestCtx.Iteration++
	log.Debugf("Sending Quote request %v", attestReq)

	_, contents, senderStatus, err := trySendToController(attestReq, attestCtx.Iteration)
	if err != nil || senderStatus != types.SenderStatusNone {
		log.Errorf("[ATTEST] Error %v, senderStatus %v",
			err, senderStatus)
		return zattest.ErrControllerReqFailed
	}

	attestResp := &attest.ZAttestResponse{}
	if err := proto.Unmarshal(contents, attestResp); err != nil {
		log.Errorf("[ATTEST] Error %v in Unmarshaling nonce response", err)
		return zattest.ErrControllerReqFailed
	}

	respType := attestResp.GetRespType()
	if respType != attest.ZAttestRespType_ATTEST_RESP_QUOTE_RESP {
		log.Errorf("[ATTEST] Got %v, but want %v",
			respType, attest.ZAttestRespType_ATTEST_RESP_QUOTE_RESP)
		return zattest.ErrControllerReqFailed
	}

	var quoteResp *attest.ZAttestQuoteResp
	if quoteResp = attestResp.GetQuoteResp(); quoteResp == nil {
		log.Errorf("[ATTEST] Got empty quote response")
		return zattest.ErrControllerReqFailed
	}
	quoteRespCode := quoteResp.GetResponse()
	switch quoteRespCode {
	case attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_INVALID:
		log.Errorf("[ATTEST] Invalid response code")
		return zattest.ErrControllerReqFailed
	case attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_SUCCESS:
		//Retrieve integrity token
		storeIntegrityToken(quoteResp.GetIntegrityToken())
		log.Infof("[ATTEST] Attestation successful")
		return nil
	case attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_NONCE_MISMATCH:
		log.Errorf("[ATTEST] Nonce Mismatch")
		return zattest.ErrNonceMismatch
	case attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_NO_CERT_FOUND:
		log.Errorf("[ATTEST] Controller yet to receive signing cert")
		return zattest.ErrNoCertYet
	case attest.ZAttestResponseCode_Z_ATTEST_RESPONSE_CODE_QUOTE_FAILED:
		log.Errorf("[ATTEST] Quote Mismatch")
		return zattest.ErrQuoteMismatch
	}
	return nil
}

//SendAttestEscrow implements SendAttestEscrow method of zattest.Verifier
func (server *VerifierImpl) SendAttestEscrow(ctx *zattest.Context) error {
	//XXX: Fill it in when Controller code is ready
	return nil
}

//SendInternalQuoteRequest implements SendInternalQuoteRequest method of zattest.TpmAgent
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
		log.Infof("[ATTEST] Clearing current quote, before requesting a new one")
		attestCtx.InternalQuote = nil
	}
	publishAttestNonce(attestCtx)
	return nil
}

//PunchWatchdog implements PunchWatchdog method of zattest.Watchdog
func (wd *WatchdogImpl) PunchWatchdog(ctx *zattest.Context) error {
	log.Debug("[ATTEST] Punching watchdog")
	agentlog.StillRunning(agentName+"attest", warningTime, errorTime)
	return nil
}

// initialize attest pubsub trigger handlers and channels
func attestModuleInitialize(ctx *zedagentContext, ps *pubsub.PubSub) error {
	zattest.RegisterExternalIntf(&TpmAgentImpl{}, &VerifierImpl{}, &WatchdogImpl{})

	if ctx.attestCtx == nil {
		ctx.attestCtx = &attestContext{}
	}

	c, err := zattest.New(retryTimeInterval, watchdogInterval, ctx.attestCtx)
	if err != nil {
		log.Errorf("[ATTEST] Error %v while initializing attestation FSM", err)
		return err
	}
	ctx.attestCtx.attestFsmCtx = c
	pubAttestNonce, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.AttestNonce{},
		})
	if err != nil {
		log.Fatal(err)
	}
	ctx.attestCtx.pubAttestNonce = pubAttestNonce
	return nil
}

// start the task threads
func attestModuleStart(ctx *zedagentContext) error {
	log.Info("[ATTEST] Starting attestation task")
	if ctx.attestCtx == nil {
		return fmt.Errorf("No attest module context")
	}
	if ctx.attestCtx.attestFsmCtx == nil {
		return fmt.Errorf("No state machine context found")
	}
	go ctx.attestCtx.attestFsmCtx.EnterEventLoop()
	zattest.Kickstart(ctx.attestCtx.attestFsmCtx)
	return nil
}

// pubsub functions
func handleAttestQuoteModify(ctxArg interface{}, key string, quoteArg interface{}) {

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

	log.Infof("handleAttestQuoteModify done for %s", quote.Key())
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
	log.Infof("handleAttestQuoteDelete done for %s", quote.Key())
	return
}

func publishAttestNonce(ctx *attestContext) {
	nonce := types.AttestNonce{
		Nonce:     ctx.Nonce,
		Requester: agentName,
	}
	key := nonce.Key()
	log.Debugf("[ATTEST] publishAttestNonce %s", key)
	pub := ctx.pubAttestNonce
	pub.Publish(key, nonce)
	log.Debugf("[ATTEST] publishAttestNonce done for %s", key)
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
	log.Debugf("[ATTEST] unpublishAttestNonce done for %s", key)
}

//helper to set IntegrityToken
func storeIntegrityToken(token []byte) {
	if len(token) == 0 {
		log.Warnf("[ATTEST] Received empty integrity token")
	}
	err := ioutil.WriteFile(types.ITokenFile, token, 644)
	if err != nil {
		log.Fatalf("Failed to store integrity token, err: %v", err)
	}
}

//helper to get IntegrityToken
func readIntegrityToken() ([]byte, error) {
	return ioutil.ReadFile(types.ITokenFile)
}
