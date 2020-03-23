// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

// certs API specific parser/utility routines

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/golang/protobuf/proto"
	zcert "github.com/lf-edge/eve/api/go/certs"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

var certConfigHash []byte

// parse and update controller certs
func parseControllerCerts(ctx *zedagentContext, contents []byte) {
	cfgConfig := &zcert.ZControllerCert{}
	err := proto.Unmarshal(contents, cfgConfig)
	if err != nil {
		log.Errorf("parseControllerCerts(): Unmarshal error %v\n", err)
		return
	}

	cfgCerts := cfgConfig.GetCerts()
	h := sha256.New()
	for _, cfgCert := range cfgCerts {
		computeConfigElementSha(h, cfgCert)
	}
	newConfigHash := h.Sum(nil)
	if bytes.Equal(newConfigHash, certConfigHash) {
		return
	}
	log.Infof("parseControllerCerts: Applying updated config\n"+
		"Last Sha: % x\n"+
		"New  Sha: % x\n"+
		"cfgCertList: %v\n",
		certConfigHash, newConfigHash, cfgCerts)

	certConfigHash = newConfigHash

	// First look for deleted ones
	items := ctx.subControllerCertConfig.GetAll()
	for _, item := range items {
		config := item.(types.ControllerCertConfig)
		configHash := config.CertHash
		found := false
		for _, cfgConfig := range cfgCerts {
			cfgConfigHash := cfgConfig.GetCertHash()
			if bytes.Equal(configHash, cfgConfigHash) {
				found = true
				break
			}
		}
		if !found {
			unpublishControllerCertConfig(ctx.getconfigCtx, config.Key())
		}
	}

	for _, cfgConfig := range cfgCerts {
		config := types.ControllerCertConfig{
			HashAlgo: cfgConfig.GetHashAlgo(),
			Type:     cfgConfig.GetType(),
			Cert:     cfgConfig.GetCert(),
			CertHash: cfgConfig.GetCertHash(),
		}
		publishControllerCertConfig(ctx.getconfigCtx, config)
	}
}

// handler for controller cert config object triggers
func handleControllerCertConfigModify(ctxArg interface{}, key string,
	configArg interface{}) {
	log.Infof("handleControllerCertConfigModify(%s)\n", key)
	ctx := ctxArg.(*zedagentContext)
	config := configArg.(types.ControllerCertConfig)
	handleControllerCertConfigUpdate(ctx.getconfigCtx, config, false)
	log.Debugf("handleControllerCertConfigModify(%s) done %v\n", key, config)
}

func handleControllerCertConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {
	log.Infof("handleControllerCertConfigDelete(%s)\n", key)
	ctx := ctxArg.(*zedagentContext)
	config := configArg.(types.ControllerCertConfig)
	handleControllerCertConfigUpdate(ctx.getconfigCtx, config, true)
	log.Debugf("handleControllerCertConfigDelete(%s) done\n", key)
}

// handler for controller cert status object triggers
func handleControllerCertStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	log.Infof("handleControllerCertStatusModify(%s)\n", key)
	ctx := ctxArg.(*zedagentContext)
	status := statusArg.(types.ControllerCertStatus)
	handleControllerCertStatusUpdate(ctx.getconfigCtx, status, false)
	log.Debugf("handleControllerCertStatusModify(%s) done %v\n", key, status)
}

func handleControllerCertStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	log.Infof("handleControllerCertStatusDelete(%s)\n", key)
	ctx := ctxArg.(*zedagentContext)
	status := statusArg.(types.ControllerCertStatus)
	handleControllerCertStatusUpdate(ctx.getconfigCtx, status, true)
	log.Debugf("handleControllerCertStatusDelete(%s) done\n", key)
}

func handleControllerCertConfigUpdate(ctx *getconfigContext,
	config types.ControllerCertConfig, reset bool) {
	if reset {
		unpublishControllerCertStatus(ctx, config.Key())
		return
	}
	status := getControllerCertStatus(ctx.zedagentCtx, config.Key())
	if status == nil {
		// create controller cert status
		status0 := types.ControllerCertStatus{
			HashAlgo: config.HashAlgo,
			Type:     config.Type,
			Cert:     config.Cert,
			CertHash: config.CertHash,
		}
		status = &status0
	}
	status.ClearErrorInfo()
	// TBD:XXX, validate the the certificate
	// and update the ErrorInfo accordingly
	publishControllerCertStatus(ctx, *status)
	return
}

// controller cert status update, triggers cipher context update
func handleControllerCertStatusUpdate(ctx *getconfigContext,
	status types.ControllerCertStatus, reset bool) {
	switch status.Type {
	case zcert.ZCertType_CERT_TYPE_CONTROLLER_ECDH_EXCHANGE:
		updateCipherContextsWithControllerCert(ctx, status, reset)
		return
	case zcert.ZCertType_CERT_TYPE_CONTROLLER_SIGNING:
	case zcert.ZCertType_CERT_TYPE_CONTROLLER_INTERMEDIATE:
		// TBD:XXX add appropriate handlers
	}
	return
}

// update the cipher context(s) status with the controller cert
func updateCipherContextsWithControllerCert(ctx *getconfigContext,
	status types.ControllerCertStatus, reset bool) {
	log.Infof("%v, update cipher contexts, reset:%v\n",
		status.Key(), reset)
	items := ctx.pubCipherContextStatus.GetAll()
	for _, item := range items {
		cipherCtx := item.(types.CipherContextStatus)
		if !bytes.Equal(cipherCtx.ControllerCertHash,
			status.CertHash) {
			continue
		}
		log.Infof("%v, updating ciphercontext, %s\n",
			status.Key(), cipherCtx.Key())
		if reset {
			cipherCtx.ControllerCert = []byte{}
			errStr := fmt.Sprintf("Controller Cert deleted")
			cipherCtx.SetErrorInfo(agentName, errStr)
			publishCipherContextStatus(ctx, cipherCtx)
			continue
		}
		cipherCtx.ControllerCert = status.Cert
		if len(status.Error) != 0 {
			cipherCtx.SetErrorInfo(agentName, status.Error)
		}
		publishCipherContextStatus(ctx, cipherCtx)
	}
}

// fetch controller cert config
func getControllerCertConfig(ctx *zedagentContext,
	key string) *types.ControllerCertConfig {
	sub := ctx.subControllerCertConfig
	item, err := sub.Get(key)
	if err != nil {
		return nil
	}
	config := item.(types.ControllerCertConfig)
	return &config
}

// fetch controller cert status
func getControllerCertStatus(ctx *zedagentContext,
	key string) *types.ControllerCertStatus {
	sub := ctx.subControllerCertStatus
	item, err := sub.Get(key)
	if err != nil {
		return nil
	}
	status := item.(types.ControllerCertStatus)
	return &status
}

// fetch controller cert
func getControllerCert(ctx *zedagentContext,
	suppliedHash []byte) ([]byte, error) {
	log.Infof("%v, get controller cert\n", suppliedHash)
	items := ctx.subControllerCertStatus.GetAll()
	for _, item := range items {
		status := item.(types.ControllerCertStatus)
		if bytes.Equal(status.CertHash, suppliedHash) {
			if status.Error != "" {
				return status.Cert, errors.New(status.Error)
			}
			return status.Cert, nil
		}
	}
	// TBD:XXX, schedule a cert API Get Call for
	// the suppliedHash
	hexStr := hex.EncodeToString(suppliedHash)
	errStr := fmt.Sprintf("%s, controller certificate not found", hexStr)
	return []byte{}, errors.New(errStr)
}

// for device cert
func getDeviceCert(hashScheme zconfig.CipherHashAlgorithm,
	suppliedHash []byte) ([]byte, error) {
	log.Infof("%v, get device cert\n", suppliedHash)
	// TBD:XXX as of now, only one
	certBytes, err := ioutil.ReadFile(types.DeviceCertName)
	if err == nil {
		if computeAndMatchHash(certBytes, suppliedHash, hashScheme) {
			return certBytes, nil
		}
	}
	hexStr := hex.EncodeToString(suppliedHash)
	errStr := fmt.Sprintf("%s, device certificate not found", hexStr)
	return []byte{}, errors.New(errStr)
}

// hash function
func computeAndMatchHash(cert []byte, suppliedHash []byte,
	hashScheme zconfig.CipherHashAlgorithm) bool {

	switch hashScheme {
	case zconfig.CipherHashAlgorithm_HASH_NONE:
		return false

	case zconfig.CipherHashAlgorithm_HASH_SHA256_16bytes:
		h := sha256.New()
		h.Write(cert)
		computedHash := h.Sum(nil)
		return bytes.Equal(suppliedHash, computedHash[:16])

	case zconfig.CipherHashAlgorithm_HASH_SHA256_32bytes:
		h := sha256.New()
		h.Write(cert)
		computedHash := h.Sum(nil)
		return bytes.Equal(suppliedHash, computedHash)
	}
	return false
}

// pubsub functions

// for controller cert config
func publishControllerCertConfig(ctx *getconfigContext,
	config types.ControllerCertConfig) {
	key := config.Key()
	log.Debugf("publishControllerCertConfig %s\n", key)
	pub := ctx.pubControllerCertConfig
	pub.Publish(key, config)
}

func unpublishControllerCertConfig(ctx *getconfigContext, key string) {
	log.Debugf("unpublishControllerCertConfig %s\n", key)
	pub := ctx.pubControllerCertConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishCertObjConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

// for controller cert status
func publishControllerCertStatus(ctx *getconfigContext,
	status types.ControllerCertStatus) {
	key := status.Key()
	log.Debugf("publishControllerCertStatus %s\n", key)
	pub := ctx.pubControllerCertStatus
	pub.Publish(key, status)
}

func unpublishControllerCertStatus(ctx *getconfigContext, key string) {
	log.Debugf("unpublishControllerCertStatus %s\n", key)
	pub := ctx.pubControllerCertStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishCertObjStatus(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}
