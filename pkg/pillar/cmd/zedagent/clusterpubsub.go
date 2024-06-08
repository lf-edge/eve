// Copyright (c) 2017-2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"bytes"
	"encoding/gob"
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

func handleEncPubToRemoteDataCreate(ctxArg interface{}, key string, configArg interface{}) {
	log.Noticef("handleEncPubToRemoteDataCreate, key %s", key)
	handleEncPubToRemoteDataImp(ctxArg, key, configArg)
}

// Handles UUID change from process client
func handleEncPubToRemoteDataModify(ctxArg interface{}, key string,
	configArg interface{}, oldconfigArg interface{}) {
	log.Noticef("handleEncPubToRemoteDataModify, key %s", key)
	handleEncPubToRemoteDataImp(ctxArg, key, configArg)
}

func handleEncPubToRemoteDataDelete(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	getconfigCtx := ctx.getconfigCtx
	log.Noticef("handleEncPubToRemoteDataDelete, key %s", key)
	encCfg := configArg.(types.EncPubToRemoteData)
	switch encCfg.Header.TypeNumber {
	case types.EncNetInstConfig:
		log.Noticef("handleEncPubToRemoteDataDelete, NIC unpublish, key %s", key)
		getconfigCtx.pubNetworkInstanceConfig.Unpublish(key)
	case types.EncAppInstConfig:
		log.Noticef("handleEncPubToRemoteDataDelete, AIC unpublish, key %s", key)
		getconfigCtx.pubAppInstanceConfig.Unpublish(key)
	case types.EncVolumeConfig:
		log.Noticef("handleEncPubToRemoteDataDelete, VC unpublish, key %s", key)
		getconfigCtx.pubVolumeConfig.Unpublish(key)
	case types.EncDataStoreConfig:
		log.Noticef("handleEncPubToRemoteDataDelete, DS unpublish, key %s", key)
		getconfigCtx.pubDatastoreConfig.Unpublish(key)
	case types.EncContentTreeConfig:
		log.Noticef("handleEncPubToRemoteDataDelete, CT unpublish, key %s", key)
		getconfigCtx.pubContentTreeConfig.Unpublish(key)
	default:
	}
}

func handleEncPubToRemoteDataImp(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*zedagentContext)

	getconfigCtx := ctx.getconfigCtx
	encCfg := configArg.(types.EncPubToRemoteData)
	if encCfg.Header.AgentName != agentName {
		log.Noticef("handleEncPubToRemoteDataImp: agentName %s not match, do nothing", encCfg.Header.AgentName)
		return
	}

	switch encCfg.Header.TypeNumber {
	case types.EncNetInstConfig:
		var niconfig types.NetworkInstanceConfig
		err := decodeGobData(encCfg.AgentData, &niconfig)
		if err != nil {
			log.Errorf("handleEncPubToRemoteDataImp: NIC decode error %v", err)
			return
		}
		if encCfg.Header.OpType == types.EncPubOpDelete {
			log.Noticef("handleEncPubToRemoteDataImp(%s) NIC unpublish", key)
			getconfigCtx.pubNetworkInstanceConfig.Unpublish(key)
		} else {
			log.Noticef("handleEncPubToRemoteDataImp(%s) NIC create/update %v", key, niconfig)
			getconfigCtx.pubNetworkInstanceConfig.Publish(key, niconfig)
		}
	case types.EncAppInstConfig:
		var aiconfig types.AppInstanceConfig
		err := decodeGobData(encCfg.AgentData, &aiconfig)
		if err != nil {
			log.Errorf("handleEncPubToRemoteDataImp: AIC decode error %v", err)
			return
		}
		if encCfg.Header.OpType == types.EncPubOpDelete {
			log.Noticef("handleEncPubToRemoteDataImp(%s) AIC unpublish", key)
			getconfigCtx.pubAppInstanceConfig.Unpublish(key)
		} else {
			log.Noticef("handleEncPubToRemoteDataImp(%s) AIC create/update %v", key, aiconfig)
			getconfigCtx.pubAppInstanceConfig.Publish(key, aiconfig)
		}
	case types.EncVolumeConfig:
		var vcconfig types.VolumeConfig
		err := decodeGobData(encCfg.AgentData, &vcconfig)
		if err != nil {
			log.Errorf("handleEncPubToRemoteDataImp: VC decode error %v", err)
			return
		}
		if encCfg.Header.OpType == types.EncPubOpDelete {
			log.Noticef("handleEncPubToRemoteDataImp(%s) VC unpublish", key)
			getconfigCtx.pubVolumeConfig.Unpublish(key)
		} else {
			log.Noticef("handleEncPubToRemoteDataImp(%s) VC create/update %v", key, vcconfig)
			getconfigCtx.pubVolumeConfig.Publish(key, vcconfig)
		}
	case types.EncDataStoreConfig:
		var dsconfig types.DatastoreConfig
		err := decodeGobData(encCfg.AgentData, &dsconfig)
		if err != nil {
			log.Errorf("handleEncPubToRemoteDataImp: DS decode error %v", err)
			return
		}
		if encCfg.Header.OpType == types.EncPubOpDelete {
			log.Noticef("handleEncPubToRemoteDataImp(%s) DS unpublish", key)
			getconfigCtx.pubDatastoreConfig.Unpublish(key)
		} else {
			log.Noticef("handleEncPubToRemoteDataImp(%s) DS create/update %v", key, dsconfig)
			getconfigCtx.pubDatastoreConfig.Publish(key, dsconfig)
		}
	case types.EncContentTreeConfig:
		var ctconfig types.ContentTreeConfig
		err := decodeGobData(encCfg.AgentData, &ctconfig)
		if err != nil {
			log.Errorf("handleEncPubToRemoteDataImp: CT decode error %v", err)
			return
		}
		if encCfg.Header.OpType == types.EncPubOpDelete {
			log.Noticef("handleEncPubToRemoteDataImp(%s) CT unpublish", key)
			getconfigCtx.pubContentTreeConfig.Unpublish(key)
		} else {
			log.Noticef("handleEncPubToRemoteDataImp(%s) CT create/update %v", key, ctconfig)
			err := getconfigCtx.pubContentTreeConfig.Publish(key, ctconfig)
			if err != nil { // XXX
				log.Errorf("handleEncPubToRemoteDataImp: CT publish error %v", err)
			}
		}
	default:
	}
}

func decodeGobData(data []byte, config interface{}) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)

	err := dec.Decode(config)
	if err != nil {
		return fmt.Errorf("Error decoding data: %v", err)
	}

	return nil
}
