// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"reflect"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func (ctx *volumemgrContext) subscription(topicType interface{}, objType string) pubsub.Subscription {
	var sub pubsub.Subscription
	val := reflect.ValueOf(topicType)
	if val.Kind() == reflect.Ptr {
		log.Fatalf("subscription got a pointer type: %T", topicType)
	}
	switch typeName := topicType.(type) {
	case types.VolumeConfig:
		switch objType {
		case types.AppImgObj:
			sub = ctx.subAppVolumeConfig
		case types.BaseOsObj:
			sub = ctx.subBaseOsVolumeConfig
		default:
			log.Fatalf("subscription: Unknown ObjType %s for %T",
				objType, typeName)
		}
	case types.DownloaderStatus:
		switch objType {
		case types.AppImgObj:
			sub = ctx.subAppImgDownloadStatus
		case types.BaseOsObj:
			sub = ctx.subBaseOsDownloadStatus
		case types.CertObj:
			sub = ctx.subCertObjDownloadStatus
		default:
			log.Fatalf("subscription: Unknown ObjType %s for %T",
				objType, typeName)
		}
	case types.VerifyImageStatus:
		switch objType {
		case types.AppImgObj:
			sub = ctx.subAppImgVerifierStatus
		case types.BaseOsObj:
			sub = ctx.subBaseOsVerifierStatus
		default:
			log.Fatalf("subscription: Unknown ObjType %s for %T",
				objType, typeName)
		}
	default:
		log.Fatalf("subscription: Unknown typeName %T",
			typeName)
	}
	return sub
}

func (ctx *volumemgrContext) publication(topicType interface{}, objType string) pubsub.Publication {
	var pub pubsub.Publication
	val := reflect.ValueOf(topicType)
	if val.Kind() == reflect.Ptr {
		log.Fatalf("publication got a pointer type: %T", topicType)
	}
	switch typeName := topicType.(type) {
	case types.VolumeStatus:
		switch objType {
		case types.AppImgObj:
			pub = ctx.pubAppVolumeStatus
		case types.BaseOsObj:
			pub = ctx.pubBaseOsVolumeStatus
		case types.UnknownObj:
			pub = ctx.pubUnknownVolumeStatus
		default:
			log.Fatalf("publication: Unknown ObjType %s for %T",
				objType, typeName)
		}
	case types.DownloaderConfig:
		switch objType {
		case types.AppImgObj:
			pub = ctx.pubAppImgDownloadConfig
		case types.BaseOsObj:
			pub = ctx.pubBaseOsDownloadConfig
		case types.CertObj:
			pub = ctx.pubCertObjDownloadConfig
		default:
			log.Fatalf("publication: Unknown ObjType %s for %T",
				objType, typeName)
		}
	case types.VerifyImageConfig:
		switch objType {
		case types.AppImgObj:
			pub = ctx.pubAppImgVerifierConfig
		case types.BaseOsObj:
			pub = ctx.pubBaseOsVerifierConfig
		default:
			log.Fatalf("publication: Unknown ObjType %s for %T",
				objType, typeName)
		}
	case types.PersistImageStatus:
		switch objType {
		case types.AppImgObj:
			pub = ctx.pubAppImgPersistStatus
		case types.BaseOsObj:
			pub = ctx.pubBaseOsPersistStatus
		default:
			log.Fatalf("publication: Unknown ObjType %s for %T",
				objType, typeName)
		}
	default:
		log.Fatalf("publication: Unknown typeName %T",
			typeName)
	}
	return pub
}
