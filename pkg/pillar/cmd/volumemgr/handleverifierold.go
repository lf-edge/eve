// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// MaybeAddVerifyImageConfigOld publishes verify image config to verifier
// If checkCerts is set this can return false. Otherwise not.
func MaybeAddVerifyImageConfigOld(ctx *volumemgrContext,
	status types.OldVolumeStatus, checkCerts bool) (bool, types.ErrorAndTime) {

	log.Infof("MaybeAddVerifyImageConfigOld for %s, checkCerts: %v",
		status.BlobSha256, checkCerts)

	// check the certificate files, if not present,
	// we can not start verification
	if checkCerts {
		certObjStatus := lookupCertObjStatus(ctx, status.AppInstID.String())
		displaystr := status.VolumeID.String()
		ret, err := status.IsCertsAvailable(displaystr)
		if err != nil {
			log.Fatalf("%s, invalid certificate configuration", displaystr)
		}
		if ret {
			if ret, errInfo := status.HandleCertStatus(displaystr, *certObjStatus); !ret {
				return false, errInfo
			}
		}
	}

	m := lookupVerifyImageConfig(ctx, status.ObjType, status.BlobSha256)
	if m != nil {
		m.RefCount++
		log.Infof("MaybeAddVerifyImageConfigOld: refcnt to %d for %s",
			m.RefCount, status.BlobSha256)
		publishVerifyImageConfig(ctx, status.ObjType, m)
	} else {
		log.Infof("MaybeAddVerifyImageConfigOld: add for %s, IsContainer: %t",
			status.BlobSha256, status.DownloadOrigin.IsContainer)
		n := types.VerifyImageConfig{
			ImageID: status.VolumeID,
			VerifyConfig: types.VerifyConfig{
				Name:             status.DisplayName,
				ImageSha256:      status.BlobSha256,
				CertificateChain: status.DownloadOrigin.CertificateChain,
				ImageSignature:   status.DownloadOrigin.ImageSignature,
				SignatureKey:     status.DownloadOrigin.SignatureKey,
				FileLocation:     status.FileLocation,
			},
			IsContainer: status.DownloadOrigin.IsContainer,
			RefCount:    1,
		}
		publishVerifyImageConfig(ctx, status.ObjType, &n)
		log.Debugf("MaybeAddVerifyImageConfigOld - config: %+v", n)
	}
	log.Infof("MaybeAddVerifyImageConfigOld done for %s", status.BlobSha256)
	return true, types.ErrorAndTime{}
}
