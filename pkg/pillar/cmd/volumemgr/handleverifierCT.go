// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// MaybeAddVerifyImageConfigCT publishes the verifier config
func MaybeAddVerifyImageConfigCT(ctx *volumemgrContext,
	status types.ContentTreeStatus, checkCerts bool) (bool, types.ErrorAndTime) {

	log.Infof("MaybeAddVerifyImageConfigCT for %s, checkCerts: %v",
		status.ContentSha256, checkCerts)

	// check the certificate files, if not present,
	// we can not start verification
	if checkCerts {
		certObjStatus := lookupCertObjStatus(ctx, status.ContentID.String())
		displaystr := status.ContentID.String()
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

	m := lookupVerifyImageConfig(ctx, status.ObjType, status.ContentSha256)
	if m != nil {
		m.RefCount++
		log.Infof("MaybeAddVerifyImageConfigCT: refcnt to %d for %s",
			m.RefCount, status.ContentSha256)
		publishVerifyImageConfig(ctx, status.ObjType, m)
	} else {
		log.Infof("MaybeAddVerifyImageConfigCT: add for %s, IsContainer: %t",
			status.ContentSha256, status.IsContainer())
		n := types.VerifyImageConfig{
			ImageID: status.ContentID,
			VerifyConfig: types.VerifyConfig{
				Name:             status.DisplayName,
				ImageSha256:      status.ContentSha256,
				CertificateChain: status.CertificateChain,
				ImageSignature:   status.ImageSignature,
				SignatureKey:     status.SignatureKey,
				FileLocation:     status.FileLocation,
			},
			IsContainer: status.IsContainer(),
			RefCount:    1,
		}
		publishVerifyImageConfig(ctx, status.ObjType, &n)
		log.Debugf("MaybeAddVerifyImageConfigCT - config: %+v", n)
	}
	log.Infof("MaybeAddVerifyImageConfigCT done for %s", status.ContentSha256)
	return true, types.ErrorAndTime{}
}
