// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Manage /run/authorized_keys using /config/authorized_keys as the base
// At some point we may also consider extracting key material
// from x509 certificates...
//   bash -c 'ssh-keygen -f <(openssl x509 -in /config/onboard.cert.pem -pubkey -noout) -i -mPKCS8' >> /run/authorized_keys
// ...or using CA signed ssh keys
//  TrustedUserCAKeys /path/to/server_ca.pub

package ssh

import (
	"os"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

const (
	runDir                   = "/run"
	targetAuthorizedKeysFile = runDir + "/authorized_keys"
)

func UpdateSshAuthorizedKeys(log *base.LogObject, authorizedKeys string) {

	log.Functionf("UpdateSshAuthorizedKeys: %s", authorizedKeys)
	tmpfile, err := os.CreateTemp(runDir, "ak")
	if err != nil {
		log.Errorln("TempFile ", err)
		return
	}
	defer tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	tmpfile.Chmod(0600)

	if authorizedKeys != "" {
		if _, err := tmpfile.WriteString(authorizedKeys); err != nil {
			log.Error(err)
			return
		}
	}

	tmpfile.Sync()
	if err := tmpfile.Close(); err != nil {
		log.Errorln("Close ", tmpfile.Name(), err)
		return
	}

	if err := os.Rename(tmpfile.Name(), targetAuthorizedKeysFile); err != nil {
		log.Errorln(err)
		return
	}
	log.Functionf("UpdateSshAuthorizedKey done")
}
