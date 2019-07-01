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
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	configDir                = "/config"
	runDir                   = "/run"
	baseAuthorizedKeysFile   = configDir + "/authorized_keys"
	targetAuthorizedKeysFile = runDir + "/authorized_keys"

	// XXX a bit of a hack to hard-code this here
	sshCommand = `command="ctr --namespace services.linuxkit t exec ${TERM:+-t} --exec-id $(basename $(mktemp)) pillar ${TERM:+env TERM=\"$TERM\"} ${SSH_ORIGINAL_COMMAND:-sh} ${TERM:+-l}"`
)

func UpdateSshAuthorizedKeys(authorizedKeys string) {

	log.Infof("UpdateSshAuthorizedKeys: %s", authorizedKeys)
	tmpfile, err := ioutil.TempFile(runDir, "ak")
	if err != nil {
		log.Errorln("TempFile ", err)
		return
	}
	defer tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	tmpfile.Chmod(0600)

	fileDesc, err := os.Open(baseAuthorizedKeysFile)
	if err != nil {
		log.Warnln("Open ", err)
	} else {
		reader := bufio.NewReader(fileDesc)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				log.Debugln(err)
				if err != io.EOF {
					log.Errorln("ReadString ", err)
					return
				}
				break
			}
			// remove trailing "/n" from line
			line = line[0 : len(line)-1]

			// Is it a comment or a key?
			if strings.HasPrefix(line, "#") {
				continue
			}
			_, err = tmpfile.WriteString(fmt.Sprintf("%s %s\n",
				sshCommand, line))
			if err != nil {
				log.Error(err)
				return
			}
		}
	}
	if authorizedKeys != "" {
		_, err := tmpfile.WriteString(fmt.Sprintf("%s %s\n",
			sshCommand, authorizedKeys))
		if err != nil {
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
		log.Errorln("Rename ", tmpfile.Name(), targetAuthorizedKeysFile, err)
		return
	}
	log.Infof("UpdateSshAuthorizedKey done")
}
