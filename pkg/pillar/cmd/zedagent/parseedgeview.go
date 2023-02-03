// Copyright (c) 2021-2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/go-cmp/cmp"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// edge-view specific parser/utility routines

func parseEvConfig(ctx *getconfigContext, config *zconfig.EdgeDevConfig) {

	log.Tracef("Started parsing edge-view config")
	zcfgEv := config.GetEdgeview()
	evConfig := types.EdgeviewConfig{}
	if zcfgEv == nil {
		if !cmp.Equal(ctx.configEdgeview, &evConfig) {
			removeEvFiles()
		}
		ctx.configEdgeview = &evConfig
		return
	}
	evConfig = types.EdgeviewConfig{
		JWToken:     zcfgEv.Token,
		DispCertPEM: zcfgEv.DispCertPem,
	}

	// device side
	dev := types.EvDevPolicy{}
	if zcfgEv.DevPolicy != nil {
		dev = types.EvDevPolicy{
			Enabled: zcfgEv.DevPolicy.AllowDev,
		}
	}
	evConfig.DevPolicy = dev

	// app side
	app := types.EvAppPolicy{}
	if zcfgEv.AppPolicy != nil {
		app = types.EvAppPolicy{
			Enabled: zcfgEv.AppPolicy.AllowApp,
		}
	}
	evConfig.AppPolicy = app

	// external side
	ext := types.EvExtPolicy{}
	if zcfgEv.ExtPolicy != nil {
		ext = types.EvExtPolicy{
			Enabled: zcfgEv.ExtPolicy.AllowExt,
		}
	}
	evConfig.ExtPolicy = ext
	evConfig.GenID = zcfgEv.GenerationId

	changed := !cmp.Equal(ctx.configEdgeview, &evConfig)
	if changed {
		params := strings.SplitN(evConfig.JWToken, ".", 3)
		if len(params) != 3 {
			log.Errorf("edgeview JWT token in wrong format")
			removeEvFiles()
		} else {
			// need to validate the signature for JWT
			err := verifyJWT(params)
			if err == nil {
				err = addEvFiles(evConfig, params)
			}
			if err != nil {
				log.Errorf("edgeview JWT token verify failed: %v", err)
				removeEvFiles()
			}
		}
	}
	ctx.configEdgeview = &evConfig
}

func verifyJWT(params []string) error {
	certBytes, err := os.ReadFile(types.ServerSigningCertFileName)
	if err != nil {
		log.Errorf("can not read signing cert: %v", err)
		return err
	}

	var ecdsaKey *ecdsa.PublicKey
	if ecdsaKey, err = jwt.ParseECPublicKeyFromPEM(certBytes); err != nil {
		log.Errorf("Unable to parse ECDSA public key: %v", err)
		return err
	}

	var jalgo types.EvjwtAlgo
	part1, err := base64.RawURLEncoding.DecodeString(params[0])
	if err != nil {
		log.Errorf("can not decode jwt algo: %v", err)
		return err
	}
	err = json.Unmarshal(part1, &jalgo)
	if err != nil {
		log.Errorf("json unmarshal algo error: %v", err)
		return err
	}

	if jalgo.Alg != types.EdgeviewJWTAlgo || jalgo.Typ != types.EdgeviewJWTType {
		err := fmt.Errorf("jwt algo incorrect: %v", jalgo)
		log.Errorf("%v", err)
		return err
	}

	method := jwt.GetSigningMethod(jalgo.Alg)
	err = method.Verify(strings.Join(params[0:2], "."), params[2], ecdsaKey)
	if err != nil {
		log.Errorf("verify jwt failed: %v", err)
		return err
	}
	log.Tracef("jwt verify ok")

	return nil
}

func addEvFiles(evConfig types.EdgeviewConfig, params []string) error {
	tokenData, err := base64.RawURLEncoding.DecodeString(params[1])
	if err != nil {
		log.Errorf("base64 decode jwt error: %v", err)
		return err
	}

	var jdata types.EvjwtInfo
	err = json.Unmarshal(tokenData, &jdata)
	if err != nil {
		log.Errorf("json unmarshal jwt error: %v", err)
		return err
	}

	if _, err = os.Stat(types.EdgeviewPath); os.IsNotExist(err) {
		if err := os.MkdirAll(types.EdgeviewPath, 0755); err != nil {
			log.Errorf("failed to create dir: %v", err)
			return err
		}
	}

	// check devUUID
	if devUUID.String() != jdata.Sub {
		err := fmt.Errorf("jwt sub does not match devUUID: %s", jdata.Sub)
		log.Errorf("%v", err)
		return err
	}

	// check the expiration time
	nowSec := uint64(time.Now().Unix())
	if nowSec > jdata.Exp {
		err := fmt.Errorf("jwt already expired: %d", jdata.Exp)
		log.Errorf("%v", err)
		return err
	}

	// create jwt token file
	f, err := os.CreateTemp(types.EdgeviewPath, "Edgeview-Config")
	if err != nil {
		log.Errorf("file create failed: %v", err)
		return err
	}
	defer f.Close()

	_, err = f.WriteString(types.EdgeViewJwtPrefix + evConfig.JWToken + "\n")
	if err != nil {
		log.Errorf("file write failed: %v", err)
		return err
	}

	// multi-instance
	if jdata.Num > 1 {
		if jdata.Num > types.EdgeviewMaxInstNum {
			err = fmt.Errorf("Exceeds maximum instances")
			log.Errorf("%v", err)
			return err
		}
		_, err = f.WriteString(types.EdgeViewMultiInstPrefix + strconv.Itoa(int(jdata.Num)) + "\n")
		if err != nil {
			log.Errorf("file write failed: %v", err)
			return err
		}
	}

	_, err = f.WriteString(types.EdgeViewExpPrefix + strconv.FormatUint(jdata.Exp, 10) + "\n")
	if err != nil {
		log.Errorf("file write failed: %v", err)
		return err
	}

	// write the dispater certs
	var certs []byte
	for _, c := range evConfig.DispCertPEM {
		certs = append(certs, c...)
	}
	if len(certs) > 0 {
		_, err = f.WriteString(types.EdgeViewCertPrefix + string(certs) + "\n")
		if err != nil {
			log.Errorf("cert file write failed: %v", err)
			return err
		}
	}

	// write device policy
	devbytes, err := json.Marshal(evConfig.DevPolicy)
	if err != nil {
		log.Errorf("json marshal failed: %v", err)
		return err
	}

	_, err = f.WriteString(types.EdgeViewDevPolicyPrefix + string(devbytes) + "\n")
	if err != nil {
		log.Errorf("file write failed: %v", err)
		return err
	}

	// write app policy
	appbytes, err := json.Marshal(evConfig.AppPolicy)
	if err != nil {
		log.Errorf("json marshal failed: %v", err)
		return err
	}

	_, err = f.WriteString(types.EdgeViewAppPolicyPrefix + string(appbytes) + "\n")
	if err != nil {
		log.Errorf("file write failed: %v", err)
		return err
	}

	// write ext policy
	extbytes, err := json.Marshal(evConfig.ExtPolicy)
	if err != nil {
		log.Errorf("json marshal failed: %v", err)
		return err
	}

	_, err = f.WriteString(types.EdgeViewExtPolicyPrefix + string(extbytes) + "\n")
	if err != nil {
		log.Errorf("file write failed: %v", err)
		return err
	}

	// write generation-id
	// since this new generation-id will cause the change of hash value of the configure file,
	// it would restart the edge-view instances as the result
	_, err = f.WriteString(types.EdgeViewGenIDPrefix + strconv.Itoa(int(evConfig.GenID)) + "\n")
	if err != nil {
		log.Errorf("file write failed: %v", err)
		return err
	}

	if err = f.Close(); err != nil {
		log.Errorf("file close failed: %v", err)
		return err
	}
	err = os.Rename(f.Name(), types.EdgeviewCfgFile)
	if err != nil {
		log.Errorf("file rename failed: %v", err)
		return err
	}
	log.Noticef("edge-view jwt install, expires in %v", time.Unix(int64(jdata.Exp), 0))

	return nil
}

func removeEvFiles() {
	_, err := os.Stat(types.EdgeviewPath)
	if err != nil {
		return
	}

	_, err = os.Stat(types.EdgeviewCfgFile)
	if err == nil {
		os.Remove(types.EdgeviewCfgFile)
	}
}
