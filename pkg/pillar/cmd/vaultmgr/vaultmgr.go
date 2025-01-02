// Copyright (c) 2018-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//Please note:
//As part of remote attestation, encryption key for the volume vault
//i.e. types.DefaultVaultName is sent to the Controller. This is done
//so that after an EVE upgrade, the device will fail to unseal the key
//from TPM (because PCRs have changed), and after proving that the device
//software is trustworthy (via PCR quote etc), Controller will send back
//the copy of the key to the device.

//However, in the above mechanism, it is desired that, the key is not sent
//in clear text, but instead be encrypted using a TPM based key, so that,
//the key is protected from being exposed in the Controller. To that requirement,
//in this PR, we add support to encrypt (aka key wrapping), the vault key
//using a TPM based key (we re-use ECDH key here) the device public key. Basically
//we are re-using a simplified ECDH exchange here, with both the parties being
//the same device. To decrypt the key, one has to be on the same device with
//access to the same TPM, where the private part of the ECDH key resides.
//publishVaultKey and handleVaultKeyFromControllerModify are the relevant
//methods that handle this functionality.

package vaultmgr

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/lf-edge/eve-api/go/attest"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	uc "github.com/lf-edge/eve/pkg/pillar/cmd/upgradeconverter"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/persist"
	"github.com/lf-edge/eve/pkg/pillar/utils/wait"
	"github.com/lf-edge/eve/pkg/pillar/vault"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

type vaultMgrContext struct {
	agentbase.AgentBase
	pubVaultStatus            pubsub.Publication
	pubVaultKeyFromDevice     pubsub.Publication
	pubVaultConfig            pubsub.Publication
	subGlobalConfig           pubsub.Subscription
	subVaultKeyFromController pubsub.Subscription
	GCInitialized             bool // GlobalConfig initialized
	defaultVaultUnlocked      bool
	vaultUCDone               bool
	ps                        *pubsub.PubSub
	ucChan                    chan struct{}
	// cli options
	args []string
}

// ProcessAgentSpecificCLIFlags process received CLI options
func (ctxPtr *vaultMgrContext) ProcessAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	ctxPtr.args = flagSet.Args()
}

const (
	agentName = "vaultmgr"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

var (
	logger            *logrus.Logger
	log               *base.LogObject
	vaultConfig       types.VaultConfig
	vaultConfigInited bool
	handler           vault.Handler
)

// publishVaultConfig: publishes vault config and also updates in memory vaultConfig
func publishVaultConfig(ctx *vaultMgrContext, tpmKeyOnly bool) {
	config := types.VaultConfig{}
	config.TpmKeyOnly = tpmKeyOnly

	key := config.Key()
	log.Notice("Publishing Vault Config with tpmKeyOnly ", tpmKeyOnly)
	pub := ctx.pubVaultConfig
	pub.Publish(key, config)
	vaultConfig = config
}

func initializeSelfPublishHandles(ps *pubsub.PubSub, ctx *vaultMgrContext) {
	//to publish vault status to other agents
	pubVaultStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.VaultStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubVaultStatus.ClearRestarted()
	ctx.pubVaultStatus = pubVaultStatus

	//to publish encrypted vault key to controller
	pubVaultKeyFromDevice, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.EncryptedVaultKeyFromDevice{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubVaultKeyFromDevice.ClearRestarted()
	ctx.pubVaultKeyFromDevice = pubVaultKeyFromDevice

	//to publish vault config to myself
	pubVaultConfig, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			TopicType:  types.VaultConfig{},
			Persistent: true,
		})
	if err != nil {
		log.Fatal(err)
	}
	item, err := pubVaultConfig.Get("global")
	if err != nil {
		vaultConfigInited = false
		log.Notice("Could not find vault config")
	} else {
		vaultConfig = item.(types.VaultConfig)
		vaultConfigInited = true
		log.Notice("Vault config inited with tpmkeyonly ", vaultConfig.TpmKeyOnly)
	}
	ctx.pubVaultConfig = pubVaultConfig
}

// checkAndPublishVaultConfig: If vault config is not yet initialized
// Checks if defaultVault/defaultSecretDataset exists and if not publishes the vault config TmpKeyOnly = true
// If those directories exists, then publishes the vault config TmpKeyOnly = false
// Function returns TmpKeyOnly value
func checkAndPublishVaultConfig(ctx *vaultMgrContext) bool {
	// We do not have vault config, publish it
	if vaultConfigInited == false {
		persistFsType := persist.ReadPersistType()
		tpmKeyOnly := false

		switch persistFsType {
		case types.PersistExt4:
			_, err := os.Stat(types.SealedDirName)
			if os.IsNotExist(err) {
				tpmKeyOnly = true
			}
		case types.PersistZFS:
			if _, err := zfs.GetDatasetKeyStatus(types.SealedDataset); err != nil {
				tpmKeyOnly = true
			}
		default:
			log.Noticef("unsupported %s filesystem, ignoring vault config setup",
				persistFsType)
		}
		publishVaultConfig(ctx, tpmKeyOnly)
		return tpmKeyOnly
	}
	return vaultConfig.TpmKeyOnly
}

// Run is the entrypoint for running vaultmgr as a standalone program
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int {
	logger = loggerArg
	log = logArg

	// Context to pass around
	ctx := vaultMgrContext{
		ps:     ps,
		ucChan: make(chan struct{}),
	}

	// do we run a single command, or long-running service?
	// if any args defined, will run that single command and exit.
	// otherwise, will run the agent
	var (
		command string
		args    []string
	)
	if len(arguments) > 0 {
		command = arguments[0]
	}
	if len(arguments) > 1 {
		args = arguments[1:]
	}

	handler = vault.GetHandler(log)

	// if an explicit command was given, run that command and return, else run the agent
	if command != "" {
		return runCommand(ps, command, args)
	}

	agentArgs := []agentbase.AgentOpt{agentbase.WithBaseDir(baseDir), agentbase.WithArguments(arguments), agentbase.WithPidFile()}
	agentbase.Init(&ctx, logger, log, agentName, agentArgs...)

	log.Functionf("Starting %s\n", agentName)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(15 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Wait until we have been onboarded aka know our own UUID, but we don't use the UUID
	err := wait.WaitForOnboarded(ps, log, agentName, warningTime, errorTime)
	if err != nil {
		log.Fatal(err)
	}
	log.Functionf("processed onboarded")

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleGlobalConfigCreate,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	// Look for encrypted vault key coming from Controller
	subVaultKeyFromController, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.EncryptedVaultKeyFromController{},
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleVaultKeyFromControllerCreate,
		ModifyHandler: handleVaultKeyFromControllerModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	ctx.subVaultKeyFromController = subVaultKeyFromController
	subVaultKeyFromController.Activate()

	// Pick up debug aka log level before we start real work
	for !ctx.GCInitialized {
		log.Functionf("waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Functionf("processed GlobalConfig")

	// initialize publishing handles
	initializeSelfPublishHandles(ps, &ctx)
	tpmEnabled := etpm.IsTpmEnabled()
	if tpmEnabled {
		// TPM is enabled. Check if defaultVault directory exists, if not set vaultconfig
		tpmKeyOnlyMode := checkAndPublishVaultConfig(&ctx)
		handler.SetHandlerOptions(vault.HandlerOptions{TpmKeyOnlyMode: tpmKeyOnlyMode})
	}

	if tpmEnabled {
		log.Noticef("about to setup the vault and fetch the disk key from TPM")
	} else {
		log.Noticef("about to setup the vault without TPM")
	}
	// if TPM available, this sets up the fscrypt and eventually calls FetchSealedVaultKey
	if err := handler.SetupDefaultVault(); err != nil {
		log.Errorf("SetupDefaultVault failed, err: %v", err)
		getAndPublishAllVaultStatuses(&ctx)
	} else {
		log.Noticef("vault is setup and unlocked successfully")
		ctx.defaultVaultUnlocked = true
	}
	if ctx.defaultVaultUnlocked || !tpmEnabled {
		// Now that vault is unlocked, run any upgrade converter handler if needed
		// In case of non-TPM platforms, we do this irrespective of
		// defaultVaultUnlocked
		log.Notice("Starting upgradeconverter(post-vault)")
		go uc.RunPostVaultHandlers(agentName, ps, logger, log,
			ctx.CLIParams().DebugOverride, ctx.ucChan)
	}

	// publish vault key to Controller, if required
	if err := publishVaultKey(&ctx, types.DefaultVaultName); err != nil {
		log.Errorf("Failed to publish Vault Key, %v", err)
	}

	for {
		select {
		case change := <-subVaultKeyFromController.MsgChan():
			subVaultKeyFromController.ProcessChange(change)
		case <-stillRunning.C:
			ps.StillRunning(agentName, warningTime, errorTime)
		case <-ctx.ucChan:
			log.Notice("upgradeconverter(post-vault) Completed")
			ctx.vaultUCDone = true
			// Publish current status of vault
			getAndPublishAllVaultStatuses(&ctx)
		}
	}
}

func runCommand(ps *pubsub.PubSub, command string, _ []string) int {
	switch command {
	case "setupDeprecatedVaults":
		if err := handler.SetupDeprecatedVaults(); err != nil {
			log.Error(err)
			return 1
		}
	case "waitUnsealed":
		if err := wait.WaitForVault(ps, log, agentName, warningTime, errorTime); err != nil {
			log.Fatal(err)
			return 1
		}
	default:
		log.Errorf("Unknown command %s", command)
		return 1
	}
	return 0
}

func handleGlobalConfigCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*vaultMgrContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s\n", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s\n", key)
	gcp := agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	if gcp != nil {
		ctx.GCInitialized = true
	}
	log.Functionf("handleGlobalConfigImpl done for %s\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*vaultMgrContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Functionf("handleGlobalConfigDelete for %s\n", key)
	agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	log.Functionf("handleGlobalConfigDelete done for %s\n", key)
}

func handleVaultKeyFromControllerCreate(ctxArg interface{}, key string,
	keyArg interface{}) {
	handleVaultKeyFromControllerImpl(ctxArg, key, keyArg)
}

func handleVaultKeyFromControllerModify(ctxArg interface{}, key string,
	keyArg interface{}, oldStatusArg interface{}) {
	handleVaultKeyFromControllerImpl(ctxArg, key, keyArg)
}

func handleVaultKeyFromControllerImpl(ctxArg interface{}, key string,
	keyArg interface{}) {

	ctx := ctxArg.(*vaultMgrContext)
	if !etpm.IsTpmEnabled() {
		log.Notice("Receiving Vault key on device without active TPM usage. Ignoring")
		return
	}

	keyFromController, ok := keyArg.(types.EncryptedVaultKeyFromController)
	if !ok {
		log.Fatalf("[VAULT] Unexpected pub type %T", keyArg)
	}
	if keyFromController.Name != types.DefaultVaultName {
		log.Warnf("Ignoring unknown vault %s", keyFromController.Name)
		return
	}
	log.Tracef("Processing EncryptedVaultKeyFromController %s\n", key)
	if len(keyFromController.EncryptedVaultKey) > 0 {
		keyData := &attest.AttestVolumeKeyData{}
		if err := proto.Unmarshal(keyFromController.EncryptedVaultKey, keyData); err != nil {
			log.Errorf("Failed to unmarshal keyData %v", err)
			return
		}
		decryptedKey, err := etpm.EncryptDecryptUsingTpm(keyData.EncryptedKey, false)
		if err != nil {
			log.Errorf("Failed to decrypt Controller provided key data: %v", err)
			return
		}

		hash := sha256.New()
		hash.Write(decryptedKey)
		digest256 := hash.Sum(nil)
		if !bytes.Equal(digest256, keyData.DigestSha256) {
			log.Errorf("Computed SHA is not matching provided SHA")
			return
		}
		log.Functionf("Computed and provided SHA are matching")

		if ctx.defaultVaultUnlocked {
			return
		}
		// Try unlocking the vault now, in case it is not yet unlocked
		log.Noticef("Vault is still locked, trying to unlock")
		err = etpm.SealDiskKey(log, decryptedKey, etpm.DiskKeySealingPCRs)
		if err != nil {
			log.Errorf("Failed to Seal key in TPM %v", err)
			return
		}
		log.Noticef("Sealed key in TPM, unlocking %s", types.DefaultVaultName)

		err = handler.UnlockDefaultVault()
		if err != nil {
			log.Errorf("Failed to unlock zfs vault after receiving Controller key, %v",
				err)
			return
		}

		//Log the type of key used for unlocking default vault
		log.Noticef("%s unlocked using key type %s", types.DefaultVaultName,
			etpm.CompareLegacyandSealedKey().String())
	} else {
		// We are here if we receive no keys from controller
		if ctx.defaultVaultUnlocked {
			// if already unlocked, do nothing
			return
		}
		if !vault.IsVaultCleanupAllowed() {
			log.Warnf("Vault cleanup is not allowed")
			return
		}
		log.Warnf("Processing empty EncryptedVaultKeyFromController %s", key)
		// If we had no luck in unlock with sealed key, and receive empty EncryptedVaultKey from zedagent,
		// which indicates that we receive no keys from the controller,
		// than we cannot unlock the vault.
		// Try to remove and re-create default vault now
		if err := handler.RemoveDefaultVault(); err != nil {
			log.Errorf("Failed to remove vault after receiving dummy Controller key: %v", err)
			return
		}
		log.Warnln("default vault removed")
		if err := handler.SetupDefaultVault(); err != nil {
			log.Errorf("SetupDefaultVault failed, err: %v", err)
			getAndPublishAllVaultStatuses(ctx)
			return
		}
		ctx.defaultVaultUnlocked = true
		log.Noticef("%s re-created", types.DefaultVaultName)
	}

	// Mark the default vault as unlocked
	ctx.defaultVaultUnlocked = true

	// publish vault key to Controller
	if err := publishVaultKey(ctx, types.DefaultVaultName); err != nil {
		log.Errorf("Failed to publish Vault Key, %v", err)
	}

	// Publish current status of vault
	getAndPublishAllVaultStatuses(ctx)

	// Now that vault is unlocked, run any upgrade converter handler if needed
	// The main select loop which is waiting on ucChan event, will publish
	// the latest status of vault(s) once RunPostVaultHandlers is complete.
	log.Notice("Starting upgradeconverter(post-vault)")
	go uc.RunPostVaultHandlers(agentName, ctx.ps, logger, log,
		ctx.CLIParams().DebugOverride, ctx.ucChan)
}

func publishVaultKey(ctx *vaultMgrContext, vaultName string) error {
	var encryptedVaultKey []byte
	//we try to fill EncryptedVaultKey only in case of tpm enabled
	//otherwise we leave it empty
	isTpmEnabled := etpm.IsTpmEnabled()
	if isTpmEnabled {
		if !ctx.defaultVaultUnlocked {
			log.Errorf("Vault is not yet unlocked, waiting for Controller key")
			return nil
		}
		keyBytes, err := etpm.FetchSealedVaultKey(log)
		if err != nil {
			return fmt.Errorf("failed to retrieve key from TPM %w", err)
		}

		// if this fails, tpm manager signals the controller something is wrong with TPM
		encryptedKey, err := etpm.EncryptDecryptUsingTpm(keyBytes, true)
		if err != nil {
			return fmt.Errorf("failed to encrypt vault key %w", err)
		}

		hash := sha256.New()
		hash.Write(keyBytes)
		digest256 := hash.Sum(nil)

		keyData := &attest.AttestVolumeKeyData{
			EncryptedKey: encryptedKey,
			DigestSha256: digest256,
		}
		encryptedVaultKey, err = proto.Marshal(keyData)
		if err != nil {
			return fmt.Errorf("failed to Marshal keyData %w", err)
		}
	}

	keyFromDevice := types.EncryptedVaultKeyFromDevice{}
	keyFromDevice.Name = vaultName
	keyFromDevice.EncryptedVaultKey = encryptedVaultKey
	keyFromDevice.IsTpmEnabled = isTpmEnabled
	key := keyFromDevice.Key()
	log.Tracef("Publishing EncryptedVaultKeyFromDevice %s\n", key)
	pub := ctx.pubVaultKeyFromDevice
	pub.Publish(key, keyFromDevice)
	return nil
}

func getAndPublishAllVaultStatuses(ctx *vaultMgrContext) {
	statuses := handler.GetVaultStatuses()
	for _, status := range statuses {
		// adjust ConversionComplete field with information from context
		status.ConversionComplete = ctx.vaultUCDone
		publishVaultStatus(ctx, *status)
	}
}

func publishVaultStatus(ctx *vaultMgrContext, status types.VaultStatus) {
	key := status.Key()
	log.Tracef("Publishing VaultStatus %s\n", key)
	pub := ctx.pubVaultStatus
	pub.Publish(key, status)
}
