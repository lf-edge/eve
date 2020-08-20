// Copyright (c) 2018-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vaultmgr

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/vault"
	"github.com/sirupsen/logrus"
)

type vaultMgrContext struct {
	pubVaultStatus  pubsub.Publication
	subGlobalConfig pubsub.Subscription
	GCInitialized   bool // GlobalConfig initialized
}

const (
	agentName           = "vaultmgr"
	keyctlPath          = "/bin/keyctl"
	deprecatedImgVault  = types.PersistDir + "/img"
	defaultCfgVault     = types.PersistDir + "/config"
	defaultVault        = types.PersistDir + "/vault"
	oldKeyDir           = "/TmpVaultDir1"
	oldKeyFile          = oldKeyDir + "/protector.key"
	keyDir              = "/TmpVaultDir2"
	keyFile             = keyDir + "/protector.key"
	protectorPrefix     = "TheVaultKey"
	vaultKeyLen         = 32 //bytes
	vaultHalfKeyLen     = 16 //bytes
	defaultVaultName    = "Application Data Store"
	defaultCfgVaultName = "Configuration Data Store"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

var (
	keyctlParams      = []string{"link", "@u", "@s"}
	mntPointParams    = []string{"setup", vault.MountPoint, "--quiet"}
	vaultStatusParams = []string{"status"}
	setupParams       = []string{"setup", "--quiet"}
	debug             = false
	debugOverride     bool // From command line arg
	log               *base.LogObject
)

func getEncryptParams(vaultPath string) []string {
	args := []string{"encrypt", vaultPath, "--key=" + keyFile,
		"--source=raw_key", "--name=" + protectorPrefix + filepath.Base(vaultPath),
		"--user=root"}
	return args
}

func getUnlockParams(vaultPath string) []string {
	args := []string{"unlock", vaultPath, "--key=" + keyFile,
		"--user=root"}
	return args
}

func getStatusParams(vaultPath string) []string {
	args := vaultStatusParams
	return append(args, vaultPath)
}

func getChangeProtectorParams(protectorID string) []string {
	args := []string{"metadata", "change-passphrase", "--key=" + keyFile,
		"--old-key=" + oldKeyFile, "--source=raw_key",
		"--protector=" + vault.MountPoint + ":" + protectorID}
	return args
}

func getRemoveProtectorParams(protectorID string) []string {
	args := []string{"metadata", "destroy", "--protector=" + vault.MountPoint + ":" + protectorID, "--quiet", "--force"}
	return args
}

func getRemovePolicyParams(policyID string) []string {
	args := []string{"metadata", "destroy", "--policy=" + vault.MountPoint + ":" + policyID, "--quiet", "--force"}
	return args
}

func getProtectorIDByName(vaultPath string) ([][]string, error) {
	stdOut, _, err := execCmd(vault.FscryptPath, vault.StatusParams...)
	if err != nil {
		return nil, err
	}
	patternStr := fmt.Sprintf("([[:xdigit:]]+)  No      raw key protector \"%s\"",
		protectorPrefix+filepath.Base(vaultPath))
	protector := regexp.MustCompile(patternStr)
	return protector.FindAllStringSubmatch(stdOut, -1), nil
}

func getPolicyIDByProtectorID(protectID string) ([][]string, error) {
	stdOut, _, err := execCmd(vault.FscryptPath, vault.StatusParams...)
	if err != nil {
		return nil, err
	}
	patternStr := fmt.Sprintf("([[:xdigit:]]+)  No        %s", protectID)
	policy := regexp.MustCompile(patternStr)
	return policy.FindAllStringSubmatch(stdOut, -1), nil
}

func removeProtectorIfAny(vaultPath string) error {
	protectorID, err := getProtectorIDByName(vaultPath)
	if err == nil && len(protectorID) == 0 {
		//No protector found, nothing to be done.
		return nil
	}
	if err == nil {
		log.Infof("Removing protectorID %s for vaultPath %s", protectorID[0][1], vaultPath)
		args := getRemoveProtectorParams(protectorID[0][1])
		if stdOut, stdErr, err := execCmd(vault.FscryptPath, args...); err != nil {
			log.Errorf("Error changing protector key: %v, %v, %v", err, stdOut, stdErr)
			return err
		}
		policyID, err := getPolicyIDByProtectorID(protectorID[0][1])
		if err == nil {
			log.Infof("Removing policyID %s for vaultPath %s", policyID[0][1], vaultPath)
			args := getRemovePolicyParams(policyID[0][1])
			if stdOut, stdErr, err := execCmd(vault.FscryptPath, args...); err != nil {
				log.Errorf("Error changing policy key: %v, %v, %v", err, stdOut, stdErr)
				return err
			}
		}
	}
	return nil
}

func getProtectorID(vaultPath string) ([][]string, error) {
	args := getStatusParams(vaultPath)
	stdOut, _, err := execCmd(vault.FscryptPath, args...)
	if err != nil {
		return nil, err
	}
	protector := regexp.MustCompile(`([[:xdigit:]]+)  No      raw key protector`)
	return protector.FindAllStringSubmatch(stdOut, -1), nil
}

func changeProtector(vaultPath string) error {
	protectorID, err := getProtectorID(vaultPath)
	if protectorID != nil {
		if err := stageKey(true, oldKeyDir, oldKeyFile); err != nil {
			return err
		}
		defer unstageKey(oldKeyDir, oldKeyFile)
		if err := stageKey(false, keyDir, keyFile); err != nil {
			return err
		}
		defer unstageKey(keyDir, keyFile)
		if stdOut, stdErr, err := execCmd(vault.FscryptPath,
			getChangeProtectorParams(protectorID[0][1])...); err != nil {
			log.Errorf("Error changing protector key: %v", err)
			log.Debug(stdOut)
			log.Debug(stdErr)
			return err
		}
		log.Infof("Changed key for protector %s", (protectorID[0][1]))
	}
	return err
}

//Error values
var (
	ErrInvalKeyLen = errors.New("Unexpected key length")
)

func execCmd(command string, args ...string) (string, string, error) {
	var stdout, stderr bytes.Buffer

	cmd := exec.Command(command, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	stdoutStr, stderrStr := stdout.String(), stderr.String()
	return stdoutStr, stderrStr, err
}

func linkKeyrings() error {
	if _, _, err := execCmd(keyctlPath, keyctlParams...); err != nil {
		return fmt.Errorf("Error in linking user keyring %v", err)
	}
	return nil
}

func retrieveTpmKey() ([]byte, error) {
	var tpmKey []byte
	var err error
	tpmKey, err = etpm.FetchVaultKey(log)
	if err != nil {
		log.Errorf("Error fetching TPM key: %v", err)
		return nil, err
	}
	log.Info("Using TPM key")
	return tpmKey, nil
}

func retrieveCloudKey() ([]byte, error) {
	//For now, return a dummy key, until controller support is ready.
	cloudKey := []byte("foobarfoobarfoobarfoobarfoobarfo")
	return cloudKey, nil
}

func mergeKeys(key1 []byte, key2 []byte) ([]byte, error) {
	if len(key1) != vaultKeyLen ||
		len(key2) != vaultKeyLen {
		return nil, ErrInvalKeyLen
	}

	//merge first half of key1 with second half of key2
	v1 := vaultHalfKeyLen
	v2 := vaultKeyLen
	mergedKey := []byte("")
	mergedKey = append(mergedKey, key1[0:v1]...)
	mergedKey = append(mergedKey, key2[v1:v2]...)
	log.Info("Merging keys")
	return mergedKey, nil
}

//cloudKeyOnlyMode is set when the key is used only from cloud, and not from TPM.
func deriveVaultKey(cloudKeyOnlyMode bool) ([]byte, error) {
	//First fetch Cloud Key
	cloudKey, err := retrieveCloudKey()
	if err != nil {
		return nil, err
	}
	if cloudKeyOnlyMode {
		log.Infof("Using cloud key")
		return cloudKey, nil
	}
	tpmKey, err := retrieveTpmKey()
	if err == nil {
		return mergeKeys(tpmKey, cloudKey)
	} else {
		//TPM is present but still error retriving the key
		return cloudKey, err
	}
}

//stageKey is responsible for talking to TPM and Controller
//and preparing the key for accessing the vault
func stageKey(cloudKeyOnlyMode bool, keyDirName string, keyFileName string) error {
	//Create a tmpfs file to pass the secret to fscrypt
	if _, _, err := execCmd("mkdir", keyDirName); err != nil {
		return fmt.Errorf("Error creating keyDir %s %v", keyDirName, err)
	}

	if _, _, err := execCmd("mount", "-t", "tmpfs", "tmpfs", keyDirName); err != nil {
		return fmt.Errorf("Error mounting tmpfs on keyDir %s: %v", keyDirName, err)
	}

	vaultKey, err := deriveVaultKey(cloudKeyOnlyMode)
	if err != nil {
		log.Errorf("Error deriving key for accessing the vault: %v", err)
		return err
	}
	if err := ioutil.WriteFile(keyFileName, vaultKey, 0700); err != nil {
		return fmt.Errorf("Error creating keyFile: %v", err)
	}
	return nil
}

func unstageKey(keyDirName string, keyFileName string) {
	//Shred the tmpfs file, and remove it
	if _, _, err := execCmd("shred", "--remove", keyFileName); err != nil {
		log.Errorf("Error shredding keyFile %s: %v", keyFileName, err)
		return
	}
	if _, _, err := execCmd("umount", keyDirName); err != nil {
		log.Errorf("Error unmounting %s: %v", keyDirName, err)
		return
	}
	if _, _, err := execCmd("rm", "-rf", keyDirName); err != nil {
		log.Errorf("Error removing keyDir %s : %v", keyDirName, err)
		return
	}
	return
}

func isDirEmpty(path string) bool {
	if f, err := os.Open(path); err == nil {
		files, err := f.Readdirnames(0)
		if err != nil {
			log.Errorf("Error reading dir contents: %v", err)
			return false
		}
		if len(files) == 0 {
			log.Debugf("No files in %s", path)
			return true
		}
	}
	log.Debugf("Dir is not empty at %s", path)
	return false
}

//handleFirstUse sets up mountpoint for the first time use
func handleFirstUse() error {
	//setup mountPoint for encryption
	if _, _, err := execCmd(vault.FscryptPath, mntPointParams...); err != nil {
		return fmt.Errorf("Error setting up mountpoint for encrption: %v", err)
	}
	return nil
}

func unlockVault(vaultPath string, cloudKeyOnlyMode bool) error {
	if err := stageKey(cloudKeyOnlyMode, keyDir, keyFile); err != nil {
		return err
	}
	defer unstageKey(keyDir, keyFile)

	//Unlock vault for access
	if _, _, err := execCmd(vault.FscryptPath, getUnlockParams(vaultPath)...); err != nil {
		log.Errorf("Error unlocking vault: %v", err)
		return err
	}
	return linkKeyrings()
}

//createVault expects an empty, existing dir at vaultPath
func createVault(vaultPath string) error {
	if err := removeProtectorIfAny(vaultPath); err != nil {
		return err
	}
	if err := stageKey(false, keyDir, keyFile); err != nil {
		return err
	}
	defer unstageKey(keyDir, keyFile)

	//Encrypt vault, and unlock it for accessing
	if stdout, stderr, err := execCmd(vault.FscryptPath, getEncryptParams(vaultPath)...); err != nil {
		log.Errorf("Encryption failed: %v, %s, %s", err, stdout, stderr)
		return err
	}
	return linkKeyrings()
}

//if deprecated is set, only unlock will be attempted, and creation of the vault will be skipped
func setupVault(vaultPath string, deprecated bool) error {
	_, err := os.Stat(vaultPath)
	if os.IsNotExist(err) && deprecated {
		log.Infof("vault %s is marked deprecated, so not creating a new vault", vaultPath)
		return nil
	}
	if err != nil && !deprecated {
		//Create vault dir
		if err := os.MkdirAll(vaultPath, 755); err != nil {
			return err
		}
	}
	args := getStatusParams(vaultPath)
	if stdOut, stdErr, err := execCmd(vault.FscryptPath, args...); err != nil {
		log.Infof("%v, %v, %v", stdOut, stdErr, err)
		if !isDirEmpty(vaultPath) || deprecated {
			//Don't disturb existing installations
			log.Infof("Not disturbing non-empty or deprecated vault(%s), deprecated=%v",
				vaultPath, deprecated)
			return nil
		}
		return createVault(vaultPath)
	}
	//Already setup for encryption, go for unlocking
	log.Infof("Unlocking %s", vaultPath)
	if err := unlockVault(vaultPath, false); err != nil {
		log.Infof("Unlocking using fallback mode: %s", vaultPath)
		if err := unlockVault(vaultPath, true); err != nil {
			return err
		}
		log.Infof("Migrating keys to TPM %s", vaultPath)
		return changeProtector(vaultPath)
	}
	log.Infof("Successfully unlocked %s", vaultPath)
	return nil
}

func setupFscryptEnv() error {
	//setup fscrypt.conf, if not done already
	if _, _, err := execCmd(vault.FscryptPath, setupParams...); err != nil {
		return fmt.Errorf("Error setting up fscrypt.conf: %v", err)
	}
	//Check if /persist is already setup for encryption
	if _, _, err := execCmd(vault.FscryptPath, vault.StatusParams...); err != nil {
		//Not yet setup, set it up for the first use
		return handleFirstUse()
	}
	return nil
}

func publishVaultStatus(ctx *vaultMgrContext,
	vaultName string, vaultPath string,
	fscryptStatus info.DataSecAtRestStatus,
	fscryptError string) {
	status := types.VaultStatus{}
	status.Name = vaultName
	if fscryptStatus != info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED {
		status.Status = fscryptStatus
		status.SetErrorNow(fscryptError)
	} else {
		args := getStatusParams(vaultPath)
		if stdOut, stdErr, err := execCmd(vault.FscryptPath, args...); err != nil {
			log.Errorf("Status failed, %v, %v, %v", err, stdOut, stdErr)
			status.Status = info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR
			status.SetErrorNow(stdOut + stdErr)
		} else {
			status.Status = info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED
		}
	}
	key := status.Key()
	log.Debugf("Publishing VaultStatus %s\n", key)
	pub := ctx.pubVaultStatus
	pub.Publish(key, status)
}

func fetchFscryptStatus() (info.DataSecAtRestStatus, string) {
	_, err := os.Stat(vault.FscryptConfFile)
	if err == nil {
		if _, _, err := execCmd(vault.FscryptPath, vault.StatusParams...); err != nil {
			//fscrypt is setup, but not being used
			log.Debug("Setting status to Error")
			return info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR,
				"Initialization failure"
		} else {
			//fscrypt is setup , and being used on /persist
			log.Debug("Setting status to Enabled")
			return info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED, ""
		}
	} else {
		_, err := os.Stat(etpm.TpmDevicePath)
		if err != nil {
			//This is due to lack of TPM
			log.Debug("Setting status to disabled, TPM is not in use")
			return info.DataSecAtRestStatus_DATASEC_AT_REST_DISABLED,
				"No active TPM found, but needed for key generation"
		} else {
			//This is due to ext3 partition
			log.Debug("setting status to disabled, ext3 partition")
			return info.DataSecAtRestStatus_DATASEC_AT_REST_DISABLED,
				"File system is incompatible, needs a disruptive upgrade"
		}
	}
}

func initializeSelfPublishHandles(ps *pubsub.PubSub, ctx *vaultMgrContext) {
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
}

//setup vaults on ext4, using fscrypt
func setupVaultsOnExt4() error {
	if err := setupFscryptEnv(); err != nil {
		return fmt.Errorf("Error in setting up fscrypt environment: %s",
			err)
	}
	if err := setupVault(deprecatedImgVault, true); err != nil {
		return fmt.Errorf("Error in setting up vault %s:%v", deprecatedImgVault, err)
	}
	if err := setupVault(defaultCfgVault, false); err != nil {
		return fmt.Errorf("Error in setting up vault %s %v", defaultCfgVault, err)
	}
	if err := setupVault(defaultVault, false); err != nil {
		return fmt.Errorf("Error in setting up vault %s:%v", defaultVault, err)
	}
	return nil
}

//setup vaults on zfs, using zfs native encryption support
func setupVaultsOnZfs() error {
	if err := setupZfsVault(defaultSecretDataset); err != nil {
		return fmt.Errorf("Error in setting up ZFS vault %s:%v", defaultSecretDataset, err)
	}
	//XXX: We are deprecating persist/config as a vault soon, till then set it up
	if err := setupZfsVault(defaultCfgSecretDataset); err != nil {
		return fmt.Errorf("Error in setting up ZFS vault %s:%v", defaultCfgSecretDataset, err)
	}
	return nil
}

func publishAllFscryptVaultStatus(ctx *vaultMgrContext) {
	fscryptStatus, fscryptErr := fetchFscryptStatus()
	publishVaultStatus(ctx, defaultVaultName, defaultVault,
		fscryptStatus, fscryptErr)
	publishVaultStatus(ctx, defaultCfgVaultName, defaultCfgVault,
		fscryptStatus, fscryptErr)
}

func publishAllZfsVaultStatus(ctx *vaultMgrContext) {
	//XXX: till Controller deprecates handling status of persist/config, keep sending
	publishZfsVaultStatus(ctx, defaultCfgVaultName, defaultCfgSecretDataset)
	publishZfsVaultStatus(ctx, defaultVaultName, defaultSecretDataset)
}

func publishZfsVaultStatus(ctx *vaultMgrContext, vaultName, vaultPath string) {
	status := types.VaultStatus{}
	status.Name = vaultName
	zfsEncryptStatus, zfsEncryptError := vault.GetOperInfo(log)
	if zfsEncryptStatus != info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED {
		status.Status = zfsEncryptStatus
		status.SetErrorNow(zfsEncryptError)
	} else {
		datasetStatus, err := vault.CheckOperStatus(log, vaultPath)
		if err == nil {
			log.Infof("checkOperStatus returns %s for %s", datasetStatus, vaultPath)
			datasetStatus = processOperStatus(datasetStatus)
		}
		if datasetStatus != "" {
			log.Errorf("Status failed, %s", datasetStatus)
			status.Status = info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR
			status.SetErrorNow(datasetStatus)
		} else {
			status.Status = info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED
		}
	}
	key := status.Key()
	log.Debugf("Publishing VaultStatus %s\n", key)
	pub := ctx.pubVaultStatus
	pub.Publish(key, status)
}

//Run is the entrypoint for running vaultmgr as a standalone program
func Run(ps *pubsub.PubSub) int {

	debugPtr := flag.Bool("d", false, "Debug flag")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	// XXX Make logrus record a noticable global source
	agentlog.Init("xyzzy-" + agentName)

	// Sending json log format to stdout
	log = agentlog.Init(agentName)

	if len(flag.Args()) == 0 {
		log.Error("Insufficient arguments")
		return 1
	}

	switch flag.Args()[0] {
	case "setupVaults":
		//start with an assumption that nothing needs to be done
		persistFsType := vault.ReadPersistType()
		switch persistFsType {
		case "ext4":
			if err := setupVaultsOnExt4(); err != nil {
				log.Error(err)
				return 1
			}
		case "zfs":
			if err := setupVaultsOnZfs(); err != nil {
				log.Error(err)
				return 1
			}
		default:
			log.Infof("Ignoring request to setup vaults on unsupported %s filesystem", persistFsType)
		}
	case "runAsService":
		log.Infof("Starting %s\n", agentName)

		if err := pidfile.CheckAndCreatePidfile(log, agentName); err != nil {
			log.Fatal(err)
		}
		// Run a periodic timer so we always update StillRunning
		stillRunning := time.NewTicker(15 * time.Second)
		ps.StillRunning(agentName, warningTime, errorTime)

		// Context to pass around
		ctx := vaultMgrContext{}

		// Look for global config such as log levels
		subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
			AgentName:     "",
			TopicImpl:     types.ConfigItemValueMap{},
			Activate:      false,
			Ctx:           &ctx,
			CreateHandler: handleGlobalConfigModify,
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

		// Pick up debug aka log level before we start real work
		for !ctx.GCInitialized {
			log.Infof("waiting for GCInitialized")
			select {
			case change := <-subGlobalConfig.MsgChan():
				subGlobalConfig.ProcessChange(change)
			case <-stillRunning.C:
			}
			ps.StillRunning(agentName, warningTime, errorTime)
		}
		log.Infof("processed GlobalConfig")

		// initialize publishing handles
		initializeSelfPublishHandles(ps, &ctx)

		persistFsType := vault.ReadPersistType()
		switch persistFsType {
		case "ext4":
			publishAllFscryptVaultStatus(&ctx)
		case "zfs":
			publishAllZfsVaultStatus(&ctx)
		default:
			log.Warnf("Ignoring unknown filesystem type %s", persistFsType)
		}
		for {
			select {
			case <-stillRunning.C:
				ps.StillRunning(agentName, warningTime, errorTime)
			}
		}
	default:
		log.Errorf("Unknown argument %s", flag.Args()[0])
		return 1
	}
	return 0
}

// Handles both create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*vaultMgrContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s\n", key)
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride)
	if gcp != nil {
		ctx.GCInitialized = true
	}
	log.Infof("handleGlobalConfigModify done for %s\n", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*vaultMgrContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s\n", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s\n", key)
	debug, _ = agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		debugOverride)
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
}
