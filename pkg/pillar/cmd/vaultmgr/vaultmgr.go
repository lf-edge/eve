// Copyright (c) 2018-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vaultmgr

import (
	"bytes"
	"errors"
	"flag"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/cmd/tpmmgr"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	pubsublegacy "github.com/lf-edge/eve/pkg/pillar/pubsub/legacy"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

type vaultMgrContext struct {
	pubVaultStatus  pubsub.Publication
	subGlobalConfig pubsub.Subscription
	GCInitialized   bool // GlobalConfig initialized
}

const (
	agentName           = "vaultmgr"
	fscryptConfFile     = "/etc/fscrypt.conf"
	keyctlPath          = "/bin/keyctl"
	oldKeyDir           = "/TmpVaultDir1"
	keyDir              = "/TmpVaultDir2"
	protectorPrefix     = "TheVaultKey"
	vaultKeyLen         = 32 //bytes
	vaultHalfKeyLen     = 16 //bytes
	defaultImgVaultName = "Application Data Store"
	defaultCfgVaultName = "Configuration Data Store"
	fscryptOptBin       = "/opt/zededa/bin/fscrypt"
	fscryptUsrBin       = "/usr/bin/fscrypt"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second
)

var (
	fscryptPath = "/usr/bin/fscrypt" //by default points to /usr/bin
	mountPoint  = "/var/persist"     //by default assumes /var/persist
	keyFile     = keyDir + "/protector.key"
	oldKeyFile  = oldKeyDir + "/protector.key"

	keyctlParams      = []string{"link", "@u", "@s"}
	mntPointParams    = []string{"setup", mountPoint, "--quiet"}
	statusParams      = []string{"status", mountPoint}
	vaultStatusParams = []string{"status"}
	setupParams       = []string{"setup", "--quiet"}
	debug             = false
	debugOverride     bool // From command line arg
)

func defaultImgVault() string {
	return mountPoint + "/img"
}

func defaultCfgVault() string {
	return mountPoint + "/config"
}

func setMountPoint(mntPt string) {
	mountPoint = mntPt
}

func setMntPointParams(mntPt string) {
	mntPointParams = []string{"setup", mntPt, "--quiet"}
}

func setStatusParams(mntPt string) {
	statusParams = []string{"status", mntPt}
}

func setFscryptPath(path string) {
	fscryptPath = path
}

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
		"--protector=" + mountPoint + ":" + protectorID}
	return args
}

func getProtectorID(vaultPath string) ([][]string, error) {
	args := getStatusParams(vaultPath)
	stdOut, _, err := execCmd(fscryptPath, args...)
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
		if stdOut, stdErr, err := execCmd(fscryptPath,
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
		log.Fatalf("Error in linking user keyring %v", err)
		return err
	}
	return nil
}

func retrieveTpmKey() ([]byte, error) {
	var tpmKey []byte
	var err error
	tpmKey, err = tpmmgr.FetchVaultKey()
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
		log.Fatalf("Error creating keyDir %s %v", keyDirName, err)
		return err
	}

	if _, _, err := execCmd("mount", "-t", "tmpfs", "tmpfs", keyDirName); err != nil {
		log.Fatalf("Error mounting tmpfs on keyDir %s: %v", keyDirName, err)
		return err
	}

	vaultKey, err := deriveVaultKey(cloudKeyOnlyMode)
	if err != nil {
		log.Errorf("Error deriving key for accessing the vault: %v", err)
		return err
	}
	if err := ioutil.WriteFile(keyFileName, vaultKey, 0700); err != nil {
		log.Fatalf("Error creating keyFile: %v", err)
	}
	return nil
}

func unstageKey(keyDirName string, keyFileName string) {
	//Shred the tmpfs file, and remove it
	if _, _, err := execCmd("shred", "--remove", keyFileName); err != nil {
		log.Fatalf("Error shredding keyFile %s: %v", keyFileName, err)
		return
	}
	if _, _, err := execCmd("umount", keyDirName); err != nil {
		log.Fatalf("Error unmounting %s: %v", keyDirName, err)
		return
	}
	if _, _, err := execCmd("rm", "-rf", keyDirName); err != nil {
		log.Fatalf("Error removing keyDir %s : %v", keyDirName, err)
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
	if _, _, err := execCmd(fscryptPath, mntPointParams...); err != nil {
		log.Fatalf("Error setting up mountpoint for encrption: %v", err)
		return err
	}
	return nil
}

func unlockVault(vaultPath string, cloudKeyOnlyMode bool) error {
	if err := stageKey(cloudKeyOnlyMode, keyDir, keyFile); err != nil {
		return err
	}
	defer unstageKey(keyDir, keyFile)

	//Unlock vault for access
	if _, _, err := execCmd(fscryptPath, getUnlockParams(vaultPath)...); err != nil {
		log.Errorf("Error unlocking vault: %v", err)
		return err
	}
	return linkKeyrings()
}

//createVault expects an empty, existing dir at vaultPath
func createVault(vaultPath string) error {
	if err := stageKey(true, keyDir, keyFile); err != nil {
		return err
	}
	defer unstageKey(keyDir, keyFile)

	//Encrypt vault, and unlock it for accessing
	if stdout, stderr, err := execCmd(fscryptPath, getEncryptParams(vaultPath)...); err != nil {
		log.Errorf("Encryption failed: %v, %s, %s", err, stdout, stderr)
		return err
	}
	return linkKeyrings()
}

func setupVault(vaultPath string) error {
	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		//Create vault dir
		if _, _, err := execCmd("mkdir", "-p", vaultPath); err != nil {
			return err
		}
	}
	args := getStatusParams(vaultPath)
	if _, _, err := execCmd(fscryptPath, args...); err != nil {
		if !isDirEmpty(vaultPath) {
			//Don't disturb existing installations
			log.Debugf("Not disturbing non-empty %s", vaultPath)
			return nil
		}
		return createVault(vaultPath)
	}
	//Already setup for encryption, go for unlocking
	log.Debugf("Unlocking %s", vaultPath)
	if err := unlockVault(vaultPath, false); err != nil {
		log.Debug("Unlocking using fallback mode")
		if err := unlockVault(vaultPath, true); err != nil {
			return err
		}
		//return changeProtector(vaultPath)
	}
	return nil
}

func setupFscryptEnv() error {
	//setup fscrypt.conf, if not done already
	if _, _, err := execCmd(fscryptPath, setupParams...); err != nil {
		log.Fatalf("Error setting up fscrypt.conf: %v", err)
		return err
	}
	//Check if /persist is already setup for encryption
	if _, _, err := execCmd(fscryptPath, statusParams...); err != nil {
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
		status.Error = fscryptError
		status.ErrorTime = time.Now()
	} else {
		args := getStatusParams(vaultPath)
		if _, stderr, err := execCmd(fscryptPath, args...); err != nil {
			status.Status = info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR
			status.Error = stderr
			status.ErrorTime = time.Now()
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
	_, err := os.Stat(fscryptConfFile)
	if err == nil {
		if stdout, stderr, err := execCmd(fscryptPath, statusParams...); err != nil {
			//fscrypt is setup, but not being used
			log.Debug("Setting status to Error")
			log.Errorf("Setting status to error due to : %s, %s", stdout, stderr)
			return info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR, stderr
		} else {
			//fscrypt is setup , and being used on /persist
			log.Debug("Setting status to Enabled")
			return info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED, ""
		}
	} else {
		_, err := os.Stat(tpmmgr.TpmDevicePath)
		if err != nil {
			//This is due to lack of TPM
			log.Debug("Setting status to disabled, HSM is not in use")
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

func initializeSelfPublishHandles(ctx *vaultMgrContext) {
	pubVaultStatus, err := pubsublegacy.Publish(agentName,
		types.VaultStatus{})
	if err != nil {
		log.Fatal(err)
	}
	pubVaultStatus.ClearRestarted()
	ctx.pubVaultStatus = pubVaultStatus
}

//GetOperInfo gets the current operational state of fscrypt. (Deprecated)
func GetOperInfo() (info.DataSecAtRestStatus, string) {
	setMountPoint(types.PersistDir)
	setMntPointParams(mountPoint)
	setStatusParams(mountPoint)
	setFscryptPath(fscryptOptBin)

	_, err := os.Stat(fscryptConfFile)
	if err == nil {
		if _, _, err := execCmd(fscryptPath, statusParams...); err != nil {
			//fscrypt is setup, but not being used
			log.Debug("Setting status to Error")
			return info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR,
				"Initialization failure"
		} else {
			//fscrypt is setup, and being used on /persist
			log.Debug("Setting status to Enabled")
			return info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED,
				"Using Secure Application Vault=Yes, Using Secure Configuration Vault=Yes"
		}
	} else {
		if !tpmmgr.IsTpmEnabled() {
			//This is due to ext3 partition
			log.Debug("Setting status to disabled, HSM is not in use")
			return info.DataSecAtRestStatus_DATASEC_AT_REST_DISABLED,
				"HSM is either absent or not in use"
		} else {
			//This is due to ext3 partition
			log.Debug("setting status to disabled, ext3 partition")
			return info.DataSecAtRestStatus_DATASEC_AT_REST_DISABLED,
				"File system is incompatible, needs a disruptive upgrade"
		}
	}
}

//Run is the entrypoint for running vaultmgr as a standalone program
func Run() {

	curpartPtr := flag.String("c", "", "Current partition")
	debugPtr := flag.Bool("d", false, "Debug flag")
	flag.Parse()
	debug = *debugPtr
	debugOverride = debug
	if debugOverride {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	curpart := *curpartPtr

	// Sending json log format to stdout
	logf, err := agentlog.Init(agentName, curpart)
	if err != nil {
		log.Fatal(err)
	}
	defer logf.Close()

	if len(flag.Args()) == 0 {
		log.Fatal("Insufficient arguments")
	}

	switch flag.Args()[0] {
	case "setupVaults":
		if err := setupFscryptEnv(); err != nil {
			log.Fatalf("Error in setting up fscrypt environment: %v", err)
			os.Exit(1)
		}
		if err := setupVault(defaultImgVault()); err != nil {
			log.Fatalf("Error in setting up vault %s:%v", defaultImgVault(), err)
		}
		if err := setupVault(defaultCfgVault()); err != nil {
			log.Fatalf("Error in setting up vault %s %v", defaultImgVault(), err)
		}
	case "runAsService":
		log.Infof("Starting %s\n", agentName)

		setMountPoint(types.PersistDir)
		setMntPointParams(mountPoint)
		setStatusParams(mountPoint)
		setFscryptPath(fscryptOptBin)

		if err := setupFscryptEnv(); err != nil {
			log.Fatalf("Error in setting up fscrypt environment: %v", err)
		}
		if err := pidfile.CheckAndCreatePidfile(agentName); err != nil {
			log.Fatal(err)
		}
		// Run a periodic timer so we always update StillRunning
		stillRunning := time.NewTicker(15 * time.Second)
		agentlog.StillRunning(agentName, warningTime, errorTime)

		// Context to pass around
		ctx := vaultMgrContext{}

		// Look for global config such as log levels
		subGlobalConfig, err := pubsublegacy.Subscribe("", types.GlobalConfig{},
			false, &ctx, &pubsub.SubscriptionOptions{
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
			agentlog.StillRunning(agentName, warningTime, errorTime)
		}
		log.Infof("processed GlobalConfig")

		// initialize publishing handles
		initializeSelfPublishHandles(&ctx)

		fscryptStatus, fscryptErr := fetchFscryptStatus()
		publishVaultStatus(&ctx, defaultImgVaultName, defaultImgVault(),
			fscryptStatus, fscryptErr)
		publishVaultStatus(&ctx, defaultCfgVaultName, defaultCfgVault(),
			fscryptStatus, fscryptErr)
		for {
			select {
			case <-stillRunning.C:
				agentlog.StillRunning(agentName, warningTime, errorTime)
			}
		}
	default:
		log.Fatalf("Unknown argument %s", flag.Args()[0])
	}
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
	var gcp *types.GlobalConfig
	debug, gcp = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
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
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	log.Infof("handleGlobalConfigDelete done for %s\n", key)
}
