// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"io/fs"
	"os"
	"regexp"

	"github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

var bootVariableRe = regexp.MustCompile(`^Boot[0-9a-fA-F]{4}$`)

type efiVariable struct {
	Name  string `json:"name,omitempty"`
	Value []byte `json:"value,omitempty"`
}

type tpmLogs struct {
	LastFailedLog   []byte        `json:"last_failed_log,omitempty"`
	LastGoodLog     []byte        `json:"last_good_log,omitempty"`
	BackupFailedLog []byte        `json:"backup_failed_log,omitempty"`
	BackupGoodLog   []byte        `json:"backup_good_log,omitempty"`
	EfiVarsSuccess  []efiVariable `json:"efi_vars_success,omitempty"`
	EfiVarsFailed   []efiVariable `json:"efi_vars_failed,omitempty"`
}

type nodeStatus struct {
	Server         string                   `json:"server,omitempty"`
	NodeUUID       uuid.UUID                `json:"node_uuid,omitempty"`
	Onboarded      bool                     `json:"onboarded"`
	AppSummary     types.AppInstanceSummary `json:"app_summary,omitempty"`
	ZedAgentStatus types.ZedAgentStatus     `json:"zedagent_status,omitempty"`
}

type appInstancesStatus struct {
	Apps []types.AppInstanceStatus `json:"apps"`
}

type tuiConfig struct {
	LogLevel string `json:"log_level"`
}

func (ctx *monitor) isOnboarded() (bool, uuid.UUID) {
	sub := ctx.subscriptions["OnboardingStatus"]
	if item, err := sub.Get("global"); err == nil {
		onboardingStatus := item.(types.OnboardingStatus)
		if onboardingStatus.DeviceUUID != uuid.Nil {
			return true, onboardingStatus.DeviceUUID
		}
	}
	return false, uuid.Nil
}

func (ctx *monitor) getAppSummary() types.AppInstanceSummary {
	sub := ctx.subscriptions["AppSummary"]
	if item, err := sub.Get("global"); err == nil {
		appSummary := item.(types.AppInstanceSummary)
		return appSummary
	}
	return types.AppInstanceSummary{}
}

func (ctx *monitor) sendNodeStatus() {
	// send the node status to the server
	nodeStatus := nodeStatus{
		Server: ctx.serverNameAndPort,
	}
	if onboarded, nodeUUID := ctx.isOnboarded(); onboarded {
		nodeStatus.NodeUUID = nodeUUID
		nodeStatus.Onboarded = true
	}

	nodeStatus.ZedAgentStatus = ctx.getZedAgentStatus()
	nodeStatus.AppSummary = ctx.getAppSummary()

	if ctx.lastNodeStatus != nil && *ctx.lastNodeStatus == nodeStatus {
		return
	}
	ctx.lastNodeStatus = &nodeStatus

	ctx.IPCServer.sendIpcMessage("NodeStatus", nodeStatus)
}

func (ctx *monitor) getAppInstancesStatus() []types.AppInstanceStatus {
	sub := ctx.subscriptions["AppStatus"]
	items := sub.GetAll()
	apps := make([]types.AppInstanceStatus, 0)
	for _, item := range items {
		appSummary := item.(types.AppInstanceStatus)
		apps = append(apps, appSummary)
	}
	return apps
}

func (ctx *monitor) getZedAgentStatus() types.ZedAgentStatus {
	var err error
	sub := ctx.subscriptions["ZedAgentStatus"]
	if item, err := sub.Get("global"); err == nil {
		zedAgentStatus := item.(types.ZedAgentStatus)
		return zedAgentStatus
	}
	log.Errorf("Failed to get ZedAgentStatus %s", err)
	return types.ZedAgentStatus{}
}

func (ctx *monitor) sendAppsList() {
	// send the application list to the client
	// empty list is allowed
	appStatus := ctx.getAppInstancesStatus()
	apps := appInstancesStatus{
		Apps: appStatus,
	}
	ctx.IPCServer.sendIpcMessage("AppsList", apps)
}

func readEfiVars(fsys fs.FS) ([]efiVariable, error) {
	vars, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}

	// read boot order
	bootOrder, err := fs.ReadFile(fsys, "BootOrder")
	if err != nil {
		return nil, err
	}

	// read boot variables
	bootVars := make([]efiVariable, 0)
	for _, varFile := range vars {
		varName := varFile.Name()
		if varFile.IsDir() || !bootVariableRe.MatchString(varName) {
			continue
		}
		varValue, err := fs.ReadFile(fsys, varName)
		if err != nil {
			return nil, err
		}
		bootVars = append(bootVars, efiVariable{Name: varName, Value: varValue})
	}

	bootVars = append(bootVars, efiVariable{Name: "BootOrder", Value: bootOrder})

	return bootVars, nil
}

func (ctx *monitor) sendTpmLogs() {
	currentGoodTpmLog, currentFailedTpmLog := evetpm.GetTpmLogFileNames()
	backupGoodTpmLog, backupFailedTpmLog := evetpm.GetTpmLogBackupFileNames()

	goodLog, err := os.ReadFile(currentGoodTpmLog)

	if err != nil {
		log.Warnf("Cannot read last good TPM log: %v", err)
		goodLog = nil
	}

	failedLog, err := os.ReadFile(currentFailedTpmLog)
	if err != nil {
		log.Warnf("Cannot read failed TPM log: %v", err)
		failedLog = nil
	}

	// backup logs
	backupGoodLog, err := os.ReadFile(backupGoodTpmLog)
	if err != nil {
		log.Warnf("Cannot read backup good TPM log: %v", err)
		backupGoodLog = nil
	}

	backupFailedLog, err := os.ReadFile(backupFailedTpmLog)
	if err != nil {
		log.Warnf("Cannot read backup failed TPM log: %v", err)
		backupFailedLog = nil
	}

	efiVarsDirSuccess, efiVarsDirFailed := evetpm.GetBootVariablesDirNames()

	bootVarsSuccess, err := readEfiVars(os.DirFS(efiVarsDirSuccess))
	if err != nil {
		log.Warnf("Cannot read boot variables: %v", err)
		bootVarsSuccess = nil
	}

	bootVarsFailed, err := readEfiVars(os.DirFS(efiVarsDirFailed))
	if err != nil {
		log.Warnf("Cannot read boot variables: %v", err)
		bootVarsFailed = nil
	}

	tpmLogs := tpmLogs{
		LastFailedLog:   failedLog,
		LastGoodLog:     goodLog,
		BackupFailedLog: backupFailedLog,
		BackupGoodLog:   backupGoodLog,
		EfiVarsSuccess:  bootVarsSuccess,
		EfiVarsFailed:   bootVarsFailed,
	}

	ctx.IPCServer.sendIpcMessage("TpmLogs", tpmLogs)
}

func (ctx *monitor) processGlobalConfig(cfg *types.ConfigItemValueMap) {
	if cfg == nil {
		return
	}

	logLevel := cfg.GlobalValueString(types.TUIMonitorLogLevel)

	tuiConfig := tuiConfig{
		LogLevel: logLevel,
	}

	ctx.IPCServer.sendIpcMessage("TUIConfig", tuiConfig)
}
