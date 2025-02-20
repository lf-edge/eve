// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"io/fs"
	"regexp"

	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

var bootVariableRe = regexp.MustCompile(`^Boot[0-9a-fA-F]{4}$`)

type efiVariable struct {
	Name  string `json:"name,omitempty"`
	Value []byte `json:"value,omitempty"`
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
