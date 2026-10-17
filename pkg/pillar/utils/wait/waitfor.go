// Copyright (c) 2020-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package wait

import (
	"fmt"
	"strings"
	"time"

	info "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// Context is a helper struct used to pass around in pubsub handlers
type Context struct {
	Initialized bool
	Status      types.OnboardingStatus
}

// WaitForVault waits until it receives a types.VaultStatus msg, for types.DefaultVaultName
// and the status does not indicate any error
func WaitForVault(ps *pubsub.PubSub, log *base.LogObject, agentName string, warningTime, errorTime time.Duration) error {
	// Look for vault status
	Ctx := &Context{}
	subVaultStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "vaultmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.VaultStatus{},
		Activate:      false,
		Ctx:           Ctx,
		CreateHandler: handleVaultStatusCreate,
		ModifyHandler: handleVaultStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return err
	}

	subVaultStatus.Activate()

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Wait for vault to be ready, which might be delayed due to attestation
	for !Ctx.Initialized {
		log.Functionf("Waiting for VaultStatus initialized")
		select {
		case change := <-subVaultStatus.MsgChan():
			subVaultStatus.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	subVaultStatus.Close()
	stillRunning.Stop()
	return nil
}

func handleVaultStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleVaultStatusImpl(ctxArg, key, statusArg)
}

func handleVaultStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleVaultStatusImpl(ctxArg, key, statusArg)
}

func handleVaultStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*Context)
	vault := statusArg.(types.VaultStatus)
	if vault.Name == types.DefaultVaultName && vault.ConversionComplete &&
		vault.Status != info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR {
		ctx.Initialized = true
	}
}

// WaitForOnboarded waits until it receives a types.OnboardingStatus msg with
// a non-zero UUID
func WaitForOnboarded(ps *pubsub.PubSub, log *base.LogObject, agentName string, warningTime, errorTime time.Duration) (types.OnboardingStatus, error) {
	// Look for vault status
	Ctx := &Context{}
	subOnboardStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedclient",
		MyAgentName:   agentName,
		TopicImpl:     types.OnboardingStatus{},
		Activate:      true,
		Persistent:    true,
		Ctx:           Ctx,
		CreateHandler: handleOnboardStatusCreate,
		ModifyHandler: handleOnboardStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return types.OnboardingStatus{}, err
	}

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Wait for Onboarding to be done by client
	for !Ctx.Initialized {
		log.Functionf("Waiting for OnboardStatus initialized")
		select {
		case change := <-subOnboardStatus.MsgChan():
			subOnboardStatus.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	stillRunning.Stop()
	subOnboardStatus.Close()
	return Ctx.Status, nil
}

// Really a constant
var nilUUID = uuid.UUID{}

// Set Initialized if the UUID is not nil
func handleOnboardStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleOnboardStatusImpl(ctxArg, key, statusArg)
}

func handleOnboardStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleOnboardStatusImpl(ctxArg, key, statusArg)
}

func handleOnboardStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.OnboardingStatus)
	ctx := ctxArg.(*Context)

	if status.DeviceUUID == nilUUID {
		return
	}
	ctx.Status = status
	ctx.Initialized = true
}

// NodeNameFromDeviceName converts an EdgeNodeInfo.DeviceName into the Kubernetes
// node name that k3s registers this node under: lower-cased with underscores
// replaced by hyphens. This normalization must match convert_to_k8s_compatible
// in pkg/kube/cluster-utils.sh; keep them in sync.
func NodeNameFromDeviceName(deviceName string) string {
	return strings.ReplaceAll(strings.ToLower(deviceName), "_", "-")
}

// edgeNodeInfoContext carries the resolved EdgeNodeInfo out of the handlers.
type edgeNodeInfoContext struct {
	info  types.EdgeNodeInfo
	found bool
}

// WaitForEdgeNodeInfo waits for zedagent to publish an EdgeNodeInfo with a
// non-empty DeviceName and returns it. EdgeNodeInfo is static for the lifetime
// of a boot, so a single up-front wait is enough; callers need not keep a
// long-lived subscription to react to later updates. If timeout > 0 it returns
// an error should the info not arrive within that window; timeout == 0 waits
// indefinitely. The watchdog is kicked throughout.
//
//revive:disable-next-line:exported // WaitFor* naming matches WaitForVault/WaitForOnboarded in this package
func WaitForEdgeNodeInfo(ps *pubsub.PubSub, log *base.LogObject, agentName string,
	warningTime, errorTime, timeout time.Duration) (types.EdgeNodeInfo, error) {

	nctx := &edgeNodeInfoContext{}
	sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.EdgeNodeInfo{},
		Activate:      false,
		Ctx:           nctx,
		CreateHandler: handleEdgeNodeInfoCreate,
		ModifyHandler: handleEdgeNodeInfoModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return types.EdgeNodeInfo{}, err
	}
	sub.Activate()
	defer sub.Close()

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	defer stillRunning.Stop()
	ps.StillRunning(agentName, warningTime, errorTime)

	var timeoutCh <-chan time.Time
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		timeoutCh = timer.C
	}

	for !nctx.found {
		log.Functionf("Waiting for EdgeNodeInfo DeviceName")
		select {
		case change := <-sub.MsgChan():
			sub.ProcessChange(change)
		case <-timeoutCh:
			return types.EdgeNodeInfo{}, fmt.Errorf("timeout waiting for EdgeNodeInfo DeviceName")
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	return nctx.info, nil
}

// WaitForNodeName waits for a non-empty EdgeNodeInfo.DeviceName and returns the
// derived Kubernetes node name (see NodeNameFromDeviceName). Timeout and watchdog
// semantics match WaitForEdgeNodeInfo.
//
//revive:disable-next-line:exported // WaitFor* naming matches WaitForVault/WaitForOnboarded in this package
func WaitForNodeName(ps *pubsub.PubSub, log *base.LogObject, agentName string,
	warningTime, errorTime, timeout time.Duration) (string, error) {

	enInfo, err := WaitForEdgeNodeInfo(ps, log, agentName, warningTime, errorTime, timeout)
	if err != nil {
		return "", err
	}
	return NodeNameFromDeviceName(enInfo.DeviceName), nil
}

func handleEdgeNodeInfoCreate(ctxArg interface{}, key string, statusArg interface{}) {
	handleEdgeNodeInfoImpl(ctxArg, statusArg)
}

func handleEdgeNodeInfoModify(ctxArg interface{}, key string, statusArg interface{}, _ interface{}) {
	handleEdgeNodeInfoImpl(ctxArg, statusArg)
}

func handleEdgeNodeInfoImpl(ctxArg interface{}, statusArg interface{}) {
	ctx := ctxArg.(*edgeNodeInfoContext)
	enInfo := statusArg.(types.EdgeNodeInfo)
	if enInfo.DeviceName == "" {
		return
	}
	ctx.info = enInfo
	ctx.found = true
}
