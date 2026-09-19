// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/sema"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// mapSubscription serves fixed items, the way a subscription looks to
// runHandler once the main loop has processed a change.
type mapSubscription struct {
	items map[string]interface{}
}

func (s *mapSubscription) Get(key string) (interface{}, error) {
	if v, ok := s.items[key]; ok {
		return v, nil
	}
	return nil, fmt.Errorf("%s not found", key)
}
func (s *mapSubscription) GetAll() map[string]interface{} { return s.items }
func (s *mapSubscription) Iterate(_ base.StrMapFunc)      {}
func (s *mapSubscription) Restarted() bool                { return false }
func (s *mapSubscription) RestartCounter() int            { return 0 }
func (s *mapSubscription) Synchronized() bool             { return true }
func (s *mapSubscription) ProcessChange(_ pubsub.Change)  {}
func (s *mapSubscription) MsgChan() <-chan pubsub.Change  { return nil }
func (s *mapSubscription) Activate() error                { return nil }
func (s *mapSubscription) Close() error                   { return nil }

// recordingTask is the hypervisor side of one domain, built on the null
// hypervisor's task so it tracks the types.Task interface of whichever
// branch it is compiled on. Setup applies the ownership check that the KVM,
// Xen and kubevirt backends run while rendering the domain config, but
// records the violation instead of logrus.Fatalf so the test can observe
// it. Create fails so a boot retry stops after Setup.
type recordingTask struct {
	types.Task
	infoState types.SwState
	notOurs   []string
}

func (r *recordingTask) Setup(status types.DomainStatus, config types.DomainConfig,
	aa *types.AssignableAdapters, _ *types.ConfigItemValueMap, _ *os.File) error {
	for _, adapter := range config.IoAdapterList {
		for _, ib := range aa.LookupIoBundleAny(adapter.Name) {
			if ib.UsedByUUID != config.UUIDandVersion.UUID {
				r.notOurs = append(r.notOurs, fmt.Sprintf(
					"IoBundle not ours %s: %d %s for %s",
					ib.UsedByUUID, adapter.Type, adapter.Name, status.DomainName))
			}
		}
	}
	return nil
}

func (r *recordingTask) Create(_ string, _ string, _ *types.DomainConfig) (int, error) {
	return 0, errors.New("recordingTask does not create domains")
}

func (r *recordingTask) Info(_ string) (int, types.SwState, error) {
	return 0, r.infoState, nil
}

// recordingHypervisor hands out the recording task and treats PCI
// reservation as a no-op; everything else comes from the null hypervisor.
type recordingHypervisor struct {
	hypervisor.Hypervisor
	task *recordingTask
}

func (h *recordingHypervisor) Task(_ *types.DomainStatus) types.Task { return h.task }
func (h *recordingHypervisor) PCIReserve(_ string) error             { return nil }
func (h *recordingHypervisor) PCIRelease(_ string) error             { return nil }

// newRecordingHypervisor swaps the package's hypervisor for a recording one
// for the duration of the test and returns its task.
func newRecordingHypervisor(t *testing.T) *recordingTask {
	t.Helper()
	null, err := hypervisor.GetHypervisor("null")
	if err != nil {
		t.Fatal(err)
	}
	task := &recordingTask{Task: null.Task(&types.DomainStatus{}), infoState: types.RUNNING}
	saved := hyper
	hyper = &recordingHypervisor{Hypervisor: null, task: task}
	t.Cleanup(func() { hyper = saved })
	return task
}

// newRetryBootContext wires the pubsub state that adapter reservation,
// verifyStatus, handleModify and maybeRetry touch.
func newRetryBootContext(t *testing.T, aa *types.AssignableAdapters,
	configs *mapSubscription) *domainContext {
	t.Helper()
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)
	newPub := func(topic interface{}) pubsub.Publication {
		pub, err := ps.NewPublication(pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: topic,
		})
		if err != nil {
			t.Fatal(err)
		}
		return pub
	}
	pubCap := newPub(types.Capabilities{})
	if err := pubCap.Publish("global", types.Capabilities{IOVirtualization: true}); err != nil {
		t.Fatal(err)
	}
	createSema := sema.New(log, 1)
	createSema.P(1)
	return &domainContext{
		assignableAdapters:    aa,
		pubAssignableAdapters: newPub(types.AssignableAdapters{}),
		pubCapabilities:       pubCap,
		pubDomainStatus:       newPub(types.DomainStatus{}),
		subDomainConfig:       configs,
		subGlobalConfig: &mapSubscription{items: map[string]interface{}{
			"global": *types.DefaultConfigItemValueMap(),
		}},
		subNodeAgentStatus:  &mapSubscription{},
		createSema:          createSema,
		domainBootRetryTime: 600,
	}
}

// TestRetryBootAfterAdaptersReleased reproduces the node crash
// "IoBundle not ours 0000...: 13 USB for <domain>". A domain with a pending
// boot retry is deactivated, which releases its adapters, and reactivated.
// When runHandler serves the status tick before the config notification, the
// retry renders a domain config for adapters the domain no longer holds. The
// real hypervisor backends call logrus.Fatalf there and the watchdog reboots
// the node.
func TestRetryBootAfterAdaptersReleased(t *testing.T) {
	appUUID, err := uuid.FromString("5df1b3a0-2c4e-4d6f-9a8b-7c6d5e4f3a21")
	if err != nil {
		t.Fatal(err)
	}
	config := types.DomainConfig{
		UUIDandVersion: types.UUIDandVersion{UUID: appUUID, Version: "1"},
		DisplayName:    "usb-app",
		Activate:       true,
		AppNum:         1,
		VmConfig: types.VmConfig{
			VirtualizationMode: types.HVM,
			DisableVirtualTPM:  true,
		},
		IoAdapterList: []types.IoAdapter{{Type: types.IoUSBController, Name: "USB"}},
	}
	aa := &types.AssignableAdapters{
		Initialized: true,
		IoBundleList: []types.IoBundle{{
			Type:            types.IoUSBController,
			Phylabel:        "USB0",
			Logicallabel:    "USB0",
			AssignmentGroup: "USB",
			PciLong:         "0000:00:14.0",
		}},
	}
	task := newRecordingHypervisor(t)
	configs := &mapSubscription{items: map[string]interface{}{config.Key(): config}}
	ctx := newRetryBootContext(t, aa, configs)

	// The domain runs with the USB controller reserved and assigned, as
	// doActivate leaves it.
	status := &types.DomainStatus{
		UUIDandVersion: config.UUIDandVersion,
		DisplayName:    config.DisplayName,
		DomainName:     config.GetTaskName(),
		AppNum:         config.AppNum,
		VmConfig:       config.VmConfig,
		State:          types.RUNNING,
		Activated:      true,
		DomainId:       7,
	}
	if d := reserveAdapters(ctx, config); d != nil {
		t.Fatalf("reserveAdapters: %s", d.Error)
	}
	status.IoAdapterList = config.IoAdapterList
	if err := doAssignIoAdaptersToDomain(ctx, config, status); err != nil {
		t.Fatal(err)
	}
	publishDomainStatus(ctx, status)

	// The guest dies. The status tick schedules a boot retry and keeps the
	// adapters reserved for it.
	task.infoState = types.HALTED
	verifyStatus(ctx, status)
	if !status.BootFailed {
		t.Fatal("verifyStatus did not schedule a boot retry")
	}

	// zedmanager restarts the app and first publishes Activate=false.
	// handleModify tears the domain down, which releases the adapters.
	inactive := config
	inactive.Activate = false
	configs.items[config.Key()] = inactive
	handleModify(ctx, config.Key(), &inactive, status)
	if got := aa.IoBundleList[0].UsedByUUID; got != nilUUID {
		t.Fatalf("deactivation did not release the adapter, still held by %s", got)
	}

	// zedmanager sees Activated=false and publishes Activate=true. The main
	// loop stores it in the subscription and queues a notification for
	// runHandler, whose select may serve a pending status tick first. This is
	// that tick.
	configs.items[config.Key()] = config
	verifyStatus(ctx, status)
	maybeRetry(ctx, status)

	if len(task.notOurs) != 0 {
		t.Fatalf("boot retry rendered a domain config for adapters the domain "+
			"does not hold; KVM, Xen and kubevirt Fatal here: %v", task.notOurs)
	}
}
