// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"encoding/json"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

func newTestMonitorCtx(t *testing.T) *monitor {
	logger = logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, "test", 1234)

	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)
	pubDevicePortConfig, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.DevicePortConfig{},
		})
	if err != nil {
		t.Fatalf("failed to create DevicePortConfig publication: %v", err)
	}

	ctx := newMonitorContext()
	ctx.pubDevicePortConfig = pubDevicePortConfig
	return ctx
}

func TestRevertManualConfigUnpublishesManualDPC(t *testing.T) {
	ctx := newTestMonitorCtx(t)

	manualDPC := types.DevicePortConfig{Key: types.ManualDPCKey}
	if err := ctx.pubDevicePortConfig.Publish(manualDPC.Key, manualDPC); err != nil {
		t.Fatalf("failed to publish manual DPC: %v", err)
	}

	req := &request{
		ID:          1,
		RequestType: "RevertManualConfig",
		RequestData: json.RawMessage(`{}`),
	}
	if err := req.validate(); err != nil {
		t.Fatalf("expected request to validate, got: %v", err)
	}

	resp := req.handleRequest(ctx)
	if resp.Err != "" {
		t.Fatalf("expected ok response, got error: %s", resp.Err)
	}
	if resp.Ok != "ok" {
		t.Fatalf("expected Ok response, got: %+v", resp)
	}

	if _, err := ctx.pubDevicePortConfig.Get(types.ManualDPCKey); err == nil {
		t.Fatal("expected manual DPC to be unpublished, but it is still present")
	}
}

func TestRevertManualConfigWithoutManualDPCReturnsError(t *testing.T) {
	ctx := newTestMonitorCtx(t)

	req := &request{
		ID:          1,
		RequestType: "RevertManualConfig",
		RequestData: json.RawMessage(`{}`),
	}
	resp := req.handleRequest(ctx)
	if resp.Err == "" {
		t.Fatal("expected an error response when no manual DPC is currently published")
	}
}
