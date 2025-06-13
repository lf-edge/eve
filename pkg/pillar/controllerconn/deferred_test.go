// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package controllerconn_test

import (
	"bytes"
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/netdump"
	"github.com/sirupsen/logrus"
	"net"
	"sync"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

type sendOperation struct {
	itemType interface{}
	data     *bytes.Buffer
	result   types.SenderStatus
	traces   []netdump.TracedNetRequest
}

func TestDeferredQueue(test *testing.T) {
	var executedSendOps []sendOperation
	var sentHandlerMutex sync.Mutex
	sentHandler := func(itemType interface{}, data *bytes.Buffer, result types.SenderStatus,
		traces []netdump.TracedNetRequest) {
		sentHandlerMutex.Lock()
		defer sentHandlerMutex.Unlock()
		if result == types.SenderStatusDebug {
			// not actually sent
			return
		}
		sendOp := sendOperation{
			itemType: itemType,
			data:     data,
			result:   result,
			traces:   traces,
		}
		executedSendOps = append(executedSendOps, sendOp)
	}

	countOfExecutedSendOps := func() int {
		sentHandlerMutex.Lock()
		defer sentHandlerMutex.Unlock()
		return len(executedSendOps)
	}

	dns := getDeviceNetworkStatus(test)
	// Add a fake port with no IPs (should be skipped by SendOnAllIntf)
	unusedName := getUnusedInterfaceName()
	fakePort := types.NetworkPortStatus{
		IfName:         unusedName,
		Phylabel:       unusedName,
		Logicallabel:   unusedName,
		IsMgmt:         true,
		IsL3Port:       true,
		Up:             false,
		AddrInfoList:   []types.AddrInfo{},
		DefaultRouters: []net.IP{},
	}
	dns.Ports = append(dns.Ports, fakePort)
	fmt.Printf("DeviceNetworkStatus %+v\n", dns)
	agentMetrics := controllerconn.NewAgentMetrics()
	client := makeControllerClient(test, &dns, agentMetrics)

	logger := logrus.StandardLogger()
	logObj = base.NewSourceLogObject(logger, "test", 1234)
	queue := controllerconn.CreateDeferredQueue(logObj, client, nil, "unittest",
		"deferred-send-operation", 15*time.Second, 20*time.Second, sentHandler)

	buf := bytes.NewBufferString("foo=bar")
	queue.SetDeferred("test1", buf, "https://postman-echo.com/post", nil,
		controllerconn.DeferredItemOpts{
			BailOnHTTPErr:    false,
			WithNetTracing:   false,
			IgnoreErr:        false,
			SuppressLogs:     false,
			AllowLoopbackDNS: true,
		})
	queue.KickTimerNow()

	t := NewGomegaWithT(test)
	t.Eventually(countOfExecutedSendOps, 10*time.Second, 100*time.Millisecond).Should(Equal(1))
	sendOp := executedSendOps[0]
	t.Expect(sendOp.result).To(Equal(types.SenderStatusNone))
	t.Expect(sendOp.traces).To(BeEmpty())
}

func TestDeferredQueue_NoUsablePorts(test *testing.T) {
	var executedSendOps []sendOperation
	var sentHandlerMutex sync.Mutex
	sentHandler := func(itemType interface{}, data *bytes.Buffer, result types.SenderStatus,
		traces []netdump.TracedNetRequest) {
		sentHandlerMutex.Lock()
		defer sentHandlerMutex.Unlock()
		if result == types.SenderStatusDebug {
			// not actually sent
			return
		}
		sendOp := sendOperation{
			itemType: itemType,
			data:     data,
			result:   result,
			traces:   traces,
		}
		executedSendOps = append(executedSendOps, sendOp)
	}

	countOfExecutedSendOps := func() int {
		sentHandlerMutex.Lock()
		defer sentHandlerMutex.Unlock()
		return len(executedSendOps)
	}

	// Create DeviceNetworkStatus with only fake, unusable ports
	var dns types.DeviceNetworkStatus
	for i := 0; i < 2; i++ {
		unusedName := getUnusedInterfaceName()
		fakePort := types.NetworkPortStatus{
			IfName:         unusedName,
			Phylabel:       unusedName,
			Logicallabel:   unusedName,
			IsMgmt:         true,
			IsL3Port:       true,
			Up:             false,
			AddrInfoList:   []types.AddrInfo{},
			DefaultRouters: []net.IP{},
		}
		dns.Ports = append(dns.Ports, fakePort)
	}
	fmt.Printf("DeviceNetworkStatus %+v\n", dns)
	agentMetrics := controllerconn.NewAgentMetrics()
	client := makeControllerClient(test, &dns, agentMetrics)

	logger := logrus.StandardLogger()
	logObj = base.NewSourceLogObject(logger, "test", 1234)
	queue := controllerconn.CreateDeferredQueue(logObj, client, nil, "unittest",
		"deferred-send-operation", 15*time.Second, 20*time.Second, sentHandler)

	buf := bytes.NewBufferString("foo=bar")
	queue.SetDeferred("test1", buf, "https://postman-echo.com/post", nil,
		controllerconn.DeferredItemOpts{
			BailOnHTTPErr:  false,
			WithNetTracing: false,
			// We will ignore errors (but we will check the sendOp.result value below)
			IgnoreErr:        true,
			SuppressLogs:     false,
			AllowLoopbackDNS: true,
		})
	queue.KickTimerNow()

	t := NewGomegaWithT(test)
	t.Eventually(countOfExecutedSendOps, 10*time.Second, 100*time.Millisecond).Should(Equal(1))
	sendOp := executedSendOps[0]
	t.Expect(sendOp.result).To(Equal(types.SenderStatusFailed))
	t.Expect(sendOp.traces).To(BeEmpty())
}
