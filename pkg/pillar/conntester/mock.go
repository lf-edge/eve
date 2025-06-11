// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package conntester

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/netdump"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// MockConnectivityTester is used for unit testing.
type MockConnectivityTester struct {
	sync.Mutex
	TestDuration   time.Duration             // inject
	NetworkMonitor netmonitor.NetworkMonitor // inject

	iteration  int
	connErrors map[ifRef]error
}

type ifRef struct {
	dpcKey string
	ifName string
}

// SetConnectivityError : allows to simulate failing connectivity for an interface
// with a config from a given DPC.
// With nil error value, any previously set error is removed.
func (t *MockConnectivityTester) SetConnectivityError(dpcKey, ifName string, err error) {
	t.Lock()
	defer t.Unlock()
	if t.connErrors == nil {
		t.connErrors = make(map[ifRef]error)
	}
	ifRef := ifRef{dpcKey: dpcKey, ifName: ifName}
	if err == nil {
		delete(t.connErrors, ifRef)
	} else {
		t.connErrors[ifRef] = err
	}
}

// TestConnectivity simulates connectivity test.
func (t *MockConnectivityTester) TestConnectivity(
	dns types.DeviceNetworkStatus, airGapMode AirGapMode, withNetTrace bool) (
	intfStatusMap types.IntfStatusMap, tracedReqs []netdump.TracedNetRequest, err error) {
	t.Lock()
	defer t.Unlock()

	var (
		successCount  uint
		errorList     []error
		nonRtfErrs    bool
		rtfErr        error
		portsNotReady []string
	)
	t.iteration++
	intfStatusMap = *types.NewIntfStatusMap()

	intfs := types.GetMgmtPortsSortedCost(dns, t.iteration)
	if len(intfs) == 0 {
		err = errors.New("no management interfaces")
		return intfStatusMap, nil, err
	}

	for _, ifName := range intfs {
		if successCount >= requiredSuccessCount {
			// We have enough uplinks with controller connectivity working.
			break
		}
		if _, exists, _ := t.NetworkMonitor.GetInterfaceIndex(ifName); !exists {
			err = fmt.Errorf("interface %s is missing", ifName)
			errorList = append(errorList, err)
			intfStatusMap.RecordFailure(ifName, err.Error())
			continue
		}
		port := dns.LookupPortByIfName(ifName)
		if !port.IsMgmt {
			continue
		}
		if len(port.AddrInfoList) == 0 {
			err := &types.IPAddrNotAvailError{IfName: ifName}
			errorList = append(errorList, err)
			intfStatusMap.RecordFailure(ifName, err.Error())
			continue
		}
		time.Sleep(t.TestDuration)
		ifRef := ifRef{dpcKey: dns.DPCKey, ifName: ifName}
		err = t.connErrors[ifRef]
		if _, rtf := err.(*RemoteTemporaryFailure); rtf {
			rtfErr = err
		} else {
			nonRtfErrs = true
		}
		if _, noDNSErr := err.(*types.DNSNotAvailError); noDNSErr {
			portsNotReady = append(portsNotReady, port.Logicallabel)
		}
		if _, noIPErr := err.(*types.IPAddrNotAvailError); noIPErr {
			portsNotReady = append(portsNotReady, port.Logicallabel)
		}
		if err != nil {
			errorList = append(errorList, err)
			intfStatusMap.RecordFailure(ifName, err.Error())
		} else {
			successCount++
			intfStatusMap.RecordSuccess(ifName)
		}
	}

	if successCount < requiredSuccessCount {
		err = fmt.Errorf("not enough working ports (%d); failed with: %v",
			successCount, errorList)
		if len(portsNotReady) > 0 {
			return intfStatusMap, nil, &PortsNotReady{
				WrappedErr: err,
				Ports:      portsNotReady,
			}
		}
		if nonRtfErrs || rtfErr == nil {
			return intfStatusMap, nil, err
		}
		// RTF error(s) only.
		return intfStatusMap, nil, rtfErr
	}
	return intfStatusMap, nil, nil
}
