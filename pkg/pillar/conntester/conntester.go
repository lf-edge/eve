// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package conntester

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/netdump"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// ConnectivityTester allows to probe the state of external connectivity.
// It is not required for ConnectivityTester to be thread-safe.
type ConnectivityTester interface {
	// TestConnectivity returns nil error if connectivity test has passed.
	// Additionally, it returns test result for each tested device network interface
	// and network traces of executed probes if withNetTrace was enabled.
	TestConnectivity(dns types.DeviceNetworkStatus,
		withNetTrace bool) (types.IntfStatusMap, []netdump.TracedNetRequest, error)
}

// RemoteTemporaryFailure can be returned by TestConnectivity to indicate that test failed
// due to a remote failure (i.e. the remote endpoint is accessible but fails to respond
// to the test properly).
type RemoteTemporaryFailure struct {
	Endpoint   string
	WrappedErr error
}

// Error message.
func (e *RemoteTemporaryFailure) Error() string {
	return fmt.Sprintf("Remote temporary failure (endpoint: %s): %v",
		e.Endpoint, e.WrappedErr)
}

// Unwrap : return wrapped error.
func (e *RemoteTemporaryFailure) Unwrap() error {
	return e.WrappedErr
}

// PortsNotReady can be returned by TestConnectivity to indicate that one or more
// ports do not have working connectivity due to a potentially transient error
// (e.g. missing DNS config, no suitable IP addresses, etc.).
// For the caller this is a signal to possibly wait and repeat the test later.
type PortsNotReady struct {
	WrappedErr error
	// Ports which are not ready.
	Ports []string
}

// Error message.
func (e *PortsNotReady) Error() string {
	return fmt.Sprintf("Ports %v are not ready: %v", e.Ports, e.WrappedErr)
}

// Unwrap : return wrapped error.
func (e *PortsNotReady) Unwrap() error {
	return e.WrappedErr
}
