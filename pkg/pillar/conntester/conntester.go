// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package conntester

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// ConnectivityTester allows to probe the state of external connectivity.
// It is not required for ConnectivityTester to be thread-safe.
type ConnectivityTester interface {
	// TestConnectivity returns nil error if connectivity test has passed.
	// Additionally it returns test result for each tested device network interface.
	TestConnectivity(dns types.DeviceNetworkStatus) (types.IntfStatusMap, error)
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
