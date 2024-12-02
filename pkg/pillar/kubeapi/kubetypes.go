// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubeapi

import "time"

// DrainStatus tracks progress of draining a node of replica disks and workloads
type DrainStatus uint8

const (
	UNKNOWN       DrainStatus = iota + 0 // UNKNOWN Unable to determine
	NOTSUPPORTED                         // NOTSUPPORTED System not (HV=kubevirt and clustered)
	NOTREQUESTED                         // NOTREQUESTED Not yet requested
	REQUESTED                            // REQUESTED From zedagent device operation or baseosmgr new update
	STARTING                             // STARTING Zedkube go routine started, not yet cordoned
	CORDONED                             // CORDONED Node Unschedulable set
	FAILEDCORDON                         // FAILEDCORDON Node modification unable to apply
	DRAINRETRYING                        // DRAINRETRYING Drain retry in progress, could be retried replica rebuild
	FAILEDDRAIN                          // FAILEDDRAIN Could be retried replica rebuild
	COMPLETE                             // COMPLETE All node workloads removed from system
)

func (status DrainStatus) String() string {
	switch status {
	case UNKNOWN:
		return "Unknown"
	case NOTSUPPORTED:
		return "Not Supported"
	case NOTREQUESTED:
		return "Not Requested"
	case REQUESTED:
		return "Requested"
	case STARTING:
		return "Starting"
	case CORDONED:
		return "Cordoned"
	case FAILEDCORDON:
		return "Failed Cordon"
	case DRAINRETRYING:
		return "Drain Retrying"
	case FAILEDDRAIN:
		return "Failed Drain"
	case COMPLETE:
		return "Complete"
	default:
		return "Unknown"
	}
}

// DrainRequester is a user initiated edge-node operation from a pillar microservice
type DrainRequester uint8

const (
	NONE     DrainRequester = iota + 1 // NONE - The default value
	DEVICEOP                           // DEVICEOP - Node Reboot or shutdown
	UPDATE                             // UPDATE - baseos update
)

// NodeDrainRequest is the trigger to NodeDrainStatus
//
//	Used by Reboots, Prepare-Shutdown, baseos updates
type NodeDrainRequest struct {
	RequestedAt time.Time
	RequestedBy DrainRequester
	Context     string
}

// NodeDrainStatus is a response to NodeDrainRequest
//
//	Subscribe to updates to continue NodeDrainRequest operations.
type NodeDrainStatus struct {
	Status      DrainStatus
	RequestedBy DrainRequester
}
