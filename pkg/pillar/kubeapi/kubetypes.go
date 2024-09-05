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
	Hostname    string
	RequestedAt time.Time
	RequestedBy DrainRequester
}

// NodeDrainStatus is a response to NodeDrainRequest
//
//	Subscribe to updates to continue NodeDrainRequest operations.
type NodeDrainStatus struct {
	Status      DrainStatus
	RequestedBy DrainRequester
}
