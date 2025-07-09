package conntrack

import "errors"

var (
	errNotConntrack     = errors.New("trying to decode a non-conntrack or conntrack-exp message")
	errConnHasListeners = errors.New("Conn has existing listeners, open another to listen on more groups")
	errMultipartEvent   = errors.New("received multicast event with more than one Netlink message")

	errUnknownAttribute = errors.New("unknown attribute")
	errUnknownEventType = errors.New("unknown event")

	errNotNested       = errors.New("needs to be a nested attribute")
	errNeedSingleChild = errors.New("need (at least) 1 child attribute")
	errNeedChildren    = errors.New("need (at least) 2 child attributes")
	errIncorrectSize   = errors.New("binary attribute data has incorrect size")

	errReusedEvent     = errors.New("cannot to unmarshal into existing Event")
	errReusedProtoInfo = errors.New("cannot to unmarshal into existing ProtoInfo")

	errBadIPTuple = errors.New("IPTuple source and destination must be valid addresses of the same family")

	errNeedTimeout = errors.New("Flow needs Timeout field set for this operation")
	errNeedTuples  = errors.New("Flow needs Original and Reply Tuple set for this operation")

	errUpdateMaster = errors.New("cannot send TupleMaster in Flow update")

	errExpectNeedTuples = errors.New("Expect needs Tuple, Mask and TupleMaster Tuples set for this operation")

	errNoWorkers = errors.New("number of workers to start cannot be 0")
)
