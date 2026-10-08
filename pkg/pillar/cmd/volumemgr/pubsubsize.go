// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import "github.com/lf-edge/eve/pkg/pillar/types"

// cutErrorIfOversized cuts the error of the status published under key down
// to types.OversizedStatusErrorLen when checkSize reports that the status
// does not fit a pubsub message, instead of letting the publish kill the
// agent, and reports whether it had to. A status without an error has
// nothing this agent could have grown past the limit and is not checked.
func cutErrorIfOversized(key string, checkSize func() error, errStr *string) bool {
	if *errStr == "" {
		return false
	}
	err := checkSize()
	if err == nil {
		return false
	}
	log.Errorf("status %s does not fit a pubsub message (%v): cutting its error to %d bytes",
		key, err, types.OversizedStatusErrorLen)
	*errStr = types.TruncateError(*errStr, types.OversizedStatusErrorLen)
	return true
}
