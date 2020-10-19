// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

// JobInProgressError indicates a job in progress
type JobInProgressError struct {
	s string
}

func (e *JobInProgressError) Error() string {
	return e.s
}
