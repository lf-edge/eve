// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker

import "fmt"

// JobInProgressError indicates a job in progress
type JobInProgressError struct {
	s string
}

func (e *JobInProgressError) Error() string {
	return e.s
}

// PoolFullError indicates that a Pool refused a submission because it already
// runs maxWorkers concurrent jobs. Unlike JobInProgressError this is not
// benign: nothing owns the refused work, so the caller must keep enough state
// to submit it again later (or must not commit state that assumes the job
// will run).
type PoolFullError struct {
	maxWorkers int
}

func (e *PoolFullError) Error() string {
	return fmt.Sprintf("Would exceed maxWorkers of %d", e.maxWorkers)
}
