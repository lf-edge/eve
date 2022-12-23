// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nettrace

// networkTrace is a generic type used only internally to record and publish any network trace.
type networkTrace interface {
	isInternalNetTrace()
}

// networkTracer performs tracing of network operations.
// Currently, the only tracer implemented in this package is HTTPClient.
type networkTracer interface {
	// Get ID assigned to the tracer itself.
	getTracerID() TraceID
	// Get timestamp for the current time relative to when tracing started.
	getRelTimestamp() Timestamp
	// Publish newly recorded networkTrace into the queue for processing.
	publishTrace(networkTrace)
}
