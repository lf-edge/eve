// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package worker provides utilities for creating background workers to perform tasks,
// usually those that need to be queued up or will take a long time to run, thus potentially
// blocking the main thread.
//
// You start by creating a worker with NewWorker, indicating the queue depth and a few other parameters.
// Most important is the handlers, or actual functions that get called by the background task when a job
// is processed. Because there are different kinds of tasks, the handlers are keyed off of a `Kind`, just an
// arbitrary string. When creating a Worker, you pass it a map of Kind to handlers. When the Worker
// receives tasks, it finds the appropriate request Handler to process the task, and then, when done,
// calls the response handler, if any.
//
// The Worker has a func call, `C()` or `MsgChan()` that returns a channel sending completed task
// Processors. Your main thread is responsible for calling the `Process()` function on the Processor,
// to enable it to process the completed task. This *must* be done in your thread, so that it can be
// handled correctly. Only work processing is done in the worker thread; response should be handled in your
// thread.
//
// The Process() function will do two things. First, if you registered a response handler when
// creating the NewWorker, it will call that response handler. Second, if the original task was given
// a unique key, when done, it will keep the results in a cache, ready to be provided upon request.
// You can retrieve that response by calling Peek (retrieve without removing) or Pop (retrieve and remove).
//
// This gives you the option to process responses asynchronously via the response handler, synchronously
// by retrieving via key, or both.
package worker
