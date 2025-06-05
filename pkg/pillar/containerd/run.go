// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package containerd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"syscall"
	"time"

	ctrdd "github.com/containerd/containerd"
	"github.com/opencontainers/runtime-spec/specs-go"
)

type mutexWriter struct {
	w     io.Writer
	mutex *sync.Mutex
}

func (m mutexWriter) Write(p []byte) (n int, err error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	// seems containerd sometimes wants to write something into it,
	// but it is already too late
	if m.w == nil {
		return 0, syscall.ENOENT
	}
	n, err = m.w.Write(p)

	return n, err
}

// RunInDebugContainer runs a program in the debug container
func RunInDebugContainer(clientCtx context.Context, taskID string, w io.Writer, args []string, timeout time.Duration) error {
	ctrd, err := NewContainerdClient(false)
	if err != nil {
		return fmt.Errorf("could not initialize containerd client: %+v\n", err)
	}

	ctx, done := ctrd.CtrNewSystemServicesCtx()
	defer done()

	container, err := ctrd.CtrLoadContainer(ctx, "debug")
	if err != nil {
		return fmt.Errorf("loading container failed: %+v", err)
	}

	task, err := container.Task(ctx, nil)
	if err != nil {
		return fmt.Errorf("getting debug container task failed: %+v", err)
	}

	pspec := specs.Process{
		Args: args,
		Cwd:  "/",
		Scheduler: &specs.Scheduler{
			Deadline: uint64(time.Now().Add(timeout).Unix()),
		},
	}
	stderrBuf := bytes.Buffer{}

	writingDone := make(chan struct{})
	defer close(writingDone)
	mutexWriter := mutexWriter{
		w:     w,
		mutex: &sync.Mutex{},
	}
	stdcio := ctrd.CtrWriterCreator(mutexWriter, &stderrBuf)

	process, err := task.Exec(ctx, taskID, &pspec, stdcio)
	if err != nil {
		return fmt.Errorf("executing in task failed: %+v", err)
	}
	waiter, err := process.Wait(ctx)
	if err != nil {
		return fmt.Errorf("process wait failed: %+v", err)
	}
	err = process.Start(ctx)
	if err != nil {
		return fmt.Errorf("process start failed: %+v", err)
	}

	exitStatus := struct {
		exitCode        uint32
		killedByTimeout bool
	}{
		exitCode:        0,
		killedByTimeout: false,
	}

	timeoutTimer := time.NewTimer(timeout)
	select {
	case <-clientCtx.Done():
		exitStatus.killedByTimeout = true
		err := killProcess(ctx, process)
		if err != nil {
			return fmt.Errorf("writer closed - killing process %+v failed: %w", args, err)
		}
	case <-timeoutTimer.C:
		exitStatus.killedByTimeout = true
		err := killProcess(ctx, process)
		if err != nil {
			return fmt.Errorf("timeout - killing process %+v failed: %w", args, err)
		}
	case containerExitStatus := <-waiter:
		exitStatus.exitCode = containerExitStatus.ExitCode()
	}
	timeoutTimer.Stop()

	if !exitStatus.killedByTimeout {
		status, err := process.Delete(ctx)
		if err != nil {
			return fmt.Errorf("process delete (%+v) failed: %+v", status, err)
		}
	}

	stderrBytes, err := io.ReadAll(&stderrBuf)
	if len(stderrBytes) > 0 {
		return fmt.Errorf("Stderr output was: %s", string(stderrBytes))
	}

	mutexWriter.w = nil

	return nil
}

func killProcess(ctx context.Context, process ctrdd.Process) error {
	err := process.Kill(ctx, syscall.SIGTERM)
	if err != nil {
		return fmt.Errorf("timeout reached, killing of process failed: %w", err)
	}
	time.Sleep(time.Second)
	st, err := process.Status(ctx)
	if err != nil {
		return fmt.Errorf("timeout reached, retrieving status of process failed: %w", err)
	}
	if st.Status == ctrdd.Stopped {
		return nil
	}
	err = process.Kill(ctx, syscall.SIGKILL)
	if err != nil {
		return fmt.Errorf("timeout reached, killing of process (SIGKILL) failed: %w", err)
	}

	return nil
}
