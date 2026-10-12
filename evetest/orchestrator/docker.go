// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// gracefulStopTimeout bounds how long "docker stop" waits for the instance to
// clean up its VMs before the container is killed.
const gracefulStopTimeout = "90"

// DockerExecutor runs jobs as sibling containers through the Docker daemon.
type DockerExecutor struct {
	// Image of the evetest container.
	Image string
	// RunID labels the containers, to tell which run started them.
	RunID string
	// CommonArgs are the "docker run" options shared by all jobs (mounts,
	// devices, environment), as assembled by the Makefile.
	CommonArgs []string
	// ArtifactsHostDir, if set, is mounted at /artifacts of every job.
	ArtifactsHostDir string
	// ColorOutput ("true" or "false") is the default for EVETEST_COLOR_OUTPUT.
	// The user may override it through CommonArgs.
	ColorOutput string
	// Interactive gives the container a terminal and stdin (docker run -it),
	// for jobs which run in a terminal of their own.
	Interactive bool
}

func (d *DockerExecutor) runArgs(job *Job) []string {
	port := fmt.Sprint(job.Port)
	args := []string{"run", "--rm"}
	if d.Interactive {
		args = append(args, "-it")
	}
	args = append(args,
		"--name", job.Container,
		"-p", port+":"+port,
		"--label", "org.lfedge.evetest.run="+d.RunID,
		"--label", "org.lfedge.evetest.name="+job.Name)
	if d.ColorOutput != "" {
		args = append(args, "-e", "EVETEST_COLOR_OUTPUT="+d.ColorOutput)
	}
	if d.ArtifactsHostDir != "" {
		args = append(args, "-v", d.ArtifactsHostDir+":/artifacts")
	}
	args = append(args, d.CommonArgs...)
	return append(args,
		"-e", "EVETEST_NAME="+job.Name,
		"-e", "EVETEST_API_PORT="+port,
		"-e", "EVETEST_CONTAINER_NAME="+job.Container,
		d.Image)
}

// Run implements Executor.
func (d *DockerExecutor) Run(ctx context.Context, job *Job, out *LineWriter) (int, error) {
	cmd := exec.Command("docker", d.runArgs(job)...)
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		return -1, err
	}

	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			_ = exec.Command("docker", "stop", "-t", gracefulStopTimeout, job.Container).Run()
		case <-done:
		}
	}()
	err := cmd.Wait()
	close(done)
	<-stopped

	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &exitErr):
		code := exitErr.ExitCode()
		// 125 is "docker run" itself failing, e.g. to publish the port.
		if code == 125 && portBusy(job.Tail()) {
			return code, ErrPortBusy
		}
		return code, nil
	}
	return -1, err
}

func portBusy(tail []string) bool {
	for _, line := range tail {
		if strings.Contains(line, "port is already allocated") ||
			strings.Contains(line, "address already in use") {
			return true
		}
	}
	return false
}

// Kill implements Executor.
func (d *DockerExecutor) Kill(job *Job) {
	_ = exec.Command("docker", "kill", job.Container).Run()
}

// orchestratorContainerPrefix is what the Makefile names the orchestrator
// container of a run with, followed by the run id (which also names the
// directory of the run's logs).
const orchestratorContainerPrefix = "evetest-orchestrator-"

// RunActive tells whether the orchestrator of the run is running. An
// error means that Docker could not tell.
func RunActive(runID string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "inspect", "--type", "container",
		"-f", "{{.State.Running}}", orchestratorContainerPrefix+runID).CombinedOutput()
	if err == nil {
		return strings.TrimSpace(string(out)) == "true", nil
	}
	if strings.Contains(string(out), "No such") {
		return false, nil
	}
	return false, fmt.Errorf("docker inspect: %w: %s", err, strings.TrimSpace(string(out)))
}

// ContainerExists tells whether a container (in any state) of the name exists.
func ContainerExists(name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "docker", "inspect", "--type", "container", name).Run() == nil
}
