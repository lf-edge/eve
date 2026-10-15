// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/evetest/constants"
	"github.com/lf-edge/eve/evetest/instances"
	"github.com/lf-edge/eve/evetest/orchestrator"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

// runCommand runs several tests as parallel evetest instances. It is for
// internal use only: it is run by the Makefile in a container with the Docker
// socket and the evetest home directory mounted, on the host network (see
// "make evetest"), and is not supposed to be run from the host, neither by a
// user nor by an AI agent. Use "make evetest" instead.
func runCommand() *cobra.Command {
	var parallel int
	var failFast bool
	var ui string
	cmd := &cobra.Command{
		Use:   "run [test...]",
		Short: "Run several tests or suites as parallel evetest instances",
		Long: `Run several tests or suites as parallel evetest instances.

Normally started by "make evetest NAME=test1,test2" or "make evetest" (all test
suites); see the evetest README. Each test runs in its own container with its own
API port; use "evetest instances" and "evetest -i <name> ..." to interact with
them while they run.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return runTests(cmd, args, parallel, failFast, ui)
		},
	}
	cmd.Flags().IntVarP(&parallel, "parallel", "p", viper.GetInt(constants.ParallelEnv),
		"maximum number of instances running at the same time ("+constants.EnvPrefix+constants.ParallelEnv+")")
	cmd.Flags().BoolVar(&failFast, "fail-fast", viper.GetBool(constants.FailFastEnv),
		"cancel all other tests once one fails ("+constants.EnvPrefix+constants.FailFastEnv+")")
	cmd.Flags().StringVar(&ui, "ui", viper.GetString(constants.UIEnv),
		"output mode: tmux, dashboard, prefixed or plain ("+constants.EnvPrefix+constants.UIEnv+")")
	return cmd
}

func runTests(cmd *cobra.Command, names []string, parallel int, failFast bool, ui string) error {
	if len(names) == 0 {
		names = orchestrator.ParseNames(viper.GetString(constants.RunNamesEnv))
	}
	if len(names) == 0 {
		var err error
		if names, err = allSuites(); err != nil {
			return err
		}
	}
	image := viper.GetString(constants.RunImageEnv)
	if image == "" {
		return fmt.Errorf("%s%s is not set; run this through \"make evetest\"",
			constants.EnvPrefix, constants.RunImageEnv)
	}
	argsFile := viper.GetString(constants.RunArgsFileEnv)
	commonArgs, err := readArgsFile(argsFile)
	if err != nil {
		return err
	}
	// The options are only needed to start the tests; do not leave a copy of
	// the environment behind.
	if argsFile != "" {
		defer func() { _ = os.Remove(argsFile) }()
	}
	runID := viper.GetString(constants.RunIDEnv)
	if runID == "" {
		runID = time.Now().Format("20060102-150405")
	}
	logDir := filepath.Join(instances.Home(), "runs", runID)
	orchestrator.PruneRuns(filepath.Dir(logDir), runID, orchestrator.RunActive)

	docker := orchestrator.DockerExecutor{
		Image:            image,
		RunID:            runID,
		CommonArgs:       commonArgs,
		ArtifactsHostDir: viper.GetString(constants.ExternalArtifactDirEnv),
		ColorOutput:      viper.GetString(constants.ColorOutputEnv),
	}

	eve := eveUnderTest()
	isTTY := term.IsTerminal(int(os.Stdout.Fd()))
	if ui == "" {
		// On a terminal show the dashboard. Without one (scripts, nohup, pipes)
		// report status changes only; the full output of each test is in its
		// log file.
		ui = "plain"
		if isTTY {
			ui = "dashboard"
		}
	}
	var output orchestrator.Output
	var executor orchestrator.Executor = &docker
	var tmuxUI *orchestrator.TmuxUI
	var dashboard *orchestrator.Dashboard
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	switch ui {
	case "plain":
		printEVE(eve)
		output = orchestrator.NewPlainOutput(os.Stdout)
	case "prefixed":
		printEVE(eve)
		output = orchestrator.NewPrefixedOutput(os.Stdout, isTTY)
	case "tmux":
		if !isTTY {
			return fmt.Errorf("%s%s=tmux needs a terminal", constants.EnvPrefix, constants.UIEnv)
		}
		width, height, _ := term.GetSize(int(os.Stdout.Fd()))
		var err error
		tmuxUI, err = orchestrator.NewTmuxUI(orchestrator.TmuxConfig{
			RunID:   runID,
			Prefix:  viper.GetString(constants.TmuxPrefixEnv),
			Docker:  docker,
			StopPID: os.Getpid(),
			Width:   width,
			Height:  height,
			EVE:     eve,
		})
		if err != nil {
			return err
		}
		defer tmuxUI.Close()
		output, executor = tmuxUI, tmuxUI.Executor()
	case "dashboard":
		if !isTTY {
			return fmt.Errorf("%s%s=dashboard needs a terminal", constants.EnvPrefix, constants.UIEnv)
		}
		self, err := os.Executable()
		if err != nil {
			return err
		}
		docker.ColorOutput = "true"
		executor = &docker
		dashboard = orchestrator.NewDashboard(orchestrator.DashboardConfig{
			RunID:   runID,
			EVE:     eve,
			Ctx:     ctx,
			Cancel:  cancel,
			CLIPath: self,
		}, names)
		output = dashboard
	default:
		return fmt.Errorf("unknown %s%s %q (want tmux, dashboard, prefixed or plain)",
			constants.EnvPrefix, constants.UIEnv, ui)
	}

	r, err := orchestrator.New(orchestrator.Config{
		Names:           names,
		Parallel:        parallel,
		FailFast:        failFast,
		PortBase:        viper.GetInt(constants.APIPortEnv),
		LogDir:          logDir,
		Output:          output,
		Versions:        orchestrator.Versions{Evetest: imageTag(image), SDN: viper.GetString(constants.SDNVersionEnv)},
		ContainerExists: orchestrator.ContainerExists,
	}, executor)
	if err != nil {
		return err
	}

	// The first signal stops the instances gracefully (they clean up their
	// VMs, which takes a while); the second kills them.
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Fprintln(os.Stderr, "Stopping all tests gracefully; signal again to kill them")
		cancel()
		<-sigs
		r.KillAll()
		os.Exit(130)
	}()

	if tmuxUI != nil {
		// Closing the tmux session means "stop everything".
		go func() {
			<-tmuxUI.Closed()
			cancel()
		}()
	}

	var jobs []*orchestrator.Job
	if dashboard != nil {
		dashboard.SetKillAll(r.KillAll)
		dashboard.SetCancelQueued(r.CancelQueued)
		dashboard.SetRerun(rerunWithChecks(r, docker.Image))
		runDone := make(chan struct{})
		go func() {
			defer close(runDone)
			jobs = r.Run(ctx)
		}()
		// Returns when the user quits; the run is over or being cancelled.
		err := dashboard.Run()
		cancel()
		<-runDone
		// Also the reruns, which are not part of Run.
		r.Wait()
		if err != nil {
			return err
		}
		orchestrator.WriteSummary(os.Stdout, jobs)
	} else {
		jobs = r.Run(ctx)
	}
	if tmuxUI != nil {
		// Keep the session open for inspecting the panes until the user
		// closes it, then leave the results in the terminal's scrollback.
		tmuxUI.Wait()
		orchestrator.WriteSummary(os.Stdout, jobs)
	}
	fixOwnership(logDir)
	if !orchestrator.Succeeded(jobs) {
		os.Exit(1)
	}
	return nil
}

// imageTag returns the tag of an image reference.
func imageTag(ref string) string {
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		return ref[i+1:]
	}
	return ""
}

// rerunWithChecks reruns a test after making sure that the images of the
// versions asked for exist: missing ones are pulled, like "make evetest" does,
// but not built, because a build takes long and has its own output.
func rerunWithChecks(r *orchestrator.Orchestrator, evetestImage string) func(string, orchestrator.Versions) error {
	evetestRepo := orchestrator.ImageRepo(evetestImage)
	sdnRepo := viper.GetString(constants.SDNRepoEnv)
	// Like "make evetest", a remote broker brings its own SDN image.
	remoteBroker := viper.GetString(constants.BrokerAddressEnv) != ""
	ensure := func(ref, buildTarget string) error {
		if orchestrator.ImageExists(ref) {
			return nil
		}
		if err := orchestrator.PullImage(ref); err != nil {
			return fmt.Errorf("image %s is not local and cannot be pulled (%v); build it with \"make -C evetest %s\"",
				ref, err, buildTarget)
		}
		return nil
	}
	return func(name string, v orchestrator.Versions) error {
		if v.Evetest != "" {
			if err := ensure(evetestRepo+":"+v.Evetest, "build-container"); err != nil {
				return err
			}
		}
		if v.SDN != "" && !remoteBroker {
			if err := ensure(sdnRepo+":"+v.SDN, "build-sdn-container"); err != nil {
				return err
			}
		}
		return r.Rerun(name, v)
	}
}

// eveUnderTest describes which EVE the tests run against, as the Makefile passes
// it on: a version, possibly from a repository other than the default one, or,
// when the live image of the newest local build is tested, that.
func eveUnderTest() string {
	if version := viper.GetString(constants.EVEVersionEnv); version != "" {
		text := "EVE " + version
		if repo := viper.GetString(constants.EVERepoEnv); repo != "" && repo != constants.DefaultEVERepo {
			text += " (" + repo + ")"
		}
		return text
	}
	switch viper.GetString(constants.EVELiveImageEnv) {
	case "", "false", "False", "FALSE", "0", "f", "F":
		return ""
	}
	return "EVE of the newest local build"
}

func printEVE(eve string) {
	if eve != "" {
		fmt.Println("Testing", eve)
	}
}

// allSuites lists the test suites the evetest image contains.
func allSuites() ([]string, error) {
	out, err := exec.Command("list-tests", "-suites-only").Output()
	if err != nil {
		return nil, fmt.Errorf("cannot list test suites: %w", err)
	}
	skipped := orchestrator.ParseNames(viper.GetString(constants.SkipEnv))
	var names []string
outer:
	for _, name := range orchestrator.ParseNames(strings.ReplaceAll(string(out), "\n", ",")) {
		for _, s := range skipped {
			if s == name {
				continue outer
			}
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no test suites found")
	}
	return names, nil
}

func readArgsFile(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var args []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			args = append(args, line)
		}
	}
	return args, sc.Err()
}

// fixOwnership hands the run's files, created here as root, to the host user.
func fixOwnership(dir string) {
	uid, uidErr := parseID(os.Getenv("EVETEST_HOST_UID"))
	gid, gidErr := parseID(os.Getenv("EVETEST_HOST_GID"))
	if uidErr != nil || gidErr != nil {
		return
	}
	_ = filepath.WalkDir(dir, func(path string, _ os.DirEntry, err error) error {
		if err == nil {
			_ = os.Lchown(path, uid, gid)
		}
		return nil
	})
}

func parseID(s string) (int, error) {
	var id int
	_, err := fmt.Sscanf(s, "%d", &id)
	return id, err
}
