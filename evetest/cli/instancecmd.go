// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/lf-edge/eve/evetest/instances"
	"github.com/spf13/cobra"
)

// stopTimeout bounds how long "docker stop" waits for the graceful shutdown
// (VM and broker cleanup) of an instance before killing its container.
const stopTimeout = "90"

func instancesCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "instances",
		Aliases: []string{"ps"},
		Short:   "List running evetest instances",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			live := liveInstances()
			if len(live) == 0 {
				fmt.Println("No running evetest instances.")
				return nil
			}
			var current *instances.Instance
			if inst, ok := instances.Remembered(); ok {
				current = &inst
			}
			states := instanceStates(live)
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "\t#\tNAME\tPORT\tUPTIME\tSTATE")
			for i, inst := range live {
				mark := ""
				if current != nil && current.Port == inst.Port &&
					current.StartedAt.Equal(inst.StartedAt) {
					mark = "*"
				}
				_, _ = fmt.Fprintf(w, "%s\t%d\t%s\t%d\t%s\t%s\n", mark, i+1, inst.Name, inst.Port,
					time.Since(inst.StartedAt).Round(time.Second), states[i])
			}
			return w.Flush()
		},
	}
}

// instanceStates queries the status of the instances in parallel.
func instanceStates(list []instances.Instance) []string {
	states := make([]string, len(list))
	var wg sync.WaitGroup
	for i, inst := range list {
		wg.Add(1)
		go func() {
			defer wg.Done()
			states[i] = instances.State(inst)
		}()
	}
	wg.Wait()
	return states
}

func useCommand() *cobra.Command {
	var forget, printEnv bool
	cmd := &cobra.Command{
		Use:   "use [instance]",
		Short: "Choose the evetest instance used by the commands run in this terminal",
		Long: `Choose the evetest instance used by the commands run in this terminal.

The instance is given by name (or a unique part of it), API port or its number
in the "evetest instances" list. Without an argument, the instance is chosen
interactively. The choice is remembered for the current terminal session only
and is overridden by --instance and by EVETEST_INSTANCE.

With --env, nothing is remembered; instead a shell command is printed which sets
EVETEST_INSTANCE, for use as: eval "$(evetest use --env <instance>)"`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if forget {
				instances.Forget()
				return nil
			}
			live := liveInstances()
			if len(live) == 0 {
				return fmt.Errorf("no running evetest instances")
			}
			var inst instances.Instance
			var err error
			switch {
			case len(args) == 1:
				inst, err = instances.Match(live, args[0])
			case len(live) == 1:
				inst = live[0]
			default:
				// pickInstance remembers the choice itself.
				inst, err = pickInstance(live)
				if err == nil && !printEnv {
					return nil
				}
			}
			if err != nil {
				return err
			}
			if printEnv {
				fmt.Printf("export %s=%d\n", instanceEnv, inst.Port)
				return nil
			}
			remembered, err := instances.Remember(inst)
			if err != nil {
				return err
			}
			if !remembered {
				return fmt.Errorf("no terminal to remember the choice for; " +
					"use --instance, or: eval \"$(evetest use --env <instance>)\"")
			}
			fmt.Printf("Using %s (port %d) in this terminal.\n", inst.Name, inst.Port)
			return nil
		},
	}
	cmd.Flags().BoolVar(&forget, "clear", false, "forget the instance remembered by this terminal")
	cmd.Flags().BoolVar(&printEnv, "env", false,
		"print a shell command setting EVETEST_INSTANCE instead of remembering the choice")
	return cmd
}

func containerOf(t target) (string, error) {
	if t.Instance == nil || t.Instance.Container == "" {
		return "", fmt.Errorf("cannot determine the container of the evetest instance at %s",
			t.hostPort())
	}
	return t.Instance.Container, nil
}

func runDocker(args ...string) error {
	c := exec.Command("docker", args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}

func logsCommand(instanceFlag *string) *cobra.Command {
	var follow bool
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show the output of an evetest instance (as printed by its container)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := resolveTarget(*instanceFlag)
			if err != nil {
				return err
			}
			container, err := containerOf(t)
			if err != nil {
				return err
			}
			dockerArgs := []string{"logs"}
			if follow {
				dockerArgs = append(dockerArgs, "-f")
			}
			return runDocker(append(dockerArgs, container)...)
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "follow the output")
	return cmd
}

func stopCommand(instanceFlag *string) *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop an evetest instance (or all of them), cleaning up its VMs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var containers []string
			if all {
				for _, inst := range liveInstances() {
					if inst.Container != "" {
						containers = append(containers, inst.Container)
					}
				}
				if len(containers) == 0 {
					fmt.Println("No running evetest instances.")
					return nil
				}
			} else {
				t, err := resolveTarget(*instanceFlag)
				if err != nil {
					return err
				}
				container, err := containerOf(t)
				if err != nil {
					return err
				}
				containers = []string{container}
			}
			fmt.Printf("Stopping %s ...\n", strings.Join(containers, ", "))
			return runDocker(append([]string{"stop", "-t", stopTimeout}, containers...)...)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "stop all running instances")
	return cmd
}
