package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

//Test for testing purpose
var Test bool

//Run function for wrap exec
var Run func(command *cobra.Command, timeout time.Duration, args []string, env string) (stdout, stderr bytes.Buffer, rerr, cerr error)

// Run shell command with arguments and enviroment variables
func run(command *cobra.Command, timeout time.Duration, args []string, env string) (stdout bytes.Buffer, stderr bytes.Buffer, rerr error, cerr error) {
	var err error
	var re error
	var ce error
	var sout bytes.Buffer
	var serr bytes.Buffer

	if len(args) > 0 {
		Envs := strings.Split(env, " ")
		cmd := args[0]
		args = args[1:]
		if timeout != 0 {
			var cancel context.CancelFunc
			cnt, cancel := context.WithTimeout(context.Background(),
				timeout)
			defer cancel()

			cmd := exec.CommandContext(cnt, cmd, args...)
			cmd.Stdout = &sout
			cmd.Stderr = &serr
			cmd.Env = append(os.Environ(), Envs...)

			re = cmd.Run()
			ce = cnt.Err()
			if ce != nil {
				fmt.Fprintln(command.OutOrStderr(),
					"Context error: ", ce.Error())
			}
		} else {
			cmd := exec.Command(cmd, args...)
			cmd.Stdout = &sout
			cmd.Stderr = &serr
			cmd.Env = append(os.Environ(), Envs...)

			re = cmd.Run()
		}
	}

	if re != nil {
		if exitError, ok := re.(*exec.ExitError); ok {
			waitStatus := exitError.Sys().(syscall.WaitStatus)
			_, err = fmt.Fprint(command.OutOrStderr(), serr.String())
			if err != nil {
				fmt.Fprint(command.OutOrStdout(), serr.String())
			}
			if !Test {
				os.Exit(waitStatus.ExitStatus())
			} else {
				return sout, serr, re, ce
			}
		} else {
			_, err = fmt.Fprintf(command.OutOrStderr(),
				"Execute error: %s\n", err.Error())
			if err != nil {
				fmt.Fprintf(command.OutOrStdout(),
					"Execute error: %s\n", err.Error())
			}
		}
	}
	fmt.Fprint(command.OutOrStdout(), sout.String())

	return sout, serr, re, ce
}
