// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

func main() {
	var sshKey string
	var timeout time.Duration
	var userspaceContainerDebugFlag *[]string
	var userspaceContainerListFlag *[]string
	var userspaceContainerHTTPFlag *[]string

	execName, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	execName = filepath.Base(execName)

	rootCmd := &cobra.Command{
		Use:   "bpftrace-compiler",
		Short: "Compiles bpftrace scripts for EVE",
		Long:  "Compile bpftrace scripts for specific EVE kernels",
	}

	compileCmd := &cobra.Command{
		Use:        "compile <arm64|amd64> <eve kernel docker image> <bpftrace script> <output file>",
		Aliases:    []string{"c"},
		SuggestFor: []string{},
		Short:      "compile only",
		Example:    fmt.Sprintf("%s compile amd64 docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.38-generic-fb31ce85306c-gcc examples/opensnoop.bt opensnoop.aot", execName),
		Args:       cobra.ExactArgs(4),
		Run: func(cmd *cobra.Command, args []string) {
			lkConf := lkConf{
				kernel: args[1],
			}
			err := compile(args[0], lkConf, nil, args[2], args[3])
			if err != nil {
				log.Fatal(err)
			}
		},
	}

	runSSHCmd := &cobra.Command{
		Use:        "run-via-ssh <host:port> <bpftrace script>",
		Aliases:    []string{"rs", "run-ssh"},
		SuggestFor: []string{},
		Short:      "run bpftrace script on host via ssh",
		Example:    fmt.Sprintf("%s run-via-ssh 127.1:2222 examples/opensnoop.bt", execName),
		Args:       cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			sr, err := newSSHRun(args[0], sshKey)
			if err != nil {
				log.Fatal(err)
			}
			sr.run(args[1], nil, timeout)
			sr.end()
		},
	}

	runHTTPCmd := &cobra.Command{
		Use:        "run-via-http <host:port> <bpftrace script>",
		Aliases:    []string{"rh", "run-http"},
		SuggestFor: []string{},
		Short:      "run bpftrace script on host via http debug",
		Example:    fmt.Sprintf("%s run-via-http 127.1:6543 examples/opensnoop.bt", execName),
		Args:       cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			var uc userspaceContainer
			if len(*userspaceContainerHTTPFlag) == 2 {
				switch (*userspaceContainerHTTPFlag)[0] {
				case "onboot":
					uc = onbootContainer((*userspaceContainerHTTPFlag)[1])
				case "service":
					uc = serviceContainer((*userspaceContainerHTTPFlag)[1])
				}
			}
			hr := newHTTPRun(args[0])
			hr.run(args[1], uc, timeout)
			hr.end()
		},
	}

	debugShellCmd := &cobra.Command{
		Use:  "debug <arm64|amd64> <eve kernel docker image> <folder>",
		Args: cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			shareFolder := args[2]

			arch, lkConf, uc := interpretDebugCmdArgs(args, userspaceContainerDebugFlag)

			imageDir, err := os.MkdirTemp("/var/tmp", "bpftrace-image")
			if err != nil {
				log.Fatal(err)
			}
			defer os.RemoveAll(imageDir)
			createImage(arch, lkConf, uc, imageDir)

			var qr *qemuRunner
			if arch == "arm64" {
				qr = newQemuArm64Runner(imageDir, "", "")
			} else if arch == "amd64" {
				qr = newQemuAmd64Runner(imageDir, "", "")
			}
			qr.timeout = 0

			err = qr.runDebug(shareFolder)
			if err != nil {
				fmt.Println(err)
			}
		},
	}
	listCmd := &cobra.Command{
		Use:     "list-probes <arm64|amd64> <eve kernel docker image> <binary path|>",
		Aliases: []string{"l", "list"},
		Args:    cobra.RangeArgs(2, 3),
		Run: func(cmd *cobra.Command, args []string) {
			arch, lkConf, uc := interpretDebugCmdArgs(args, userspaceContainerListFlag)

			imageDir, err := os.MkdirTemp("/var/tmp", "bpftrace-image")
			if err != nil {
				log.Fatal(err)
			}
			defer os.RemoveAll(imageDir)
			createImage(arch, lkConf, uc, imageDir)

			var qr *qemuRunner
			if arch == "arm64" {
				qr = newQemuArm64Runner(imageDir, "", "")
			} else if arch == "amd64" {
				qr = newQemuAmd64Runner(imageDir, "", "")
			}

			listArg := ""
			if len(args) == 3 {
				listArg = args[2]
			}
			output, err := qr.runList(listArg)
			if err != nil {
				fmt.Println(err)
			}

			fmt.Printf("%s", string(output))
		},
	}

	runSSHCmd.PersistentFlags().StringVarP(&sshKey, "identity-file", "i", "", "")
	runSSHCmd.PersistentFlags().DurationVarP(&timeout, "timeout", "t", 10*time.Second, "")

	runHTTPCmd.PersistentFlags().DurationVarP(&timeout, "timeout", "t", 10*time.Second, "")
	userspaceContainerHTTPFlag = runHTTPCmd.PersistentFlags().StringSliceP("userspace", "u", []string{}, "onboot|service,name")

	userspaceContainerDebugFlag = debugShellCmd.PersistentFlags().StringSliceP("userspace", "u", []string{}, "onboot|service,name,image")

	userspaceContainerListFlag = listCmd.PersistentFlags().StringSliceP("userspace", "u", []string{}, "onboot|service,name,image")

	rootCmd.AddCommand(compileCmd, runSSHCmd, runHTTPCmd, listCmd, debugShellCmd)

	err = rootCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}

}

func interpretDebugCmdArgs(args []string, ucFlag *[]string) (string, lkConf, userspaceContainer) {
	var uc userspaceContainer

	if len(*ucFlag) != 0 && len(*ucFlag) != 3 {
		panic("wrong userspace flag usage")
	}

	arch := cleanArch(args[0])
	eveKernelImage := args[1]

	lkConf := lkConf{
		kernel: eveKernelImage,
	}

	if len(*ucFlag) == 3 {
		switch (*ucFlag)[0] {
		case "onboot":
			uc = onbootContainer((*ucFlag)[1])
			lkConf.onboot = map[string]string{
				(*ucFlag)[1]: (*ucFlag)[2],
			}
		case "service":
			uc = serviceContainer((*ucFlag)[1])
			lkConf.services = map[string]string{
				(*ucFlag)[1]: (*ucFlag)[2],
			}
		}
	}
	return arch, lkConf, uc
}
