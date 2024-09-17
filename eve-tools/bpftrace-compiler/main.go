// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

var defers []func()

func init() {
	defers = make([]func(), 0)
}

func shutdown() {
	for i := len(defers) - 1; i >= 0; i-- {
		defers[i]()
	}
}

var bpftraceCompilerDir string
var execName string

func init() {
	var err error

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		sig := <-c
		signal.Stop(c)
		log.Printf("Got signal %v, shutting down ...\n", sig)
		shutdown()
		os.Exit(0)
	}()

	execName, err = os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	execName = filepath.Base(execName)

	homedir, err := os.UserHomeDir()
	if err == nil {
		bpftraceCompilerDir = filepath.Join(homedir, ".bpftrace-compiler")
	}
}

func main() {
	var err error
	var sshKey string
	var timeout time.Duration
	var userspaceContainerDebugFlag *[]string
	var userspaceContainerListFlag *[]string
	var userspaceContainerHTTPFlag *[]string
	var userspaceContainerEVFlag *[]string
	var userspaceContainerSSHFlag *[]string
	var kernelModulesDebugFlag *[]string

	defer shutdown()

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
			err := compile(args[0], lkConf, nil, []string{}, args[2], args[3])
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
			var uc userspaceContainer
			if len(*userspaceContainerSSHFlag) == 2 {
				switch (*userspaceContainerSSHFlag)[0] {
				case "onboot":
					uc = onbootContainer((*userspaceContainerSSHFlag)[1])
				case "service":
					uc = serviceContainer((*userspaceContainerSSHFlag)[1])
				}
			}
			sr, err := newSSHRun(args[0], sshKey)
			if err != nil {
				log.Fatal(err)
			}
			sr.run(args[1], uc, []string{}, timeout)
			defers = append(defers, func() { sr.end() })
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
				default:
					log.Fatalf("unknown userspace container type %s", (*userspaceContainerHTTPFlag)[0])
				}
			}
			hr := newHTTPRun(args[0])
			hr.run(args[1], uc, []string{}, timeout)
			defers = append(defers, func() { hr.end() })
		},
	}

	runEdgeviewCmd := &cobra.Command{
		Use:        "run-via-edgeview <path to edgeview script> <bpftrace script>",
		Aliases:    []string{"re", "run-edgeview", "run-ev"},
		SuggestFor: []string{},
		Short:      "run bpftrace script on host via edgeview",
		Example:    fmt.Sprintf("%s re ~/Downloads/run.\\*.sh examples/undump.bt", execName),
		Args:       cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			var uc userspaceContainer
			if len(*userspaceContainerEVFlag) == 2 {
				switch (*userspaceContainerEVFlag)[0] {
				case "onboot":
					uc = onbootContainer((*userspaceContainerEVFlag)[1])
				case "service":
					uc = serviceContainer((*userspaceContainerEVFlag)[1])
				}
			}
			ev := edgeviewRun{}
			port, err := ev.start(args[0])
			if err != nil {
				log.Fatalf("could not start edgeview for bpftrace: %v", err)
			}

			for i := 0; i < 10; i++ {
				u := url.URL{
					Scheme: "http",
					Host:   fmt.Sprintf("127.0.0.1:%d", port),
					Path:   "/",
				}
				resp, err := http.Get(u.String())
				if err != nil || resp.StatusCode != http.StatusOK {
					time.Sleep(time.Second)
					continue
				}
			}

			hr := newHTTPRun(fmt.Sprintf("localhost:%d", port))
			defers = append(defers, func() { hr.end(); ev.shutdown() })
			hr.run(args[1], uc, []string{}, timeout)
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

			if kernelModulesDebugFlag != nil && len(*kernelModulesDebugFlag) > 0 {
				qr.withLoadKernelModule(*kernelModulesDebugFlag)
			}

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

	cacheCmd := &cobra.Command{
		Use:     "cache - manage bpftrace-compiler cache",
		Aliases: []string{"c"},
	}

	cacheEnableCmd := &cobra.Command{
		Use:     "enable - enable cache",
		Aliases: []string{"e"},
		Short:   fmt.Sprintf("creates a cache directory under %s/.bpftrace-compiler", bpftraceCompilerDir),
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cacheDir := filepath.Join(bpftraceCompilerDir, "cache")
			err := os.MkdirAll(cacheDir, 0700)
			if err != nil {
				log.Fatalf("could not create cache dir %s: %v", cacheDir, err)
			}
		},
	}
	cacheDisableCmd := &cobra.Command{
		Use:     "disable - disable and purge cache",
		Aliases: []string{"e"},
		Short:   fmt.Sprintf("deletes the cache directory under %s/.bpftrace-compiler", bpftraceCompilerDir),
		Long:    "if bpftrace-compiler cannot find a cache directory, no cache will be used",
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cacheDir := filepath.Join(bpftraceCompilerDir, "cache")
			err := os.RemoveAll(cacheDir)
			if err != nil {
				log.Fatalf("could not remove cache dir %s: %v", cacheDir, err)
			}
		},
	}
	cacheCmd.AddCommand(cacheEnableCmd, cacheDisableCmd)

	runSSHCmd.PersistentFlags().StringVarP(&sshKey, "identity-file", "i", "", "")
	runSSHCmd.PersistentFlags().DurationVarP(&timeout, "timeout", "t", 10*time.Second, "")

	runHTTPCmd.PersistentFlags().DurationVarP(&timeout, "timeout", "t", 10*time.Second, "")
	userspaceContainerHTTPFlag = runHTTPCmd.PersistentFlags().StringSliceP("userspace", "u", []string{}, "onboot|service,name")
	userspaceContainerEVFlag = runEdgeviewCmd.PersistentFlags().StringSliceP("userspace", "u", []string{}, "onboot|service,name")
	userspaceContainerSSHFlag = runSSHCmd.PersistentFlags().StringSliceP("userspace", "u", []string{}, "onboot|service,name")

	kernelModulesDebugFlag = debugShellCmd.PersistentFlags().StringSliceP("kernel-modules", "k", []string{}, "dm_crypt")

	userspaceContainerDebugFlag = debugShellCmd.PersistentFlags().StringSliceP("userspace", "u", []string{}, "onboot|service,name,image")

	userspaceContainerListFlag = listCmd.PersistentFlags().StringSliceP("userspace", "u", []string{}, "onboot|service,name,image")

	rootCmd.AddCommand(compileCmd, runSSHCmd, runHTTPCmd, runEdgeviewCmd, listCmd, debugShellCmd)
	if bpftraceCompilerDir != "" {
		rootCmd.AddCommand(cacheCmd)
	}

	err = rootCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}

func interpretDebugCmdArgs(args []string, ucFlag *[]string) (string, lkConf, userspaceContainer) {
	var uc userspaceContainer

	if len(*ucFlag) != 0 && len(*ucFlag) != 3 {
		log.Fatal("wrong userspace flag usage")
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
		default:
			log.Fatalf("unknown userspace container type %s", (*ucFlag)[0])
		}
	}
	return arch, lkConf, uc
}
