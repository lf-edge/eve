// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// lh-snap-revert reverts the Longhorn volume behind an EVE-K app PVC to one of
// its snapshots, in place. The PVC, its UID and the PV are kept. It is an
// out-of-band recovery tool for occasional use. It changes only the Longhorn
// volume and never touches the app's VMIRS or VMI: the controller stops the
// app first. Scheduling, retention and backup of snapshots stay with Longhorn
// and EVE. See README.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	defaultKubeconfig = "/run/.kube/k3s/k3s.yaml"
	defaultNamespace  = "eve-kube-app"
)

// Exit codes.
const (
	exitOK          = 0
	exitNoChange    = 1 // usage error, refusal or failure before attaching
	exitAfterAttach = 2 // failure after attaching; see the "reverted" line
)

const usageText = `Usage:
  lh-snap-revert pvcs   [flags]
  lh-snap-revert list   --pvc NAME [flags]
  lh-snap-revert revert --pvc NAME --snapshot NAME [flags]
  lh-snap-revert cleanup --pvc NAME [flags]

Commands:
  pvcs    List PVCs with their Longhorn volume, state and users
  list    Show the snapshot tree of a PVC's volume
  revert  Revert a PVC's volume to a snapshot in place
  cleanup Delete the snapshots off the current branch, such as the old
          branch a revert leaves. Run it while the app runs

Flags:
`

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		// After the first signal, restore the default handling so a
		// second Ctrl-C stops the tool, also during cleanup.
		<-sig
		fmt.Fprintln(os.Stderr, "\nInterrupted. Stopping after the current step. Interrupt again to quit at once, without cleanup.")
		signal.Stop(sig)
		cancel()
	}()
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, func(kc string) (api, error) {
		return newKubeAPI(kc)
	})
	cancel()
	os.Exit(code)
}

func run(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer,
	connect func(kubeconfig string) (api, error)) int {
	fs := flag.NewFlagSet("lh-snap-revert", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() {
		fmt.Fprint(errOut, usageText)
		fs.PrintDefaults()
	}
	o := &revertOpts{in: in, out: out, now: time.Now, poll: 2 * time.Second}
	kubeconfig := fs.String("kubeconfig", defaultKubeconfig, "kubeconfig file")
	fs.StringVar(&o.namespace, "namespace", defaultNamespace, "namespace of the PVC")
	fs.StringVar(&o.namespace, "n", defaultNamespace, "shorthand for --namespace")
	fs.StringVar(&o.pvc, "pvc", "", "PVC name (list, revert, cleanup)")
	fs.StringVar(&o.snapshot, "snapshot", "", "snapshot to revert to (revert)")
	fs.StringVar(&o.node, "node", "", "Longhorn node to attach on (revert; default: a Ready node holding a replica)")
	fs.BoolVar(&o.noSafety, "no-safety-snapshot", false, "skip the safety-net snapshot (revert)")
	fs.BoolVar(&o.ignoreVersion, "ignore-longhorn-version", false,
		"run on a Longhorn version other than "+supportedLonghorn+", with a warning (revert)")
	fs.DurationVar(&o.timeout, "timeout", 5*time.Minute, "timeout for pvcs, list and cleanup, and for each wait and the revert call in revert")
	fs.BoolVar(&o.yes, "yes", false, "do not ask for confirmation (revert, cleanup)")
	fs.BoolVar(&o.dryRun, "dry-run", false, "run the checks, print what would change and exit (revert, cleanup)")
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fs.Usage()
		return exitNoChange
	}
	cmd := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return exitNoChange
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(errOut, "unexpected argument %q\n", fs.Arg(0))
		return exitNoChange
	}
	switch cmd {
	case "pvcs":
	case "list", "cleanup":
		if o.pvc == "" {
			fmt.Fprintf(errOut, "%s needs --pvc\n", cmd)
			return exitNoChange
		}
	case "revert":
		if o.pvc == "" || o.snapshot == "" {
			fmt.Fprintln(errOut, "revert needs --pvc and --snapshot")
			return exitNoChange
		}
	default:
		fmt.Fprintf(errOut, "unknown command %q\n", cmd)
		fs.Usage()
		return exitNoChange
	}

	if o.timeout <= 0 {
		fmt.Fprintln(errOut, "--timeout must be positive")
		return exitNoChange
	}
	a, err := connect(*kubeconfig)
	if err != nil {
		fmt.Fprintf(errOut, "error: %v\n", err)
		return exitNoChange
	}
	lctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	switch cmd {
	case "pvcs":
		err = listPVCs(lctx, a, o.namespace, out)
	case "list":
		err = listSnapshots(lctx, a, o.namespace, o.pvc, out)
	case "revert":
		err = runRevert(ctx, a, o)
	case "cleanup":
		err = runCleanup(ctx, a, o)
	}
	if err == nil {
		return exitOK
	}
	fmt.Fprintf(errOut, "error: %v\n", err)
	var ae *afterAttachError
	if errors.As(err, &ae) {
		fmt.Fprintf(errOut, "reverted: %s\n", ae.reverted)
		return exitAfterAttach
	}
	return exitNoChange
}
