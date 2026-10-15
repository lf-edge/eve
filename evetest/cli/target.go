// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/evetest/constants"
	"github.com/lf-edge/eve/evetest/instances"
	"github.com/spf13/viper"
)

const (
	// instanceEnv selects the instance to talk to by name, port or index.
	instanceEnv = constants.EnvPrefix + "INSTANCE"

	livenessTimeout = 2 * time.Second
)

// target is the evetest instance a CLI command talks to.
type target struct {
	Address string
	Port    int
	// Instance is the registry record of the target; nil if the target was
	// given explicitly and is not registered (e.g. a remote instance).
	Instance *instances.Instance
}

func (t target) hostPort() string {
	return net.JoinHostPort(t.Address, strconv.Itoa(t.Port))
}

// isLive tells whether the instance still listens on its port. Only a refused
// connection proves that it is gone: a slow answer (a busy host running several
// instances) must not make a running instance disappear from the registry.
func isLive(inst instances.Instance) bool {
	d := net.Dialer{Timeout: livenessTimeout}
	conn, err := d.DialContext(context.Background(), "tcp",
		net.JoinHostPort("localhost", strconv.Itoa(inst.Port)))
	if err != nil {
		return !errors.Is(err, syscall.ECONNREFUSED)
	}
	_ = conn.Close()
	return true
}

func inContainer() bool {
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

// liveInstances returns the registered instances which still answer on their
// port. Records of dead instances are removed, except inside a container:
// there, only the container's own port is reachable on localhost, so a failed
// dial proves nothing about the other instances.
func liveInstances() []instances.Instance {
	list, _ := instances.List()
	var live []instances.Instance
	for _, inst := range list {
		if isLive(inst) {
			live = append(live, inst)
		} else if !inContainer() {
			instances.Remove(inst.Port)
		}
	}
	return live
}

// resolveTarget finds the instance a command should talk to. In order:
//  1. the --instance flag,
//  2. EVETEST_INSTANCE,
//  3. an explicit EVETEST_API_PORT / EVETEST_API_ADDRESS (a remote or manually
//     configured instance),
//  4. the instance remembered by this terminal (see "evetest use"),
//  5. the only running instance,
//  6. an interactive choice among several running instances.
func resolveTarget(flagSelector string) (target, error) {
	selector := flagSelector
	if selector == "" {
		selector = os.Getenv(instanceEnv)
	}
	if selector != "" {
		inst, err := instances.Match(liveInstances(), selector)
		if err != nil {
			return target{}, err
		}
		return instanceTarget(inst), nil
	}

	_, portSet := os.LookupEnv(constants.EnvPrefix + constants.APIPortEnv)
	_, addrSet := os.LookupEnv(constants.EnvPrefix + constants.APIAddressEnv)
	if portSet || addrSet {
		return explicitTarget(), nil
	}

	live := liveInstances()
	if inst, ok := instances.Remembered(); ok {
		for _, l := range live {
			if l.Port == inst.Port && l.StartedAt.Equal(inst.StartedAt) {
				return instanceTarget(l), nil
			}
		}
		instances.Forget()
	}
	switch len(live) {
	case 0:
		// Possibly an instance not known to the registry (started by an older
		// image or by hand): fall back to the default address.
		return explicitTarget(), nil
	case 1:
		return instanceTarget(live[0]), nil
	}
	inst, err := pickInstance(live)
	if err != nil {
		return target{}, err
	}
	return instanceTarget(inst), nil
}

func instanceTarget(inst instances.Instance) target {
	return target{Address: "localhost", Port: inst.Port, Instance: &inst}
}

func explicitTarget() target {
	t := target{
		Address: viper.GetString(constants.APIAddressEnv),
		Port:    viper.GetInt(constants.APIPortEnv),
	}
	if t.Address == "" {
		// Assume that the evetest container runs on the same host.
		t.Address = "localhost"
	}
	if t.Address == "localhost" {
		for _, inst := range liveInstances() {
			if inst.Port == t.Port {
				t.Instance = &inst
				break
			}
		}
	}
	return t
}

// pickInstance asks the user to choose one of several instances and remembers
// the choice for this terminal. The dialogue uses /dev/tty, so it works even
// when stdin or stdout are redirected.
func pickInstance(live []instances.Instance) (instances.Instance, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return instances.Instance{}, fmt.Errorf(
			"multiple evetest instances are running and no terminal is available to choose one; "+
				"use --instance or set %s:\n%s", instanceEnv, listInstances(live))
	}
	defer func() { _ = tty.Close() }()

	_, _ = fmt.Fprintf(tty, "Multiple evetest instances are running:\n%s", listInstances(live))
	reader := bufio.NewReader(tty)
	for {
		_, _ = fmt.Fprintf(tty, "Select instance [1-%d]: ", len(live))
		line, err := reader.ReadString('\n')
		if err != nil {
			return instances.Instance{}, fmt.Errorf("no instance selected: %w", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		inst, err := instances.Match(live, line)
		if err != nil {
			_, _ = fmt.Fprintf(tty, "%v\n", err)
			continue
		}
		if remembered, err := instances.Remember(inst); err != nil {
			_, _ = fmt.Fprintf(tty, "warning: cannot remember the choice: %v\n", err)
		} else if remembered {
			_, _ = fmt.Fprintf(tty, "Using %s (port %d) for this terminal; "+
				"change with \"evetest use\".\n", inst.Name, inst.Port)
		}
		return inst, nil
	}
}

func listInstances(list []instances.Instance) string {
	var sb strings.Builder
	for i, inst := range list {
		fmt.Fprintf(&sb, "  %d) %s (port %d)\n", i+1, inst.Name, inst.Port)
	}
	return sb.String()
}
