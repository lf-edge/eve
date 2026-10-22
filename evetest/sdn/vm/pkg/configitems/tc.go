// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"

	"github.com/lf-edge/eve-libs/depgraph"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/sdn/vm/pkg/maclookup"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// TrafficControl represents traffic control rules applied to a physical interface.
type TrafficControl struct {
	*api.TrafficControl
	// PhysIf : target physical network interface for traffic control.
	PhysIf PhysIf
}

// Name returns MAC address of the physical interface as the unique identifier
// for the TrafficControl instance.
func (t TrafficControl) Name() string {
	return t.PhysIf.MAC.String()
}

// Label is used only for the visualization purposes of the config/state depgraph.
func (t TrafficControl) Label() string {
	return t.PhysIf.LogicalLabel + " (traffic control)"
}

// Type assigned to TrafficControl
func (t TrafficControl) Type() string {
	return TrafficControlTypename
}

// Equal is a comparison method for two equally-named TrafficControl instances.
func (t TrafficControl) Equal(other depgraph.Item) bool {
	t2, isTrafficControl := other.(TrafficControl)
	if !isTrafficControl {
		return false
	}
	return proto.Equal(t.TrafficControl, t2.TrafficControl)
}

// External returns false.
func (t TrafficControl) External() bool {
	return false
}

// String describes TrafficControl instance.
func (t TrafficControl) String() string {
	return fmt.Sprintf("Traffic control: %#+v", t)
}

// Dependencies lists the physical interface as the only dependency.
func (t TrafficControl) Dependencies() (deps []depgraph.Dependency) {
	return []depgraph.Dependency{
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: PhysIfTypename,
				ItemName: t.PhysIf.MAC.String(),
			},
			Description: "Underlying physical network interface must exist",
		},
	}
}

// TrafficControlConfigurator implements Configurator interface for TrafficControl.
type TrafficControlConfigurator struct {
	MacLookup *maclookup.MacLookup
}

// Create applies traffic control rules for the physical interface.
func (c *TrafficControlConfigurator) Create(_ context.Context, item depgraph.Item) error {
	tc, isTrafficControl := item.(TrafficControl)
	if !isTrafficControl {
		return fmt.Errorf("invalid item type %T, expected TrafficControl", item)
	}
	netIf, found := c.MacLookup.GetInterfaceByMAC(tc.PhysIf.MAC, false)
	if !found {
		err := fmt.Errorf("failed to get physical interface with MAC %v", tc.PhysIf.MAC)
		log.Error(err)
		return err
	}
	useTBF := tc.GetRateLimit() != 0
	useNetem := tc.GetDelay() != 0 || tc.GetLossProbability() != 0 ||
		tc.GetCorruptProbability() != 0 || tc.GetDuplicateProbability() != 0 ||
		tc.GetReorderProbability() != 0
	if useTBF && !useNetem {
		// example:
		// tc qdisc add dev eth2 root tbf rate 256kbit burst 16kb limit 30kb
		var args []string
		args = append(args, "qdisc", "add", "dev", netIf.IfName, "root", "tbf")
		args = append(args, c.getTBFArgs(tc)...)
		output, err := exec.Command("tc", args...).CombinedOutput()
		if err != nil {
			err = fmt.Errorf("failed to configure tc-tbf for interface %s: %s (%w)",
				netIf.IfName, output, err)
			log.Error(err)
			return err
		}
	}
	if !useTBF && useNetem {
		// example:
		// tc qdisc add dev eth2 root netem loss 5%
		var args []string
		args = append(args, "qdisc", "add", "dev", netIf.IfName, "root", "netem")
		args = append(args, c.getNetemArgs(tc)...)
		output, err := exec.Command("tc", args...).CombinedOutput()
		if err != nil {
			err = fmt.Errorf("failed to configure tc-netem for interface %s: %s (%w)",
				netIf.IfName, output, err)
			log.Error(err)
			return err
		}
	}
	if useTBF && useNetem {
		// example:
		// tc qdisc add dev eth2 root handle 1: tbf rate 256kbit buffer 16kb limit 30kb
		// tc qdisc add dev eth2 parent 1:1 handle 10: netem delay 100ms
		var args []string
		args = append(args, "qdisc", "add", "dev", netIf.IfName,
			"root", "handle", "1:", "tbf")
		args = append(args, c.getTBFArgs(tc)...)
		output, err := exec.Command("tc", args...).CombinedOutput()
		if err != nil {
			err = fmt.Errorf("failed to configure tc-tbf for interface %s: %s (%w)",
				netIf.IfName, output, err)
			log.Error(err)
			return err
		}
		args = nil
		args = append(args, "qdisc", "add", "dev", netIf.IfName,
			"parent", "1:1", "handle", "2:", "netem")
		args = append(args, c.getNetemArgs(tc)...)
		output, err = exec.Command("tc", args...).CombinedOutput()
		if err != nil {
			err = fmt.Errorf("failed to configure tc-netem for interface %s: %s (%w)",
				netIf.IfName, output, err)
			log.Error(err)
			return err
		}
	}
	return nil
}

func (c *TrafficControlConfigurator) getTBFArgs(tc TrafficControl) []string {
	var args []string
	if tc.GetRateLimit() != 0 {
		args = append(args, "rate", strconv.Itoa(int(tc.GetRateLimit()))+"kbps")
	}
	if tc.GetBurstLimit() != 0 {
		args = append(args, "burst", strconv.Itoa(int(tc.GetBurstLimit()))+"kb")
	}
	if tc.GetQueueLimit() != 0 {
		args = append(args, "limit", strconv.Itoa(int(tc.GetQueueLimit()))+"kb")
	}
	return args
}

func (c *TrafficControlConfigurator) getNetemArgs(tc TrafficControl) []string {
	var args []string
	if tc.GetDelay() != 0 {
		args = append(args, "delay", strconv.Itoa(int(tc.GetDelay()))+"ms")
		if tc.GetDelayJitter() != 0 {
			args = append(args, strconv.Itoa(int(tc.GetDelayJitter()))+"ms")
		}
	}
	if tc.GetLossProbability() != 0 {
		args = append(args, "loss", "random", strconv.Itoa(int(tc.GetLossProbability()))+"%")
	}
	if tc.GetCorruptProbability() != 0 {
		args = append(args, "corrupt", strconv.Itoa(int(tc.GetCorruptProbability()))+"%")
	}
	if tc.GetDuplicateProbability() != 0 {
		args = append(args, "duplicate", strconv.Itoa(int(tc.GetDuplicateProbability()))+"%")
	}
	if tc.GetReorderProbability() != 0 {
		args = append(args, "reorder", strconv.Itoa(int(tc.GetReorderProbability()))+"%")
	}
	return args
}

// Modify is not implemented.
func (c *TrafficControlConfigurator) Modify(_ context.Context, _, _ depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete removes applied traffic control rules from the physical interface.
func (c *TrafficControlConfigurator) Delete(_ context.Context, item depgraph.Item) error {
	tc, isTrafficControl := item.(TrafficControl)
	if !isTrafficControl {
		return fmt.Errorf("invalid item type %T, expected TrafficControl", item)
	}
	netIf, found := c.MacLookup.GetInterfaceByMAC(tc.PhysIf.MAC, false)
	if !found {
		err := fmt.Errorf("failed to get physical interface with MAC %v", tc.PhysIf.MAC)
		log.Error(err)
		return err
	}
	// example:
	// tc qdisc del dev eth2 root
	var args []string
	args = append(args, "qdisc", "del", "dev", netIf.IfName, "root")
	output, err := exec.Command("tc", args...).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("failed to unconfigure tc from interface %s: %s (%w)",
			netIf.IfName, output, err)
		log.Error(err)
		return err
	}
	return nil
}

// NeedsRecreate returns true, Modify is not implemented.
func (c *TrafficControlConfigurator) NeedsRecreate(_, _ depgraph.Item) (recreate bool) {
	return true
}
