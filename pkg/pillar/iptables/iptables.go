// Copyright (c) 2017,2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// iptables support code

package iptables

import (
	"errors"
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/base"
)

const (
	// DeviceChainSuffix : suffix added to the name of a chain,
	// which is configured by NIM for device-wide access control.
	DeviceChainSuffix = "-device"
	// AppChainSuffix : suffix added to the name of a chain,
	// which is configured by Zedrouter for app-scoped access control.
	AppChainSuffix = "-apps"
)

const (
	iptablesCmd  = "iptables"
	ip6tablesCmd = "ip6tables"
)

type iptablesFnType func(log *base.LogObject, args ...string) error

var iptablesFn = map[string]iptablesFnType{
	iptablesCmd:  IptableCmd,
	ip6tablesCmd: Ip6tableCmd,
}

// IptableCmdOut logs the command string if log is set
func IptableCmdOut(log *base.LogObject, args ...string) (string, error) {
	var out []byte
	var err error
	// XXX as long as zedagent also calls iptables we need to
	// wait for the lock with -w 5
	args = append(args, "a", "b")
	copy(args[2:], args[0:])
	args[0] = "-w"
	args[1] = "5"
	if log != nil {
		log.Functionf("Calling command %s %v\n", iptablesCmd, args)
		out, err = base.Exec(log, iptablesCmd, args...).CombinedOutput()
	} else {
		out, err = base.Exec(log, iptablesCmd, args...).Output()
	}
	if err != nil {
		errStr := fmt.Sprintf("iptables command %s failed %s output %s",
			args, err, out)
		if log != nil {
			log.Errorln(errStr)
		}
		return "", errors.New(errStr)
	}
	return string(out), nil
}

// IptableCmd logs the command string if log is set
func IptableCmd(log *base.LogObject, args ...string) error {
	_, err := IptableCmdOut(log, args...)
	return err
}

// Ip6tableCmdOut logs the command string if log is set
func Ip6tableCmdOut(log *base.LogObject, args ...string) (string, error) {
	var out []byte
	var err error
	// XXX as long as zedagent also calls iptables we need to
	// wait for the lock with -w 5
	args = append(args, "a", "b")
	copy(args[2:], args[0:])
	args[0] = "-w"
	args[1] = "5"
	if log != nil {
		log.Functionf("Calling command %s %v\n", ip6tablesCmd, args)
		out, err = base.Exec(log, ip6tablesCmd, args...).CombinedOutput()
	} else {
		out, err = base.Exec(log, ip6tablesCmd, args...).Output()
	}
	if err != nil {
		errStr := fmt.Sprintf("ip6tables command %s failed %s output %s",
			args, err, out)
		if log != nil {
			log.Errorln(errStr)
		}
		return "", errors.New(errStr)
	}
	return string(out), nil
}

// Ip6tableCmd logs the command string if log is set
func Ip6tableCmd(log *base.LogObject, args ...string) error {
	_, err := Ip6tableCmdOut(log, args...)
	return err
}
