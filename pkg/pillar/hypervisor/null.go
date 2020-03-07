// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	"io/ioutil"
	"os"

	log "github.com/sirupsen/logrus"
)

type domState struct {
	id     int
	config string
	state  string
}

type NullContext struct {
	tempDir    string
	doms       map[string]*domState
	domCounter int
	PCI        map[string]bool
}

func newNull() Hypervisor {
	res := NullContext{tempDir: "/tmp",
		doms:       map[string]*domState{},
		domCounter: 0,
		PCI:        map[string]bool{}}
	if dir, err := ioutil.TempDir("", "null_domains"); err == nil {
		res.tempDir = dir
	}
	return res
}

func (ctx NullContext) Name() string {
	return "null"
}

func (ctx NullContext) Create(domainName string, cfgFilename string) (int, error) {
	// pre-flight checks
	if _, err := os.Stat(cfgFilename); domainName == "" || err != nil {
		return 0, fmt.Errorf("Null Domain create failed to create domain with either empty name or empty config %s\n", domainName)
	}
	if _, found := ctx.doms[domainName]; found {
		return 0, fmt.Errorf("Null Domain create failed to create existing domain %s\n", domainName)
	}

	domDescriptor := ctx.tempDir + "/" + domainName
	domFile, err := os.Create(domDescriptor)
	if err != nil {
		return 0, fmt.Errorf("Null Domain create failed to create domain descriptor %v\n", err)
	}

	config, err := ioutil.ReadFile(cfgFilename)
	if err != nil {
		return 0, fmt.Errorf("Null Domain create failed to read cfgFilename %s %v\n", cfgFilename, err)
	}

	if _, err := domFile.Write(config); err != nil {
		return 0, fmt.Errorf("Null Domain create failed to write domain descriptor %s %v\n", domDescriptor, err)
	}

	// calls to Create are serialized in the consumer: no need to worry about locking
	ctx.domCounter++
	ctx.doms[domainName] = &domState{id: ctx.domCounter, config: string(config), state: "stopped"}

	return ctx.domCounter, nil
}

func (ctx NullContext) Start(domainName string, domainID int) error {
	if dom, found := ctx.doms[domainName]; found && dom.state == "stopped" {
		dom.state = "running"
		return nil
	} else {
		return fmt.Errorf("null domain %s doesn't exist or is not stopped", domainName)
	}
}

func (ctx NullContext) Stop(domainName string, domainID int, force bool) error {
	if dom, found := ctx.doms[domainName]; found && dom.state == "running" {
		dom.state = "stopped"
		return nil
	} else {
		return fmt.Errorf("null domain %s doesn't exist or is not running", domainName)
	}
}

func (ctx NullContext) Delete(domainName string, domainID int) error {
	// calls to Delete are serialized in the consumer: no need to worry about locking
	os.RemoveAll(ctx.tempDir + "/" + domainName)
	delete(ctx.doms, domainName)
	return nil
}

func (ctx NullContext) Info(domainName string, domainID int) error {
	if dom, found := ctx.doms[domainName]; found {
		log.Infof("Null Domain %s is %s and has the following config %s\n", domainName, dom.state, dom.config)
		return nil
	} else {
		log.Errorf("Null Domain %s doesn't exist", domainName)
		return fmt.Errorf("null domain %s doesn't exist", domainName)
	}
}

func (ctx NullContext) LookupByName(domainName string, domainID int) (int, error) {
	if dom, found := ctx.doms[domainName]; found {
		return dom.id, nil
	} else {
		return 0, fmt.Errorf("null domain %s doesn't exist", domainName)
	}
}

func (ctx NullContext) Tune(string, int, int) error {
	return nil
}

func (ctx NullContext) PCIReserve(long string) error {
	if ctx.PCI[long] {
		return fmt.Errorf("PCI %s is already reserved", long)
	} else {
		ctx.PCI[long] = true
		return nil
	}
}

func (ctx NullContext) PCIRelease(long string) error {
	if !ctx.PCI[long] {
		return fmt.Errorf("PCI %s is not reserved", long)
	} else {
		ctx.PCI[long] = false
		return nil
	}
}

func (ctx NullContext) IsDeviceModelAlive(int) bool {
	return true
}
