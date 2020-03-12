// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"errors"
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/wrap"
	"os/exec"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

type xenContext struct {
}

func newXen() Hypervisor {
	return xenContext{}
}

func (ctx xenContext) Name() string {
	return "xen"
}

func (ctx xenContext) Create(domainName string, xenCfgFilename string) (int, error) {
	log.Infof("xlCreate %s %s\n", domainName, xenCfgFilename)
	cmd := "xl"
	args := []string{
		"create",
		xenCfgFilename,
		"-p",
	}
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Errorln("xl create failed ", err)
		log.Errorln("xl create output ", string(stdoutStderr))
		return 0, fmt.Errorf("xl create failed: %s\n",
			string(stdoutStderr))
	}
	log.Infof("xl create done\n")

	args = []string{
		"domid",
		domainName,
	}
	stdoutStderr, err = wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Errorln("xl domid failed ", err)
		log.Errorln("xl domid output ", string(stdoutStderr))
		return 0, fmt.Errorf("xl domid failed: %s\n",
			string(stdoutStderr))
	}
	res := strings.TrimSpace(string(stdoutStderr))
	domainID, err := strconv.Atoi(res)
	if err != nil {
		log.Errorf("Can't extract domainID from %s: %s\n", res, err)
		return 0, fmt.Errorf("Can't extract domainID from %s: %s\n", res, err)
	}
	return domainID, nil
}

func (ctx xenContext) Start(domainName string, domainID int) error {
	log.Infof("xlUnpause %s %d\n", domainName, domainID)
	cmd := "xl"
	args := []string{
		"unpause",
		domainName,
	}
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Errorln("xl unpause failed ", err)
		log.Errorln("xl unpause output ", string(stdoutStderr))
		return fmt.Errorf("xl unpause failed: %s\n",
			string(stdoutStderr))
	}
	log.Infof("xlUnpause done. Result %s\n", string(stdoutStderr))
	return nil
}

func (ctx xenContext) Stop(domainName string, domainID int, force bool) error {
	log.Infof("xlShutdown %s %d\n", domainName, domainID)
	cmd := "xl"
	var args []string
	if force {
		args = []string{
			"shutdown",
			"-F",
			domainName,
		}
	} else {
		args = []string{
			"shutdown",
			domainName,
		}
	}
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Errorln("xl shutdown failed ", err)
		log.Errorln("xl shutdown output ", string(stdoutStderr))
		return fmt.Errorf("xl shutdown failed: %s\n",
			string(stdoutStderr))
	}
	log.Infof("xl shutdown done\n")
	return nil
}

func (ctx xenContext) Delete(domainName string, domainID int) error {
	log.Infof("xlDestroy %s %d\n", domainName, domainID)
	cmd := "xl"
	args := []string{
		"destroy",
		domainName,
	}
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Errorln("xl destroy failed ", err)
		log.Errorln("xl destroy output ", string(stdoutStderr))
		return fmt.Errorf("xl destroy failed: %s\n",
			string(stdoutStderr))
	}
	log.Infof("xl destroy done\n")
	return nil
}

func (ctx xenContext) Info(domainName string, domainID int) error {
	log.Infof("xlStatus %s %d\n", domainName, domainID)
	// XXX xl list -l domainName returns json. XXX but state not included!
	// Note that state is not very useful anyhow
	cmd := "xl"
	args := []string{
		"list",
		"-l",
		domainName,
	}
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Errorln("xl list failed ", err)
		log.Errorln("xl list output ", string(stdoutStderr))
		return fmt.Errorf("xl list failed: %s\n",
			string(stdoutStderr))
	}
	// XXX parse json to look at state? Not currently included
	// XXX note that there is a warning at the top of the combined
	// output. If we want to parse the json we need to get Output()
	log.Infof("xl list done. Result %s\n", string(stdoutStderr))
	return nil
}

func (ctx xenContext) LookupByName(domainName string, domainID int) (int, error) {
	log.Debugf("xlDomid %s %d\n", domainName, domainID)
	cmd := "xl"
	args := []string{
		"domid",
		domainName,
	}
	// Avoid wrap since we are called periodically
	stdoutStderr, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		log.Debugln("xl domid failed ", err)
		log.Debugln("xl domid output ", string(stdoutStderr))
		return domainID, fmt.Errorf("xl domid failed: %s\n",
			string(stdoutStderr))
	}
	res := strings.TrimSpace(string(stdoutStderr))
	domainID2, err := strconv.Atoi(res)
	if err != nil {
		log.Errorf("xl domid not integer %s: failed %s\n", res, err)
		return domainID, err
	}
	if domainID2 != domainID {
		log.Warningf("domainid changed from %d to %d for %s\n",
			domainID, domainID2, domainName)
	}
	return domainID2, err
}

// Perform xenstore write to disable all of these for all VIFs
// feature-sg, feature-gso-tcpv4, feature-gso-tcpv6, feature-ipv6-csum-offload
func (ctx xenContext) Tune(domainName string, domainID int, vifCount int) error {
	log.Infof("xlDisableVifOffload %s %d %d\n",
		domainName, domainID, vifCount)
	pref := "/local/domain"
	for i := 0; i < vifCount; i += 1 {
		varNames := []string{
			fmt.Sprintf("%s/0/backend/vif/%d/%d/feature-sg",
				pref, domainID, i),
			fmt.Sprintf("%s/0/backend/vif/%d/%d/feature-gso-tcpv4",
				pref, domainID, i),
			fmt.Sprintf("%s/0/backend/vif/%d/%d/feature-gso-tcpv6",
				pref, domainID, i),
			fmt.Sprintf("%s/0/backend/vif/%d/%d/feature-ipv4-csum-offload",
				pref, domainID, i),
			fmt.Sprintf("%s/0/backend/vif/%d/%d/feature-ipv6-csum-offload",
				pref, domainID, i),
			fmt.Sprintf("%s/%d/device/vif/%d/feature-sg",
				pref, domainID, i),
			fmt.Sprintf("%s/%d/device/vif/%d/feature-gso-tcpv4",
				pref, domainID, i),
			fmt.Sprintf("%s/%d/device/vif/%d/feature-gso-tcpv6",
				pref, domainID, i),
			fmt.Sprintf("%s/%d/device/vif/%d/feature-ipv4-csum-offload",
				pref, domainID, i),
			fmt.Sprintf("%s/%d/device/vif/%d/feature-ipv6-csum-offload",
				pref, domainID, i),
		}
		for _, varName := range varNames {
			cmd := "xenstore"
			args := []string{
				"write",
				varName,
				"0",
			}
			stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
			if err != nil {
				log.Errorln("xenstore write failed ", err)
				log.Errorln("xenstore write output ", string(stdoutStderr))
				return fmt.Errorf("xenstore write failed: %s\n",
					string(stdoutStderr))
			}
			log.Debugf("xenstore write done. Result %s\n",
				string(stdoutStderr))
		}
	}

	log.Infof("xlDisableVifOffload done.\n")
	return nil
}

func (ctx xenContext) PCIReserve(long string) error {
	log.Infof("pciAssignableAdd %s\n", long)
	cmd := "xl"
	args := []string{
		"pci-assignable-add",
		long,
	}
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("xl pci-assignable-add failed: %s\n",
			string(stdoutStderr))
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	log.Infof("xl pci-assignable-add done\n")
	return nil
}

func (ctx xenContext) PCIRelease(long string) error {
	log.Infof("pciAssignableRemove %s\n", long)
	cmd := "xl"
	args := []string{
		"pci-assignable-rem",
		"-r",
		long,
	}
	stdoutStderr, err := wrap.Command(cmd, args...).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("xl pci-assignable-rem failed: %s\n",
			string(stdoutStderr))
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	log.Infof("xl pci-assignable-rem done\n")
	return nil
}

func (ctx xenContext) IsDeviceModelAlive(domid int) bool {
	// create pgrep command to see if dataplane is running
	match := fmt.Sprintf("domid %d", domid)
	cmd := wrap.Command("pgrep", "-f", match)

	// pgrep returns 0 when there is atleast one matching program running
	// cmd.Output returns nil when pgrep returns 0, otherwise pids.
	out, err := cmd.Output()

	if err != nil {
		log.Infof("IsDeviceModelAlive: %s process is not running: %s",
			match, err)
		return false
	}
	log.Infof("IsDeviceModelAlive: Instances of %s is running: %s",
		match, out)
	return true
}
