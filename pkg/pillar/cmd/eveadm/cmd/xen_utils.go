package cmd

import (
	"errors"
)

//XENContext have parameters for fire xen eveadm
type XENContext struct {
	containerUUID  string
	xenCfgFilename string
	containerName  string
	runPaused      bool
	force          bool
}

var xenctx XENContext

func (ctx XENContext) xenListToCmd() (args []string, envs string, err error) {
	args = []string{"xl", "list"}
	envs = ""
	err = nil
	return
}
func (ctx XENContext) xenCreateToCmd() (args []string, envs string, err error) {
	if ctx.xenCfgFilename == "" {
		return nil, "", errors.New("no xenCfgFilename in args")
	}
	args = []string{"xl", "create", ctx.xenCfgFilename}
	if ctx.runPaused {
		args = append(args, "-p")
	}
	err = nil
	return
}
func (ctx XENContext) xenStopToCmd() (args []string, envs string, err error) {
	if ctx.containerUUID == "" {
		return nil, "", errors.New("no container uuid in args")
	}
	args = []string{"xl", "shutdown"}
	if ctx.force {
		args = append(args, "-F")
	}
	args = append(args, ctx.containerUUID)
	envs = ""
	err = nil
	return
}
func (ctx XENContext) xenInfoToCmd() (args []string, envs string, err error) {
	if ctx.containerUUID == "" {
		return nil, "", errors.New("no container uuid in args")
	}
	args = []string{"xl", "list", "-l", ctx.containerUUID}
	envs = ""
	err = nil
	return
}
func (ctx XENContext) xenInfoDomidToCmd() (args []string, envs string, err error) {
	if ctx.containerName == "" {
		return nil, "", errors.New("no container name in args")
	}
	args = []string{"xl", "domid", ctx.containerName}
	envs = ""
	err = nil
	return
}
func (ctx XENContext) xenDeleteToCmd() (args []string, envs string, err error) {
	if ctx.containerUUID == "" {
		return nil, "", errors.New("no container uuid in args")
	}
	args = []string{"xl", "destroy", ctx.containerUUID}
	envs = ""
	err = nil
	return
}
func (ctx XENContext) xenStartToCmd() (args []string, envs string, err error) {
	if ctx.containerUUID == "" {
		return nil, "", errors.New("no container uuid in args")
	}
	args = []string{"xl", "unpause", ctx.containerUUID}
	envs = ""
	err = nil
	return
}
