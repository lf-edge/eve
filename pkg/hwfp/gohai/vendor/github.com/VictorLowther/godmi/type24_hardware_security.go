/*
* File Name:	type24_hardware_security.go
* Description:	
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-19
*/
package godmi

import (
	"fmt"
)

type HardwareSecurityStatus byte

const (
	HardwareSecurityStatusDisabled HardwareSecurityStatus = iota
	HardwareSecurityStatusEnabled
	HardwareSecurityStatusNotImplemented
	HardwareSecurityStatusUnknown
)

func (h HardwareSecurityStatus) String() string {
	status := [...]string{
		"Disabled",
		"Enabled",
		"Not Implemented",
		"Unknown",
	}
	return status[h]
}

type HardwareSecuritySettings struct {
	PowerOnPassword       HardwareSecurityStatus
	KeyboardPassword      HardwareSecurityStatus
	AdministratorPassword HardwareSecurityStatus
	FrontPanelReset       HardwareSecurityStatus
}

func NewHardwareSecurity(data byte) HardwareSecuritySettings {
	var h HardwareSecuritySettings
	h.PowerOnPassword = HardwareSecurityStatus(data & 0xC0)
	h.KeyboardPassword = HardwareSecurityStatus(data & 0x30)
	h.AdministratorPassword = HardwareSecurityStatus(data & 0x0C)
	h.FrontPanelReset = HardwareSecurityStatus(data & 0x03)
	return h
}

func (h HardwareSecuritySettings) String() string {
	return fmt.Sprintf("Power-on Password Status: %s\n"+
		"Keyboard Password Status: %s\n"+
		"Administrator Password Status: %s\n"+
		"Front Panel Reset Status: %s\n",
		h.PowerOnPassword,
		h.KeyboardPassword,
		h.AdministratorPassword,
		h.FrontPanelReset)
}

type HardwareSecurity struct {
	infoCommon
	Setting HardwareSecuritySettings
}

func (h HardwareSecurity) String() string {
	return fmt.Sprintf("Hardware Security\n"+
		"\tSetting: %s\n",
		h.Setting)
}
