/*
* File Name:	type23_system_reset.go
* Description:	
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-19
*/
package godmi

import (
	"fmt"
)

type SystemResetBootOption byte

const (
	SystemResetBootOptionReserved SystemResetBootOption = iota
	SystemResetBootOptionOperatingSystem
	SystemResetBootOptionSystemUtilities
	SystemResetBootOptionDoNotReboot
)

func (s SystemResetBootOption) String() string {
	options := [...]string{
		"Reserved",
		"Operating System",
		"System Utilities",
		"Do Not Reboot",
	}
	return options[s]
}

type SystemResetCapabilities struct {
	Status            bool
	BootOptionOnLimit SystemResetBootOption
	BootOption        SystemResetBootOption
	WatchdogTimer     bool
}

func NewSystemResetCapablities(data byte) SystemResetCapabilities {
	var s SystemResetCapabilities
	s.Status = (data&0x01 != 0)
	s.BootOption = SystemResetBootOption(data & 0x06)
	s.BootOptionOnLimit = SystemResetBootOption(data & 0x18)
	s.WatchdogTimer = data&0x20 != 0
	return s
}

func (s SystemResetCapabilities) String() string {
	return fmt.Sprintf("Capablities\n"+
		"\tStatus: %t\n"+
		"\tBoot Option: %s\n"+
		"\tBoot Option On Limit: %s\n"+
		"\tWatchdog Timer: %t",
		s.Status,
		s.BootOption,
		s.BootOptionOnLimit,
		s.WatchdogTimer)
}

type SystemReset struct {
	infoCommon
	Capabilities  byte
	ResetCount    uint16
	ResetLimit    uint16
	TimerInterval uint16
	Timeout       uint16
}

func (s SystemReset) String() string {
	return fmt.Sprintf("System Reset\n"+
		"\tCapabilities: %s\n"+
		"\tReset Count: %d\n"+
		"\tReset Limit: %d\n"+
		"\tTimer Interval: %d\n"+
		"\tTimeout: %d",
		s.Capabilities,
		s.ResetCount,
		s.ResetLimit,
		s.TimerInterval,
		s.Timeout)
}

