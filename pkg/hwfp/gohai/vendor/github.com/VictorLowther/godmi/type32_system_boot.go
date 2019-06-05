/*
* File Name:	type32_system_boot.go
* Description:	
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-20
*/
package godmi

import (
	"fmt"
)

type SystemBootInformationStatus byte

func (s SystemBootInformationStatus) String() string {
	status := [...]string{
		"No errors detected", /* 0 */
		"No bootable media",
		"Operating system failed to load",
		"Firmware-detected hardware failure",
		"Operating system-detected hardware failure",
		"User-requested boot",
		"System security violation",
		"Previously-requested image",
		"System watchdog timer expired",
	}
	if s <= 8 {
		return status[s]
	} else if s >= 128 && s <= 191 {
		return "OEM-specific"
	} else if s > 192 && s <= 255 {
		return "Product-specific"
	}
	return "Error"
}

type SystemBootInformation struct {
	infoCommon
	BootStatus SystemBootInformationStatus
}

func (s SystemBootInformation) String() string {
	return fmt.Sprintf("System Boot Information\n"+
		"\tBoot Status: %s",
		s.BootStatus)
}


