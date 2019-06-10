/*
* File Name:	type35_management_device_component.go
* Description:	
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-20
*/
package godmi

import (
	"fmt"
)

type ManagementDeviceComponent struct {
	infoCommon
	Description            string
	ManagementDeviceHandle uint16
	ComponentHandle        uint16
	ThresholdHandle        uint16
}

func (m ManagementDeviceComponent) String() string {
	return fmt.Sprintf("Management Device Component\n"+
		"\tDescription: %s\n"+
		"\tManagement Device Handle: %d\n"+
		"\tComponent Handle: %d\n"+
		"\tThreshold Handle: %d",
		m.Description,
		m.ManagementDeviceHandle,
		m.ComponentHandle,
		m.ThresholdHandle)
}
