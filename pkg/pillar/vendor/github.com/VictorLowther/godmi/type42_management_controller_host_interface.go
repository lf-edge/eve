/*
* File Name:	type42_management_controller_host_interface.go
* Description:	
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-20
*/
package godmi

import (
	"fmt"
)

type ManagementControllerHostInterfaceType byte

const (
	ManagementControllerHostInterfaceTypeKCSKeyboardControllerStyle ManagementControllerHostInterfaceType = 0x02 + iota
	ManagementControllerHostInterfaceType8250UARTRegisterCompatible
	ManagementControllerHostInterfaceType16450UARTRegisterCompatible
	ManagementControllerHostInterfaceType16550_16550AUARTRegisterCompatible
	ManagementControllerHostInterfaceType16650_16650AUARTRegisterCompatible
	ManagementControllerHostInterfaceType16750_16750AUARTRegisterCompatible
	ManagementControllerHostInterfaceType16850_16850AUARTRegisterCompatible
)

func (m ManagementControllerHostInterfaceType) String() string {
	types := [...]string{
		"KCS: Keyboard Controller Style",
		"8250 UART Register Compatible",
		"16450 UART Register Compatible",
		"16550/16550A UART Register Compatible",
		"16650/16650A UART Register Compatible",
		"16750/16750A UART Register Compatible",
		"16850/16850A UART Register Compatible",
	}
	if m >= 0x02 && m <= 0x08 {
		return types[m-0x02]
	}
	if m == 0xf0 {
		return "OEM"
	}
	return "<OUT OF SPEC>"
}

type ManagementControllerHostInterfaceData []byte

type ManagementControllerHostInterface struct {
	infoCommon
	Type ManagementControllerHostInterfaceType
	Data ManagementControllerHostInterfaceData
}

func (m ManagementControllerHostInterface) MCHostInterfaceData() string {
	if m.Type == 0xF0 {
		return fmt.Sprintf("Vendor ID:0x%02X%02X%02X%02X",
			m.Data[0x01], m.Data[0x02], m.Data[0x03], m.Data[0x04])
	}
	return ""
}

func (m ManagementControllerHostInterface) String() string {
	return fmt.Sprintf("Management Controller Host Interface\n"+
		"\tType: %s\n"+
		"\tMC Host Interface Data: %s\n",
		m.Type,
		m.MCHostInterfaceData)
}
