/*
* File Name:	type12_systemconfig.go
* Description:
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-19
 */
package godmi

import (
	"fmt"
	"strconv"
)

type SystemConfigurationOptions struct {
	infoCommon
	Count   byte
	strings string
}

func (s SystemConfigurationOptions) String() string {
	return fmt.Sprintf("System Configuration Option\n\t\t%s", s.strings)
}

func newSystemConfigurationOptions(h dmiHeader) dmiTyper {
	var sc SystemConfigurationOptions
	data := h.data
	sc.Count = data[0x04]
	for i := 1; i <= int(sc.Count); i++ {
		sc.strings += fmt.Sprintf("string %d: %s\n\t\t", i, h.FieldString(i))
	}
	SystemConfigurationOptionsList = append(SystemConfigurationOptionsList, &sc)
	return &sc
}

var SystemConfigurationOptionsList []*SystemConfigurationOptions

func GetSystemConfigurationOptions() string {
	var ret string
	for i, v := range SystemConfigurationOptionsList {
		ret += "\nSystem configuration options strings index:" + strconv.Itoa(i) + "\n" + v.String()
	}
	return ret
}

func init() {
	addTypeFunc(SMBIOSStructureTypeSystemConfigurationOptions, newSystemConfigurationOptions)
}
