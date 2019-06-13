/*
* File Name:	type11_oem.go
* Description:
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-19
 */
package godmi

import (
	"fmt"
	"strconv"
)

type OEMStrings struct {
	infoCommon
	Count   byte
	strings string
}

func (o OEMStrings) String() string {
	return fmt.Sprintf("OEM strings:\n\t\t%s", o.strings)
}

func newOEMStrings(h dmiHeader) dmiTyper {
	var o OEMStrings
	data := h.data
	o.Count = data[0x04]
	for i := 1; i <= int(o.Count); i++ {
		o.strings += fmt.Sprintf("strings: %d %s\n\t\t", i, h.FieldString(i))
	}
	OEMStringsList = append(OEMStringsList, &o)
	return &o
}

var OEMStringsList []*OEMStrings

func GetOEMStrings() string {
	var ret string
	for i, v := range OEMStringsList {
		ret += "\nOEM strings index:" + strconv.Itoa(i) + "\n" + v.String()
	}
	return ret
}

func init() {
	addTypeFunc(SMBIOSStructureTypeOEMStrings, newOEMStrings)
}
