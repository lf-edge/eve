/*
* File Name:	type13_bioslang.go
* Description:
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-19
 */
package godmi

import (
	"fmt"
	"strconv"
)

type BIOSLanguageInformationFlag byte

const (
	BIOSLanguageInformationFlagLongFormat BIOSLanguageInformationFlag = iota
	BIOSLanguageInformationFlagAbbreviatedFormat
)

func (f BIOSLanguageInformationFlag) String() string {
	if f == BIOSLanguageInformationFlagLongFormat {
		return "long format"
	}
	return "abbreviated format"
}

func NewBIOSLanguageInformationFlag(f byte) BIOSLanguageInformationFlag {
	return BIOSLanguageInformationFlag(f & 0x01)
}

type BIOSLanguageInformation struct {
	infoCommon
	InstallableLanguage []string
	Flags               BIOSLanguageInformationFlag
	CurrentLanguage     string
}

func (b BIOSLanguageInformation) String() string {
	return fmt.Sprintf("BIOS Language Information:\n"+
		"\tInstallable Languages %s\n"+
		"\tFlags: %v\n"+
		"\tCurrent Language: %s",
		b.InstallableLanguage,
		b.Flags,
		b.CurrentLanguage)
}

func newBIOSLanguageInformation(h dmiHeader) dmiTyper {
	var bl BIOSLanguageInformation
	data := h.data
	cnt := data[0x04]
	for i := 1; i <= int(cnt); i++ {
		bl.InstallableLanguage = append(bl.InstallableLanguage, h.FieldString(i))
	}
	bl.Flags = NewBIOSLanguageInformationFlag(data[0x05])
	bl.CurrentLanguage = bl.InstallableLanguage[data[0x15]-1]
	BIOSLanguageInformations = append(BIOSLanguageInformations, &bl)
	return &bl
}

var BIOSLanguageInformations []*BIOSLanguageInformation

func GetBIOSLanguageInformation() string {
	var ret string
	for i, v := range BIOSLanguageInformations {
		ret += "\nBIOS language infomation strings index:" + strconv.Itoa(i) + "\n" + v.String()
	}
	return ret
}

func init() {
	addTypeFunc(SMBIOSStructureTypeBIOSLanguage, newBIOSLanguageInformation)
}
