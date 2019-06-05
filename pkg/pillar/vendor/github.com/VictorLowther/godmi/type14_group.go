/*
* File Name:	type14_group.go
* Description:
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-19
 */
package godmi

import (
	"fmt"
	"strconv"
)

type GroupAssociationsItem struct {
	Type   SMBIOSStructureType
	Handle SMBIOSStructureHandle
}

type GroupAssociations struct {
	infoCommon
	GroupName string
	Item      []GroupAssociationsItem
}

func (g GroupAssociations) String() string {
	return fmt.Sprintf("Group Associations:\n"+
		"\tGroup Name: %s\n"+
		"\tItem: %#v\n",
		g.GroupName,
		g.Item)
}

func newGroupAssociations(h dmiHeader) dmiTyper {
	var ga GroupAssociations
	data := h.data
	ga.GroupName = h.FieldString(int(data[0x04]))
	cnt := (h.length - 5) / 3
	items := data[5:]
	var i byte
	for i = 0; i < cnt; i++ {
		var gai GroupAssociationsItem
		gai.Type = SMBIOSStructureType(items[i*3])
		gai.Handle = SMBIOSStructureHandle(u16(items[i*3+1:]))
		ga.Item = append(ga.Item, gai)
	}
	GroupAssociationsList = append(GroupAssociationsList, &ga)
	return &ga
}

var GroupAssociationsList []*GroupAssociations

func GetGroupAssociations() string {
	var ret string
	for i, v := range GroupAssociationsList {
		ret += "\nGroup Associations index:" + strconv.Itoa(i) + "\n" + v.String()
	}
	return ret
}

func init() {
	addTypeFunc(SMBIOSStructureTypeGroupAssociations, newGroupAssociations)
}
