/*
* File Name:	type127_end_of_table.go
* Description:	
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-20
*/
package godmi

type EndOfTable struct {
	infoCommon
}

func (e EndOfTable) String() string {
	return "End-of-Table"
}
