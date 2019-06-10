/*
* File Name:	type126_inactive.go
* Description:	
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-20
*/
package godmi

type Inactive struct {
	infoCommon
}

func (i Inactive) String() string {
	return "Inactive"
}
