package address

import "fmt"

type Address struct {
	Busnum uint16 `json:"bus"`
	Port   string `json:"port"`
}

func (a Address) String() string {
	return fmt.Sprintf("%d-%s", a.Busnum, a.Port)
}
