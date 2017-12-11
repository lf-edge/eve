package main

type Type struct {
    Type string `json:"type"`
}

type Key struct {
    KeyId string `json:"key-id"`
    Key   string `json:"key"`
}

type Rloc struct {
    Rloc     string `json:"rloc"`
    Priority string `json:"priority"`
    Weight   string `json:"weight"`
    Keys     []Key  `json:"keys"`
}

type MapCacheEntry struct {
	Opcode     string `json:"opcode"`
    InstanceId string `json:"instance-id"`
    EidPrefix  string `json:"eid-prefix"`
    Rlocs      []Rloc `json:"rlocs"`
}

type DatabaseMap struct {
    InstanceId string `json:"instance-id"`
    EidPrefix  string `json:"eid-prefix"`
}

type DatabaseMappings struct {
    Mappings []DatabaseMap `json:"database-mappings"`
}

type Interface struct {
    Interface  string `json:"interface"`
    InstanceId string `json:"instance-id"`
}

type Interfaces struct {
    Interfaces []Interface `json:"interfaces"`
}

type DecapKeys struct {
    Rloc string `json:"rloc"`
    Keys []Key  `json:"keys"`
}
