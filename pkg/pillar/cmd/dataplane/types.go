// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Defines json structures for control messages from lispers.net

package dataplane

const CRYPTO_KEY_LEN = 32

// These message type definitions should be in sync with lispers.net
const (
	MAPCACHETYPE         = "map-cache"
	ENTIREMAPCACHE       = "entire-map-cache"
	DATABASEMAPPINGSTYPE = "database-mappings"
	INTERFACESTYPE       = "interfaces"
	DECAPKEYSTYPE        = "decap-keys"
	ETRNATPORT           = "etr-nat-port"
	ITRCRYPTOPORT        = "itr-crypto-port"
)

type Type struct {
	Type string `json:"type"`
}

type Key struct {
	KeyId  string `json:"key-id"`
	EncKey string `json:"encrypt-key"`
	IcvKey string `json:"icv-key"`
}

type DKey struct {
	KeyId  string `json:"key-id"`
	DecKey string `json:"decrypt-key"`
	IcvKey string `json:"icv-key"`
}

type Rloc struct {
	Rloc     string `json:"rloc"`
	Port     string `json:"port"`
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

type EntireMapCache struct {
	MapCaches []MapCacheEntry
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
	//InstanceId int `json:"instance-id"`
}

type Interfaces struct {
	Interfaces []Interface `json:"interfaces"`
}

type DecapKeys struct {
	Rloc string `json:"rloc"`
	Port string `json:"port"`
	Keys []DKey `json:"keys"`
}

type EtrNatPort struct {
	Type string `json:"type"`
	Port int    `json:"port"`
}

type ItrCryptoPort struct {
	Type string `json:"type"`
	Port int    `json:"port"`
}
