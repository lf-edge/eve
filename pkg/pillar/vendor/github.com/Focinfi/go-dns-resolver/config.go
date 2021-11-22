package resolver

import (
	"time"
)

type Configuration struct {
	Timeout    time.Duration
	RetryTimes uint
}

func (c *Configuration) SetTimeout(seconds uint) {
	c.Timeout = time.Second * time.Duration(seconds)
}

var Config = Configuration{Timeout: time.Second * time.Duration(2), RetryTimes: uint(0)}
