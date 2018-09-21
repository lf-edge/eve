// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package logmanager

import (
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
)

// Return the UUID of the instance based on the domainname
func lookupDomainName(domainName string) string {
	if du, ok := domainUuid[domainName]; ok {
		return du
	}
	return ""
}

// Map from domainName to the UUID
var domainUuid map[string]string = make(map[string]string)

func handleDomainStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Debugf("handleDomainStatusModify for %s\n", key)
	status := cast.CastDomainStatus(statusArg)
	if status.Key() != key {
		log.Errorf("handleDomainStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	// Record the domainName even if Pending* is set
	domainUuid[status.DomainName] = status.UUIDandVersion.UUID.String()
	log.Debugf("handleDomainStatusModify done for %s\n", key)
}

func handleDomainStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Debugf("handleDomainStatusDelete for %s\n", key)
	status := cast.CastDomainStatus(statusArg)
	if status.Key() != key {
		log.Errorf("handleDomainStatusDelete key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	if _, ok := domainUuid[status.UUIDandVersion.UUID.String()]; !ok {
		log.Errorf("handleDomainStatusDelete UUID %s not in map\n",
			status.UUIDandVersion.UUID.String())
		return
	}
	delete(domainUuid, status.UUIDandVersion.UUID.String())
	log.Debugf("handleDomainStatusDelete done for %s\n", key)
}
