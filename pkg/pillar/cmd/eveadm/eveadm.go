package eveadm

import "github.com/lf-edge/eve/pkg/pillar/pubsub"
import "github.com/lf-edge/eve/pkg/pillar/cmd/eveadm/cmd"

//Run is integration into zedbox
func Run(ps *pubsub.PubSub) {
	cmd.Execute()
}
