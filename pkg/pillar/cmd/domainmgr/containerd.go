package domainmgr

import (
	"context"
	"os"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	log "github.com/sirupsen/logrus"
)

const (
	// containerd socket
	ctrdSocket = "/run/containerd/containerd.sock"
	// CtrdServicesNamespace containerd namespace for running containers
	CtrdServicesNamespace = "eve-user-apps"
)

func containerdLoadImageTar(filename string) (map[string]string, error) {
	// load the content into the containerd content store
	ctr, err := containerd.New(ctrdSocket)
	if err != nil {
		log.Errorf("could not connect to containerd socket at %s: %+s", ctrdSocket, err.Error())
		return nil, err
	}
	defer ctr.Close()

	ctrdCtx := namespaces.WithNamespace(context.Background(), CtrdServicesNamespace)

	tarReader, err := os.Open(filename)
	if err != nil {
		log.Errorf("could not open tar file for reading at %s: %+s", filename, err.Error())
		return nil, err
	}

	imgs, err := ctr.Import(ctrdCtx, tarReader)
	if err != nil {
		log.Errorf("could not load image tar at %s into containerd: %+s", filename, err.Error())
		return nil, err
	}
	// successful, so return the list of images we imported
	names := make(map[string]string)
	for _, tag := range imgs {
		names[tag.Name] = string(tag.Target.Digest)
	}
	return names, nil
}

// TODO:
// make these work

// Launch app/container thru ctr
// returns domainID, ctrID and error
func ctrRun(domainName, xenCfgFilename, imageHash string, envList map[string]string) (int, string, error) {

	log.Infof("ctrRun %s\n", domainName)
	return 0, "", nil
}

func ctrStop(ctrID string, force bool) error {
	log.Infof("ctrStop %s %t\n", ctrID, force)
	log.Infof("ctr stop done\n")
	return nil
}

func ctrRm(ctrID string) error {
	log.Infof("ctrRm %s\n", ctrID)
	log.Infof("ctrRm done\n")
	return nil
}
