package zedkube

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func runKubeConfig(ctx *zedkubeContext, config, oldconfig *types.EdgeNodeClusterConfig, isDel bool) {
	if oldconfig != nil {
		log.Noticef("runKubeConfig: oldconfig %+v", oldconfig)
		differ := compareClusterCfgs(ctx, config, oldconfig)
		if !differ {
			log.Noticef("getKubeConfig: no change in cluster config")
			return
		}
		// Remove the old IP address from the cluster interface
		err := kubeIntfIPRemove(ctx, oldconfig)
		if err != nil {
			log.Errorf("runKubeConfig: kubeIntfIPRemove failed: %v", err)
			// XXX: Should we continue with the new config?
		}
		deleteKubeSVCRoute(ctx, oldconfig)
	}
	if config == nil {
		log.Errorf("getKubeConfig: config is nil")
		return
	}
	log.Noticef("runKubeConfig: config %+v, is del %v", config, isDel)
	if isDel {
		// Remove the IP address from the cluster interface
		err := kubeIntfIPRemove(ctx, config)
		if err != nil {
			log.Errorf("getKubeConfig: kubeIntfIPRemove failed: %v", err)
		}
		deleteKubeSVCRoute(ctx, config)
		ctx.quitServer <- struct{}{}
	} else {
		err := kubeIntfIPCheckAdd(ctx, config)
		if err != nil {
			log.Errorf("getKubeConfig: kubeIntfIPCheckAdd failed: %v", err)
			// XXX: Should we continue with the new config?
		} else {
			monitorInterface(ctx, config)
		}
		addKubeSVCRoute(ctx, config)

		var bootstrapNode bool
		ipaddr := config.ClusterIPPrefix.IP
		if ipaddr.Equal(config.JoinServerIP) {
			bootstrapNode = true
		}

		if bootstrapNode {
			if ctx.statusServer == nil {
				mux := http.NewServeMux()
				mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
					statusHandler(w, r, ctx)
				})
				ctx.statusServer = &http.Server{
					Addr:    ipaddr.String() + ":" + types.ClusterStatusPort,
					Handler: mux,
				}
				go handleClusterStatus(ctx)
			}
		}
	}
	publishKubeConfigStatus(ctx, config)
}

// compareClusterCfgs compares the new and old cluster configs, returns true if they are different
func compareClusterCfgs(ctx *zedkubeContext, config, oldconfig *types.EdgeNodeClusterConfig) bool {
	if reflect.DeepEqual(config, oldconfig) {
		return false
	}
	return true
}

// kubeIntfIPRemove removes the IP address from the interface
func kubeIntfIPRemove(ctx *zedkubeContext, config *types.EdgeNodeClusterConfig) error {

	log.Noticef("kubeIntfIPRemove: config %+v", config) // XXX: remove
	// Stop the monitoring
	ctx.stopMonitor <- struct{}{}

	link, err := netlink.LinkByName(config.ClusterInterface)
	if err != nil {
		return err
	}

	// Find the address to remove
	addrs, err := getLinkAllIPs(link)
	if err != nil {
		return err
	}

	oldip := config.ClusterIPPrefix.IP
	if oldip == nil {
		err := fmt.Errorf("Invalid IP address for clusterIP prefix %s", config.ClusterIPPrefix.IP.String())
		return err
	}
	// Find the address matching the IP prefix
	var foundAddr *netlink.Addr
	for _, addr := range addrs {
		if addr.IPNet.IP.Equal(oldip) && addr.IPNet.Mask.String() == config.ClusterIPPrefix.Mask.String() {
			foundAddr = &addr
			break
		}
	}

	if foundAddr == nil {
		err := fmt.Errorf("kubeIntfIPRemove: IP address %s not found on interface %s", oldip.String(), config.ClusterInterface)
		return err
	}

	// Remove the address
	err = netlink.AddrDel(link, foundAddr)
	if err != nil {
		return err
	}
	ctx.encNodeIPAddress = nil

	return nil
}

// kubeIntfIPCheckAdd checks or adds the IP address to the interface
func kubeIntfIPCheckAdd(ctx *zedkubeContext, config *types.EdgeNodeClusterConfig) error {
	link, addr, err := getLinkAndAddr(ctx, config)
	if err != nil {
		log.Errorf("kubeIntfIPCheckAdd: getLinkAndAddr failed: %v", err)
		return err
	}

	// if the link is not up, bring it up
	attrs := link.Attrs()
	if attrs.Flags&net.FlagUp == 0 {
		// Set the IFF_UP flag to bring up the interface
		if err := netlink.LinkSetUp(link); err != nil {
			log.Errorf("kubeIntfIPCheckAdd: bringupInterface, %v", err)
			return err
		}
	}

	// check to see if it is already added
	addrs, err := getLinkAllIPs(link)
	if err != nil {
		log.Errorf("kubeIntfIPCheckAdd: getLinkAllIPs failed: %v", err)
		return err
	}
	for _, a := range addrs {
		if a.IPNet.IP.Equal(addr.IPNet.IP) {
			log.Noticef("kubeIntfIPCheckAdd: IP address %s already exists on interface %s", addr.IPNet.IP.String(), config.ClusterInterface)
			return nil
		}
	}

	// Add the address
	err = netlink.AddrAdd(link, addr)
	if err != nil {
		log.Errorf("kubeIntfIPCheckAdd: AddrAdd failed: %v", err)
		return err
	}
	log.Noticef("kubeIntfIPCheckAdd: Added IP address %s to interface %s", config.ClusterIPPrefix.IP.String(), config.ClusterInterface)

	// XXX check it's added
	addrs, err = getLinkAllIPs(link)
	if err != nil {
		log.Errorf("kubeIntfIPCheckAdd: getLinkAllIPs failed: %v", err)
		return err
	}
	for i, a := range addrs {
		log.Noticef("kubeIntfIPCheckAdd: get IP address(%d) %s on interface %s", i, a.IPNet.IP.String(), config.ClusterInterface)
	}
	return nil
}

func monitorInterface(ctx *zedkubeContext, config *types.EdgeNodeClusterConfig) {
	link, addr, err := getLinkAndAddr(ctx, config)
	if err != nil {
		log.Errorf("monitorInterface: getLinkAndAddr failed: %v", err)
		return
	}
	stopChan2 := make(chan struct{})
	// Create a new updates channel
	updates := make(chan netlink.AddrUpdate)

	go func() {
		for {
			select {
			case update, ok := <-updates:
				if !ok {
					return
				}
				if update.LinkIndex == link.Attrs().Index {
					log.Noticef("monitorInterface: update %+v", update)
					if !update.LinkAddress.IP.Equal(addr.IPNet.IP) {
						// The IP address has changed on the interface, check and may add the cluster ip back
						log.Noticef("monitorInterface: IP address changed from %s to %s", addr.IPNet.IP.String(), update.LinkAddress.String())
						err := kubeIntfIPCheckAdd(ctx, config)
						if err != nil {
							log.Errorf("monitorInterface: kubeIntfIPCheckAdd failed: %v", err)
						}
					}
				}
			case <-ctx.stopMonitor:
				stopChan2 <- struct{}{}
				return
			}
		}
	}()

	// Call AddrSubscribe for link address updates
	netlink.AddrSubscribe(updates, stopChan2)
}

func getLinkAndAddr(ctx *zedkubeContext, config *types.EdgeNodeClusterConfig) (netlink.Link, *netlink.Addr, error) {
	link, err := netlink.LinkByName(config.ClusterInterface)
	if err != nil {
		log.Errorf("getLinkAndAddr: LinkByName failed: %v", err)
		return nil, nil, err
	}

	// Add the address
	addr := &netlink.Addr{IPNet: &config.ClusterIPPrefix, Label: "", Flags: 0}
	return link, addr, nil
}

func getLinkAllIPs(link netlink.Link) ([]netlink.Addr, error) {
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

// publishKubeConfigStatus publishes the cluster config status
func publishKubeConfigStatus(ctx *zedkubeContext, config *types.EdgeNodeClusterConfig) {
	var err error
	var found bool
	link, err := netlink.LinkByName(config.ClusterInterface)
	if err == nil {
		addrs, err := getLinkAllIPs(link)
		if err == nil {
			for _, addr := range addrs {
				if addr.IPNet.IP.Equal(config.ClusterIPPrefix.IP) {
					found = true
					break
				}
			}
		}
	}

	newerr := types.ErrorDescription{}
	if err != nil {
		newerr.Error = err.Error()
		newerr.ErrorTime = time.Now()
	}
	var prefix net.IPNet
	if found {
		prefix = config.ClusterIPPrefix
	}
	status := types.EdgeNodeClusterStatus{
		ClusterName:      config.ClusterName,
		ClusterID:        config.ClusterID,
		ClusterInterface: config.ClusterInterface,
		ClusterIPPrefix:  prefix,
		IsWorkerNode:     config.IsWorkerNode,
		JoinServerIP:     config.JoinServerIP,
		BootstrapNode:    config.BootstrapNode,
		Error:            newerr,
	}

	// XXX temp configitem handling
	if config.EncryptedClusterToken != "" {
		status.EncryptedClusterToken = config.EncryptedClusterToken
		log.Noticef("publishKubeConfigStatus: use clearText token")
	} else if config.CipherToken.IsCipher {
		decToken, err := decryptClusterToken(ctx, config)
		if err != nil {
			log.Errorf("publishKubeConfigStatus: failed to decrypt cluster token: %v", err)
			status.Error = types.ErrorDescription{
				Error:     err.Error(),
				ErrorTime: time.Now(),
			}
		} else {
			status.EncryptedClusterToken = decToken
			log.Noticef("publishKubeConfigStatus: use decrypted token")
		}
	} else {
		log.Errorf("publishKubeConfigStatus: cluster token is not from configitme or encrypted")
	}

	ctx.encNodeIPAddress = &config.ClusterIPPrefix.IP
	log.Noticef("publishKubeConfigStatus: found %v, %+v", found, status)

	// publish the cluster status for the kube container
	ctx.pubEdgeNodeClusterStatus.Publish("global", status)
}

func decryptClusterToken(ctx *zedkubeContext, config *types.EdgeNodeClusterConfig) (string, error) {
	if !config.CipherToken.IsCipher {
		return "", fmt.Errorf("decryptClusterToken: cluster token is not encrypted")
	}

	decryptAvailable := ctx.subControllerCert != nil && ctx.subEdgeNodeCert != nil
	if !decryptAvailable {
		return "", fmt.Errorf("decryptClusterToken: certificates are not available")
	}
	status, decBlock, err := cipher.GetCipherCredentials(
		&cipher.DecryptCipherContext{
			Log:                  log,
			AgentName:            agentName,
			AgentMetrics:         ctx.cipherMetrics,
			PubSubControllerCert: ctx.subControllerCert,
			PubSubEdgeNodeCert:   ctx.subEdgeNodeCert,
		},
		config.CipherToken)
	if ctx.pubCipherBlockStatus != nil {
		err2 := ctx.pubCipherBlockStatus.Publish(status.Key(), status)
		if err2 != nil {
			return "", fmt.Errorf("decryptClusterToken: publish failed %v", err2)
		}
	}
	if err != nil {
		ctx.cipherMetrics.RecordFailure(log, types.DecryptFailed)
		return "", fmt.Errorf("decryptClusterToken: failed to decrypt cluster token: %v", err)
	}

	err = ctx.cipherMetrics.Publish(log, ctx.pubCipherMetrics, "global")
	if err != nil {
		log.Errorf("decryptClusterToken: publish failed for cipher metrics: %v", err)
		return "", fmt.Errorf("decryptClusterToken: failed to publish cipher metrics: %v", err)
	}

	return decBlock.ClusterToken, nil
}

// inject 10.43/16 route in main table towards cluster interface
func addKubeSVCRoute(ctx *zedkubeContext, config *types.EdgeNodeClusterConfig) {
	route, err := getKubeSVCRoute(ctx, config)
	if err != nil {
		log.Errorf("addKubeSVCRoute: getKubeSVCRoute failed: %v", err)
		return
	}

	err = netlink.RouteAdd(route)
	if err != nil {
		log.Errorf("addKubeSVCRoute: RouteAdd failed: %v", err)
	}
	log.Noticef("addKubeSVCRoute: route added %+v", route)
	return
}

func deleteKubeSVCRoute(ctx *zedkubeContext, config *types.EdgeNodeClusterConfig) {

	route, err := getKubeSVCRoute(ctx, config)
	if err != nil {
		log.Errorf("deleteKubeSVCRoute: getKubeSVCRoute failed: %v", err)
		return
	}

	err = netlink.RouteDel(route)
	if err != nil {
		log.Errorf("deleteKubeSVCRoute: RouteDel failed: %v", err)
	}
	return
}

func getKubeSVCRoute(ctx *zedkubeContext, config *types.EdgeNodeClusterConfig) (*netlink.Route, error) {
	link, err := netlink.LinkByName(config.ClusterInterface)
	if err != nil {
		return nil, err
	}

	_, dstNet, err := net.ParseCIDR(kubeSvcPrefix)
	if err != nil {
		return nil, err
	}

	gw := config.ClusterIPPrefix.IP
	route := &netlink.Route{
		Dst:       dstNet,
		Gw:        gw,
		LinkIndex: link.Attrs().Index,
	}
	return route, nil
}

func checkKubeSVCRouteExist(ctx *zedkubeContext, config *types.EdgeNodeClusterConfig) (bool, error) {
	route, err := getKubeSVCRoute(ctx, config)
	if err != nil {
		log.Errorf("checkKubeSVCRouteExist: getKubeSVCRoute failed: %v", err)
		return false, err
	}

	link, err := netlink.LinkByName(config.ClusterInterface)
	if err != nil {
		return false, err
	}

	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		log.Errorf("checkKubeSVCRouteExist: RouteList failed: %v", err)
		return false, err
	}

	for _, r := range routes {
		if r.Dst != nil && r.Dst.IP.Equal(route.Dst.IP) && r.Gw.Equal(route.Gw) {
			return true, nil
		}
	}
	return false, nil
}

// XXX temp solution to inject 10.43/16 route towards cluster interface
// regardless if the default route exist for the cluster interface
// this functionality needs to be moved to zedrouter
func checkSVCRoute(ctx *zedkubeContext) {
	sub := ctx.subEdgeNodeClusterConfig
	items := sub.GetAll()

	var config *types.EdgeNodeClusterConfig
	for _, item := range items {
		c := item.(types.EdgeNodeClusterConfig)
		config = &c
		break
	}

	if config == nil {
		return
	}
	exist, err := checkKubeSVCRouteExist(ctx, config)
	if err != nil {
		log.Errorf("checkSVCROutes: checkKubeSVCRouteExist failed: %v", err)
		return
	}

	if !exist {
		log.Noticef("checkSVCROutes: route does not exist addKubeSVCRoute")
		addKubeSVCRoute(ctx, config)
	}
}

func handleClusterStatus(ctx *zedkubeContext) {

	server := ctx.statusServer
	go func() {
		select {
		case <-ctx.quitServer:
			context, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := server.Shutdown(context); err != nil {
				log.Errorf("handleClusterStatus: server shutdown failed: %v", err)
			}
		}
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Errorf("handleClusterStatus: server ListenAndServe failed: %v", err)
	}
}

func statusHandler(w http.ResponseWriter, r *http.Request, ctx *zedkubeContext) {
	if ctx.config == nil {
		config, err := kubeapi.GetKubeConfig()
		if err != nil {
			fmt.Fprint(w, "")
			log.Errorf("statusHandler: can't get kubeconfig %v", err)
			return
		}
		ctx.config = config
	}

	clientset, err := kubernetes.NewForConfig(ctx.config)
	if err != nil {
		log.Errorf("collectAppLogs: can't get clientset %v", err)
		fmt.Fprint(w, "")
		return
	}
	labelSelector := metav1.LabelSelector{MatchLabels: map[string]string{"node-uuid": ctx.nodeuuid}}
	options := metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&labelSelector)}
	nodes, err := clientset.CoreV1().Nodes().List(context.Background(), options)
	if err != nil {
		log.Errorf("statusHandler: can't get nodes %v", err)
		return
	}

	var isMaster, isEtcd bool
	if len(nodes.Items) == 0 {
		fmt.Fprint(w, "")
		return
	}
	node := nodes.Items[0]
	labels := node.GetLabels()
	if _, ok := labels["node-role.kubernetes.io/master"]; ok {
		log.Noticef("statusHandler: master")
		isMaster = true
	}
	if _, ok := labels["node-role.kubernetes.io/etcd"]; ok {
		log.Noticef("statusHandler: etcd")
		isEtcd = true
	}

	if isMaster && isEtcd {
		log.Noticef("statusHandler: master and etcd")
		fmt.Fprint(w, "clsuter")
		return
	}
	log.Noticef("statusHandler: not master or etcd")
	fmt.Fprint(w, "")
}
