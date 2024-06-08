// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package zedkube

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func serverHandler(w http.ResponseWriter, r *http.Request, ctx *zedkubeContext) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body",
			http.StatusInternalServerError)
		return
	}
	log.Noticef("  Client UUID: %s, Type Number: %s, Type Name: %s, Type Key: %s, Agent Name: %s, Op Type: %s\n",
		r.Header.Get("Client-UUID"), r.Header.Get("Type-Number"), r.Header.Get("Type-Name"),
		r.Header.Get("Type-Key"), r.Header.Get("Agent-Name"), r.Header.Get("Op-Type"))

	typeNumberStr := r.Header.Get("Type-Number")
	typeNumber, err := strconv.Atoi(typeNumberStr)
	if err != nil {
		log.Errorf("Error converting Type-Number to integer")
		http.Error(w, "Error converting Type-Number to integer",
			http.StatusInternalServerError)
		return
	}
	encPubConfigType := types.EncPubConfigType(typeNumber)

	opTypeNum, err := strconv.Atoi(r.Header.Get("Op-Type"))
	if err != nil {
		log.Errorf("Error converting Op-Type to integer")
		http.Error(w, "Error converting Op-Type to integer",
			http.StatusInternalServerError)
		return
	}
	opType := types.EncPubOpType(opTypeNum)
	key := r.Header.Get("Type-Key")

	header := types.EncPubHeader{
		SenderUUID: uuid.FromStringOrNil(r.Header.Get("Client-UUID")),
		TypeNumber: encPubConfigType,
		TypeName:   r.Header.Get("Type-Name"),
		TypeKey:    key,
		AgentName:  r.Header.Get("Agent-Name"),
		OpType:     opType,
	}

	handleEncPubToRemoteData(ctx, &header, body)
}

func startupHandler(w http.ResponseWriter, r *http.Request, ctx *zedkubeContext) {
	sender := r.Header.Get("Client-UUID")
	log.Noticef("startupHandler: from %s, resend", sender)
	ctx.pubResendTimer = time.NewTimer(60 * time.Second)
}

// just start up and notify all the peer nodes, to resend any subs we missed
func startupNotifyPeers(ctx *zedkubeContext) {
	log.Noticef("startupNotifyPeers")
	log.Errorf("startupNotifyPeers: temp") // XXX
	hosts, err := getClusterNodes(ctx)
	if err != nil {
		log.Errorf("startupNotifyPeers, Error getting cluster nodes")
		return
	}

	// notify all the peers we are up
	for _, host := range hosts {
		req, err := http.NewRequest("POST", "http://"+host+":"+types.ClusterPubPort+"/startup", nil)
		if err != nil {
			log.Errorf("startupNotifyPeers: %v", err)
			break
		}

		req.Header.Set("Client-UUID", ctx.nodeuuid)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Errorf("startupNotifyPeers: %v", err)
			break
		}
		log.Noticef("startupNotifyPeers: host %s, response status: %s, %v", host, resp.Status, err)
		resp.Body.Close()
	}
}

func handleEncPubToRemoteData(ctx *zedkubeContext, header *types.EncPubHeader, body []byte) {
	toRemoteData := types.EncPubToRemoteData{
		Header:    *header,
		AgentData: body,
	}
	if header.OpType == types.EncPubOpDelete {
		log.Noticef("handleEncPubToRemoteData: delete key %s", header.TypeKey)
		ctx.pubEncPubToRemoteData.Unpublish(header.TypeKey)
		ctx.receiveMap.Delete(header.TypeKey)
	} else {
		log.Noticef("handleEncPubToRemoteData: header %+v, data len %d", header, len(body))
		ctx.pubEncPubToRemoteData.Publish(header.TypeKey, toRemoteData)
		ctx.receiveMap.Insert(header.TypeKey)
	}
}

func getClusterNodes(ctx *zedkubeContext) ([]string, error) {
	myNodeIP := ctx.encNodeIPAddress
	if myNodeIP == nil {
		log.Errorf("getClusterNodes: encNodeIPAddress is nil")
		return nil, fmt.Errorf("encNodeIPAddress is nil")
	}

	if ctx.config == nil {
		config, err := kubeapi.GetKubeConfig()
		if err != nil {
			log.Errorf("getClusterNodes: config is nil")
			return nil, err
		}
		ctx.config = config
	}

	clientset, err := kubernetes.NewForConfig(ctx.config)
	if err != nil {
		log.Errorf("collectAppLogs: can't get clientset %v", err)
		return nil, err
	}

	nodes, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("Error getting cluster nodes")
		return nil, err
	}

	// get all the nodes internal ip addresses except for my own
	var hosts []string
	for _, node := range nodes.Items {
		for _, addr := range node.Status.Addresses {
			if addr.Type == corev1.NodeInternalIP && addr.Address != myNodeIP.String() {
				hosts = append(hosts, addr.Address)
			}
		}
	}
	return hosts, nil
}

func sendPubToRemoteNodes(ctx *zedkubeContext, header types.EncPubHeader, body []byte) {

	found := ctx.receiveMap.Find(header.TypeKey)
	if found {
		log.Noticef("sendPubToRemoteNodes: received pub %v, skip", header)
		return
	}

	sentOk := true
	hosts, err := getClusterNodes(ctx)
	if err != nil {
		log.Errorf("Error getting cluster nodes")
		ctx.pubResendTimer = time.NewTimer(60 * time.Second)
		return
	}

	if len(hosts) != 2 {
		sentOk = false
		log.Noticef("sendPubToRemoteNodes: only %d nodes in the cluster", len(hosts))
	}

	// relay the pub to remote nodes
	for _, host := range hosts {
		req, err := http.NewRequest("POST", "http://"+host+":"+types.ClusterPubPort, bytes.NewBuffer(body))
		if err != nil {
			log.Errorf("sendPubToRemoteNodes: %v", err)
			sentOk = false
			break
		}

		req.Header.Set("Client-UUID", header.SenderUUID.String())
		req.Header.Set("Type-Number", strconv.Itoa(int(header.TypeNumber)))
		req.Header.Set("Type-Name", header.TypeName)
		req.Header.Set("Type-Key", header.TypeKey)
		req.Header.Set("Agent-Name", header.AgentName)
		req.Header.Set("Op-Type", strconv.Itoa(int(header.OpType)))

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Errorf("sendPubToRemoteNodes: %v", err)
			sentOk = false
			break
		}
		log.Noticef("sendPubToRemoteNodes: host %s, response status: %s, %v", host, resp.Status, err)
		resp.Body.Close()
	}
	if !sentOk {
		log.Noticef("sendPubToRemoteNodes: not ok, schedule retry")
		ctx.pubResendTimer = time.NewTimer(60 * time.Second)
	}
}

// received from zedagent NetworkInstanceConfig, pub to remote nodes
func sendAndPubEncNetInstConfig(ctx *zedkubeContext, config *types.NetworkInstanceConfig, key string, op types.EncPubOpType) {

	// skipt the default network instance from zedagent
	if config != nil && strings.HasPrefix(config.DisplayName, "default") {
		log.Noticef("sendAndPubEncNetInstConfig: skip kube- network instance")
		return
	}

	buf, nodeuuid, err := getGobAndUUID(ctx, config)
	if err != nil {
		log.Errorf("sendAndPubEncNetInstConfig: %v", err)
		return
	}
	header := types.EncPubHeader{
		SenderUUID: nodeuuid,
		TypeNumber: types.EncNetInstConfig,
		TypeName:   "NetworkInstanceConfig",
		TypeKey:    key,
		AgentName:  "zedagent",
		OpType:     op,
	}
	sendPubToRemoteNodes(ctx, header, buf.Bytes())
}

func getGobAndUUID(ctx *zedkubeContext, config interface{}) (bytes.Buffer, uuid.UUID, error) {
	// encode the config with gob
	var buf bytes.Buffer
	if config != nil {
		enc := gob.NewEncoder(&buf)
		if !reflect.ValueOf(config).IsNil() {
			log.Errorf("getGobAndUUID: config is nil, skip gob encoding") // XXX
			err := enc.Encode(config)
			if err != nil {
				return buf, uuid.Nil, err
			}
		}
	}

	nodeuuid, err := uuid.FromString(ctx.nodeuuid)
	if err != nil {
		return buf, nodeuuid, err
	}
	return buf, nodeuuid, nil
}

func resendPubsToRemoteNodes(ctx *zedkubeContext) {
	log.Noticef("resendPubsToRemoteNodes: retrying")
	resendPubNetInstConfigs(ctx)
	resendPubAppInstConfigs(ctx)
	resendPubVolumeConfigs(ctx)
	resendPubDatastoreConfigs(ctx)
	resendPubContentTreeConfigs(ctx)
}

func resendPubNetInstConfigs(ctx *zedkubeContext) {
	sub := ctx.subNetworkInstanceConfig
	items := sub.GetAll()
	nodeuuid, err := uuid.FromString(ctx.nodeuuid)
	if err != nil {
		log.Errorf("sendAndPubEncNetInstConfig: %v", err)
		return
	}
	header := types.EncPubHeader{
		SenderUUID: nodeuuid,
		TypeNumber: types.EncNetInstConfig,
		TypeName:   "NetworkInstanceConfig",
		AgentName:  "zedagent",
		OpType:     types.EncPubOpModify,
	}
	for key, item := range items {
		config := item.(types.NetworkInstanceConfig)
		if strings.HasPrefix(config.DisplayName, "default") {
			continue
		}
		log.Noticef("resendPubNetInstConfigs: (UUID: %s, config:%v)", key, config)
		var buf bytes.Buffer
		enc := gob.NewEncoder(&buf)
		err := enc.Encode(config)
		if err != nil {
			log.Errorf("sendAndPubEncNetInstConfig: %v", err)
			return
		}
		header.TypeKey = key
		sendPubToRemoteNodes(ctx, header, buf.Bytes())
	}
}

// resendPubsToRemoteNodes resend all the AppInstanceConfig to remote nodes
func resendPubAppInstConfigs(ctx *zedkubeContext) {
	sub := ctx.subAppInstanceConfig
	items := sub.GetAll()
	nodeuuid, err := uuid.FromString(ctx.nodeuuid)
	if err != nil {
		log.Errorf("sendAndPubEncAppInstConfig: %v", err)
		return
	}
	header := types.EncPubHeader{
		SenderUUID: nodeuuid,
		TypeNumber: types.EncAppInstConfig,
		TypeName:   "AppInstanceConfig",
		AgentName:  "zedagent",
		OpType:     types.EncPubOpModify,
	}
	for key, item := range items {
		config := item.(types.AppInstanceConfig)
		log.Noticef("resendPubAppInstConfigs: (UUID: %s, config:%v)", key, config)
		var buf bytes.Buffer
		enc := gob.NewEncoder(&buf)
		err := enc.Encode(config)
		if err != nil {
			log.Errorf("sendAndPubEncAppInstConfig: %v", err)
			return
		}
		header.TypeKey = key
		sendPubToRemoteNodes(ctx, header, buf.Bytes())
	}
}

func resendPubVolumeConfigs(ctx *zedkubeContext) {
	sub := ctx.subVolumeConfig
	items := sub.GetAll()
	nodeuuid, err := uuid.FromString(ctx.nodeuuid)
	if err != nil {
		log.Errorf("sendAndPubEncVolumeConfig: %v", err)
		return
	}
	header := types.EncPubHeader{
		SenderUUID: nodeuuid,
		TypeNumber: types.EncVolumeConfig,
		TypeName:   "VolumeConfig",
		AgentName:  "zedagent",
		OpType:     types.EncPubOpModify,
	}
	for key, item := range items {
		config := item.(types.VolumeConfig)
		if config.DesignatedNodeID == uuid.Nil {
			log.Noticef("resendPubVolumeConfigs: skip volume with nil DesignatedNodeID")
			continue
		}
		log.Noticef("resendPubVolumeConfigs: (UUID: %s, config:%v)", key, config)
		var buf bytes.Buffer
		enc := gob.NewEncoder(&buf)
		err := enc.Encode(config)
		if err != nil {
			log.Errorf("sendAndPubEncVolumeConfig: %v", err)
			return
		}
		header.TypeKey = key
		sendPubToRemoteNodes(ctx, header, buf.Bytes())
	}
}

func resendPubDatastoreConfigs(ctx *zedkubeContext) {
	sub := ctx.subDatastoreConfig
	items := sub.GetAll()
	nodeuuid, err := uuid.FromString(ctx.nodeuuid)
	if err != nil {
		log.Errorf("sendAndPubEncDataStoreConfig: %v", err)
		return
	}
	header := types.EncPubHeader{
		SenderUUID: nodeuuid,
		TypeNumber: types.EncDataStoreConfig,
		TypeName:   "DataStoreConfig",
		AgentName:  "zedagent",
		OpType:     types.EncPubOpModify,
	}
	for key, item := range items {
		config := item.(types.DatastoreConfig)
		if checkDataStoreCloudImage(&config) {
			log.Noticef("resendPubDatastoreConfigs: skip cloud image datastore")
			continue
		}
		log.Noticef("resendPubDatastoreConfigs: (UUID: %s, config:%v)", key, config)
		var buf bytes.Buffer
		enc := gob.NewEncoder(&buf)
		err := enc.Encode(config)
		if err != nil {
			log.Errorf("sendAndPubEncDataStoreConfig: %v", err)
			return
		}
		header.TypeKey = key
		sendPubToRemoteNodes(ctx, header, buf.Bytes())
	}
}

func resendPubContentTreeConfigs(ctx *zedkubeContext) {
	sub := ctx.subContentTreeConfig
	items := sub.GetAll()
	nodeuuid, err := uuid.FromString(ctx.nodeuuid)
	if err != nil {
		log.Errorf("sendAndPubEncContentTreeConfig: %v", err)
		return
	}
	header := types.EncPubHeader{
		SenderUUID: nodeuuid,
		TypeNumber: types.EncContentTreeConfig,
		TypeName:   "ContentTreeConfig",
		AgentName:  "zedagent",
		OpType:     types.EncPubOpModify,
	}
	for key, item := range items {
		config := item.(types.ContentTreeConfig)
		if config.DesignatedNodeID == uuid.Nil {
			log.Noticef("resendPubContentTreeConfigs: skip content tree with nil DesignatedNodeID")
			continue
		}
		log.Noticef("resendPubContentTreeConfigs: (UUID: %s, config:%v)", key, config)
		var buf bytes.Buffer
		enc := gob.NewEncoder(&buf)
		err := enc.Encode(config)
		if err != nil {
			log.Errorf("sendAndPubEncContentTreeConfig: %v", err)
			return
		}
		header.TypeKey = key
		sendPubToRemoteNodes(ctx, header, buf.Bytes())
	}
}

func runClusterPubSubServer(ctx *zedkubeContext) {
	// XXX hold until the gcp allowClusterPubSub configitem
	ctx.clusterPubSubStarted = true
	log.Noticef("runClusterPubSubServer: start, clusterPubSubStarted set")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		serverHandler(w, r, ctx)
	})

	http.HandleFunc("/startup", func(w http.ResponseWriter, r *http.Request) {
		startupHandler(w, r, ctx)
	})

	http.ListenAndServe("0.0.0.0:"+types.ClusterPubPort, nil)
}

func handleNetworkInstanceCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*zedkubeContext)
	config := configArg.(types.NetworkInstanceConfig)
	log.Noticef("handleNetworkInstanceCreate: (UUID: %s, name:%s)", key, config.DisplayName)
	sendAndPubEncNetInstConfig(ctx, &config, key, types.EncPubOpCreate)
}

func handleNetworkInstanceModify(ctxArg interface{}, key string,
	configArg interface{},
	oldConfigArg interface{}) {

	ctx := ctxArg.(*zedkubeContext)
	config := configArg.(types.NetworkInstanceConfig)
	log.Noticef("handleNetworkInstanceModify: (UUID: %s, name:%s)", key, config.DisplayName)
	sendAndPubEncNetInstConfig(ctx, &config, key, types.EncPubOpModify)
}

func handleNetworkInstanceDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*zedkubeContext)
	log.Noticef("handleNetworkInstanceDelete(%s)", key)
	sendAndPubEncNetInstConfig(ctx, nil, key, types.EncPubOpDelete)
}

// sendAndPubEncAppInstConfig send AppInstanceConfig to remote nodes
func sendAndPubEncAppInstConfig(ctx *zedkubeContext, config *types.AppInstanceConfig, key string, op types.EncPubOpType) {

	buf, nodeuuid, err := getGobAndUUID(ctx, config)
	if err != nil {
		log.Errorf("sendAndPubEncAppInstConfig: %v", err)
		return
	}
	header := types.EncPubHeader{
		SenderUUID: nodeuuid,
		TypeNumber: types.EncAppInstConfig,
		TypeName:   "AppInstanceConfig",
		TypeKey:    key,
		AgentName:  "zedagent",
		OpType:     op,
	}
	log.Noticef("sendAndPubEncAppInstConfig: header %+v, data len %d", header, len(buf.Bytes()))
	sendPubToRemoteNodes(ctx, header, buf.Bytes())
}

func handleVolumeCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Noticef("handleVolumeCreate(%s)", key)
	config := configArg.(types.VolumeConfig)
	ctx := ctxArg.(*zedkubeContext)
	sendAndPubEncVolumeConfig(ctx, &config, key, types.EncPubOpCreate)
}

func handleVolumeModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {

	log.Noticef("handleVolumeModify(%s)", key)
	config := configArg.(types.VolumeConfig)
	ctx := ctxArg.(*zedkubeContext)
	sendAndPubEncVolumeConfig(ctx, &config, key, types.EncPubOpModify)
}

func handleVolumeDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Noticef("handleVolumeDelete(%s)", key)
	config := configArg.(types.VolumeConfig)
	ctx := ctxArg.(*zedkubeContext)
	sendAndPubEncVolumeConfig(ctx, &config, key, types.EncPubOpDelete)
}

func sendAndPubEncVolumeConfig(ctx *zedkubeContext, config *types.VolumeConfig, key string, op types.EncPubOpType) {
	if config != nil && config.DesignatedNodeID == uuid.Nil {
		log.Noticef("sendAndPubEncVolumeConfig: skip volume with nil DesignatedNodeID")
		return
	}
	if op == types.EncPubOpDelete { // reset the config to nil
		config = nil
	}

	buf, nodeuuid, err := getGobAndUUID(ctx, config)
	if err != nil {
		log.Errorf("sendAndPubEncVolumeConfig: %v", err)
		return
	}
	header := types.EncPubHeader{
		SenderUUID: nodeuuid,
		TypeNumber: types.EncVolumeConfig,
		TypeName:   "VolumeConfig",
		AgentName:  "zedagent",
		TypeKey:    key,
		OpType:     types.EncPubOpModify,
	}
	sendPubToRemoteNodes(ctx, header, buf.Bytes())
}

func handleDatastoreConfigCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	handleDatastoreConfigImpl(ctxArg, key, configArg, types.EncPubOpCreate)
}

func handleDatastoreConfigModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	handleDatastoreConfigImpl(ctxArg, key, configArg, types.EncPubOpModify)
}

func handleDatastoreConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {
	handleDatastoreConfigImpl(ctxArg, key, configArg, types.EncPubOpDelete)
}

func handleDatastoreConfigImpl(ctxArg interface{}, key string,
	configArg interface{}, op types.EncPubOpType) {

	ctx := ctxArg.(*zedkubeContext)
	config := configArg.(types.DatastoreConfig)
	log.Noticef("handleDatastoreConfigImpl for %s", key)
	if op == types.EncPubOpDelete {
		sendAndPubEncDataStoreConfig(ctx, nil, key, op)
	} else {
		sendAndPubEncDataStoreConfig(ctx, &config, key, op)
	}
}

func sendAndPubEncDataStoreConfig(ctx *zedkubeContext, config *types.DatastoreConfig, key string, op types.EncPubOpType) {
	buf, nodeuuid, err := getGobAndUUID(ctx, config)
	if err != nil {
		log.Errorf("sendAndPubEncDataStoreConfig: %v", err)
		return
	}
	header := types.EncPubHeader{
		SenderUUID: nodeuuid,
		TypeNumber: types.EncDataStoreConfig,
		TypeName:   "DataStoreConfig",
		TypeKey:    key,
		AgentName:  "zedagent",
		OpType:     types.EncPubOpModify,
	}
	if checkDataStoreCloudImage(config) {
		log.Noticef("sendAndPubEncDataStoreConfig: skip cloud image datastore")
		return
	}
	log.Noticef("sendAndPubEncDataStoreConfig: header %+v, op %v", header, op)
	sendPubToRemoteNodes(ctx, header, buf.Bytes())
}

// checkDataStoreCloudImage check if the datastore is for default dev images
func checkDataStoreCloudImage(config *types.DatastoreConfig) bool {
	if config != nil && strings.HasPrefix(config.Dpath, "zededa-zedcloud") &&
		strings.HasSuffix(config.Dpath, "images") {
		return true
	}
	return false
}

func handleContentTreeCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Noticef("handleContentTreeCreate(%s)", key)
	config := configArg.(types.ContentTreeConfig)
	ctx := ctxArg.(*zedkubeContext)
	sendAndPubEncContentTreeConfig(ctx, &config, key, types.EncPubOpCreate)
}

func handleContentTreeModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {

	log.Noticef("handleContentTreeModify(%s)", key)
	config := configArg.(types.ContentTreeConfig)
	ctx := ctxArg.(*zedkubeContext)
	sendAndPubEncContentTreeConfig(ctx, &config, key, types.EncPubOpModify)
}

func handleContentTreeDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Noticef("handleContentTreeDelete(%s)", key)
	ctx := ctxArg.(*zedkubeContext)
	config := configArg.(types.ContentTreeConfig)
	sendAndPubEncContentTreeConfig(ctx, &config, key, types.EncPubOpDelete)
}

func sendAndPubEncContentTreeConfig(ctx *zedkubeContext, config *types.ContentTreeConfig, key string, op types.EncPubOpType) {
	if config != nil && config.DesignatedNodeID == uuid.Nil {
		log.Noticef("sendAndPubEncContentTreeConfig: skip volume with nil DesignatedNodeID")
		return
	}
	if op == types.EncPubOpDelete { // reset the config to nil
		config = nil
	}

	buf, nodeuuid, err := getGobAndUUID(ctx, config)
	if err != nil {
		log.Errorf("sendAndPubEncContentTreeConfig: %v", err)
		return
	}
	header := types.EncPubHeader{
		SenderUUID: nodeuuid,
		TypeNumber: types.EncContentTreeConfig,
		TypeName:   "ContentTreeConfig",
		TypeKey:    key,
		AgentName:  "zedagent",
		OpType:     types.EncPubOpModify,
	}
	log.Noticef("sendAndPubEncContentTreeConfig: header %+v, op %v", header, op)
	sendPubToRemoteNodes(ctx, header, buf.Bytes())
}
