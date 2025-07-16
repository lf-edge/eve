// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package lpsapi

import (
	"fmt"
	"io"
	"log"
	"net/http"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve-api/go/profile"
	"google.golang.org/protobuf/proto"

	"github.com/lf-edge/eve/evetest/testapps/lps/internal/state"
)

const protoBinaryMime = "application/x-proto-binary"

// Handler implements the LPS protocol endpoints under /api/v1/.
type Handler struct {
	state *state.State
}

// New creates a new LPS API handler.
func New(s *state.State) *Handler {
	return &Handler{state: s}
}

// Register registers all LPS API routes on the given mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/local_profile", h.localProfile)
	mux.HandleFunc("POST /api/v1/radio", h.radio)
	mux.HandleFunc("POST /api/v1/appinfo", h.appinfo)
	mux.HandleFunc("POST /api/v1/devinfo", h.devinfo)
	mux.HandleFunc("POST /api/v1/location", h.location)
	mux.HandleFunc("POST /api/v1/network", h.network)
	mux.HandleFunc("POST /api/v1/appbootinfo", h.appbootinfo)
	mux.HandleFunc("GET /api/v1/signal", h.signal)
}

func (h *Handler) localProfile(w http.ResponseWriter, r *http.Request) {
	cfg := h.state.GetConfig()
	resp := &profile.LocalProfile{
		LocalProfile: cfg.Profile,
		ServerToken:  cfg.ServerToken,
	}
	writeProto(w, resp)
	h.state.Broker().ConsumePending(
		profile.ConfigEndpoint_CONFIG_ENDPOINT_LOCAL_PROFILE)
}

func (h *Handler) radio(w http.ResponseWriter, r *http.Request) {
	var status profile.RadioStatus
	if err := readProto(r, &status); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.state.SetRadioStatus(&status)
	log.Printf("Received radio status: radioSilence=%v", status.RadioSilence)

	cfg := h.state.GetConfig()
	resp := &profile.RadioConfig{
		ServerToken:  cfg.ServerToken,
		RadioSilence: cfg.RadioSilence,
	}
	writeProto(w, resp)
	h.state.Broker().ConsumePending(
		profile.ConfigEndpoint_CONFIG_ENDPOINT_RADIO)
}

func (h *Handler) appinfo(w http.ResponseWriter, r *http.Request) {
	var appInfoList profile.LocalAppInfoList
	if err := readProto(r, &appInfoList); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.state.SetAppInfoList(&appInfoList)
	log.Printf("Received app info: %d apps", len(appInfoList.AppsInfo))

	cfg := h.state.GetConfig()
	defer h.state.Broker().ConsumePending(
		profile.ConfigEndpoint_CONFIG_ENDPOINT_APP_INFO)
	if len(cfg.AppCommands) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	resp := &profile.LocalAppCmdList{
		ServerToken: cfg.ServerToken,
		AppCommands: cfg.AppCommands,
	}
	writeProto(w, resp)
}

func (h *Handler) devinfo(w http.ResponseWriter, r *http.Request) {
	var devInfo profile.LocalDevInfo
	if err := readProto(r, &devInfo); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.state.SetDevInfo(&devInfo)
	log.Printf("Received dev info: uuid=%s state=%s", devInfo.DeviceUuid, devInfo.State)

	cfg := h.state.GetConfig()
	defer h.state.Broker().ConsumePending(
		profile.ConfigEndpoint_CONFIG_ENDPOINT_DEV_INFO)
	if cfg.DevCommand == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	cmdEnum, ok := profile.LocalDevCmd_Command_value[cfg.DevCommand.Command]
	if !ok {
		log.Printf("Unknown device command: %s", cfg.DevCommand.Command)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	resp := &profile.LocalDevCmd{
		ServerToken: cfg.ServerToken,
		Timestamp:   cfg.DevCommand.Timestamp,
		Command:     profile.LocalDevCmd_Command(cmdEnum),
	}
	writeProto(w, resp)
}

func (h *Handler) location(w http.ResponseWriter, r *http.Request) {
	var loc eveinfo.ZInfoLocation
	if err := readProto(r, &loc); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.state.SetLocation(&loc)
	log.Printf("Received location: lat=%f lon=%f", loc.Latitude, loc.Longitude)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) network(w http.ResponseWriter, r *http.Request) {
	var netInfo profile.NetworkInfo
	if err := readProto(r, &netInfo); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.state.SetNetworkInfo(&netInfo)
	log.Printf("Received network info: %d ports in latest config",
		len(netInfo.LatestConfig))

	cfg := h.state.GetConfig()
	defer h.state.Broker().ConsumePending(
		profile.ConfigEndpoint_CONFIG_ENDPOINT_NETWORK)
	if cfg.LocalNetworkConfig == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	resp := cfg.LocalNetworkConfig
	resp.ServerToken = cfg.ServerToken
	writeProto(w, resp)
}

func (h *Handler) appbootinfo(w http.ResponseWriter, r *http.Request) {
	var bootInfo profile.AppBootInfoList
	if err := readProto(r, &bootInfo); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.state.SetAppBootInfo(&bootInfo)
	log.Printf("Received app boot info: %d apps", len(bootInfo.AppsBootInfo))

	cfg := h.state.GetConfig()
	defer h.state.Broker().ConsumePending(
		profile.ConfigEndpoint_CONFIG_ENDPOINT_APP_BOOT_INFO)
	if len(cfg.AppBootConfigs) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	resp := &profile.AppBootConfigList{
		ServerToken: cfg.ServerToken,
		AppConfigs:  cfg.AppBootConfigs,
	}
	writeProto(w, resp)
}

func readProto(r *http.Request, msg proto.Message) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("reading body: %w", err)
	}
	if err := proto.Unmarshal(body, msg); err != nil {
		return fmt.Errorf("unmarshaling proto: %w", err)
	}
	return nil
}

func writeProto(w http.ResponseWriter, msg proto.Message) {
	data, err := proto.Marshal(msg)
	if err != nil {
		http.Error(w, fmt.Sprintf("marshaling proto: %v", err),
			http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", protoBinaryMime)
	w.Write(data)
}
