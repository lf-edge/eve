// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package manage

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/lf-edge/eve-api/go/profile"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/lf-edge/eve/evetest/testapps/lps/internal/state"
)

// Handler implements the management REST API under /manage/v1/.
type Handler struct {
	state *state.State
}

// New creates a new management API handler.
func New(s *state.State) *Handler {
	return &Handler{state: s}
}

// Register registers all management API routes on the given mux.
func (h *Handler) Register(mux *http.ServeMux) {
	// Push state to the UI as soon as it changes.
	mux.HandleFunc("GET /manage/v1/events", h.events)
	// Read state (polled — kept for tooling; UI uses /events).
	mux.HandleFunc("GET /manage/v1/status", h.getStatus)
	mux.HandleFunc("GET /manage/v1/config", h.getConfig)
	mux.HandleFunc("GET /manage/v1/radio-status", h.getRadioStatus)
	mux.HandleFunc("GET /manage/v1/appinfo", h.getAppInfo)
	mux.HandleFunc("GET /manage/v1/devinfo", h.getDevInfo)
	mux.HandleFunc("GET /manage/v1/location", h.getLocation)
	mux.HandleFunc("GET /manage/v1/network", h.getNetworkInfo)
	mux.HandleFunc("GET /manage/v1/appbootinfo", h.getAppBootInfo)
	// Set config
	mux.HandleFunc("PUT /manage/v1/token", h.setToken)
	mux.HandleFunc("PUT /manage/v1/profile", h.setProfile)
	mux.HandleFunc("PUT /manage/v1/radio-config", h.setRadioConfig)
	mux.HandleFunc("PUT /manage/v1/app-command", h.setAppCommands)
	mux.HandleFunc("PUT /manage/v1/dev-command", h.setDevCommand)
	mux.HandleFunc("PUT /manage/v1/app-boot-config", h.setAppBootConfigs)
	mux.HandleFunc("PUT /manage/v1/network-config", h.setNetworkConfig)
}

func (h *Handler) getStatus(w http.ResponseWriter, r *http.Request) {
	cfg, recv := h.state.GetAll()
	writeJSON(w, map[string]any{"config": cfg, "received": recv})
}

func (h *Handler) getConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, h.state.GetConfig())
}

func (h *Handler) getRadioStatus(w http.ResponseWriter, r *http.Request) {
	recv := h.state.GetReceived()
	if recv.RadioStatus == nil {
		http.Error(w, "no radio status received yet", http.StatusNotFound)
		return
	}
	writeProtoJSON(w, recv.RadioStatus)
}

func (h *Handler) getAppInfo(w http.ResponseWriter, r *http.Request) {
	recv := h.state.GetReceived()
	if recv.AppInfoList == nil {
		http.Error(w, "no app info received yet", http.StatusNotFound)
		return
	}
	writeProtoJSON(w, recv.AppInfoList)
}

func (h *Handler) getDevInfo(w http.ResponseWriter, r *http.Request) {
	recv := h.state.GetReceived()
	if recv.DevInfo == nil {
		http.Error(w, "no dev info received yet", http.StatusNotFound)
		return
	}
	writeProtoJSON(w, recv.DevInfo)
}

func (h *Handler) getLocation(w http.ResponseWriter, r *http.Request) {
	recv := h.state.GetReceived()
	if recv.Location == nil {
		http.Error(w, "no location received yet", http.StatusNotFound)
		return
	}
	writeProtoJSON(w, recv.Location)
}

func (h *Handler) getNetworkInfo(w http.ResponseWriter, r *http.Request) {
	recv := h.state.GetReceived()
	if recv.NetworkInfo == nil {
		http.Error(w, "no network info received yet", http.StatusNotFound)
		return
	}
	writeProtoJSON(w, recv.NetworkInfo)
}

func (h *Handler) getAppBootInfo(w http.ResponseWriter, r *http.Request) {
	recv := h.state.GetReceived()
	if recv.AppBootInfo == nil {
		http.Error(w, "no app boot info received yet", http.StatusNotFound)
		return
	}
	writeProtoJSON(w, recv.AppBootInfo)
}

func (h *Handler) setToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.state.SetServerToken(req.Token)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) setProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Profile string `json:"profile"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.state.SetProfile(req.Profile)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) setRadioConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RadioSilence bool `json:"radioSilence"`
	}
	if err := readJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.state.SetRadioSilence(req.RadioSilence)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) setAppCommands(w http.ResponseWriter, r *http.Request) {
	var cmds []*profile.AppCommand
	if err := readProtoJSON(r, &cmds); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.state.SetAppCommands(cmds)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) setDevCommand(w http.ResponseWriter, r *http.Request) {
	var cmd state.DevCmdConfig
	if err := readJSON(r, &cmd); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.state.SetDevCommand(&cmd)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) setAppBootConfigs(w http.ResponseWriter, r *http.Request) {
	var configs []*profile.AppBootConfig
	if err := readProtoJSON(r, &configs); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.state.SetAppBootConfigs(configs)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) setNetworkConfig(w http.ResponseWriter, r *http.Request) {
	var cfg profile.LocalNetworkConfig
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := protojson.Unmarshal(body, &cfg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.state.SetLocalNetworkConfig(&cfg)
	w.WriteHeader(http.StatusOK)
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// readProtoJSON reads a JSON array of protobuf messages.
// Since protojson doesn't support slices directly, we use raw JSON
// decoding then protojson for each element.
func readProtoJSON[T interface {
	*E
	proto.Message
}, E any](r *http.Request, out *[]T) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	var rawItems []json.RawMessage
	if err := json.Unmarshal(body, &rawItems); err != nil {
		return err
	}
	result := make([]T, 0, len(rawItems))
	for _, raw := range rawItems {
		msg := T(new(E))
		if err := protojson.Unmarshal(raw, msg); err != nil {
			return err
		}
		result = append(result, msg)
	}
	*out = result
	return nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func writeProtoJSON(w http.ResponseWriter, msg proto.Message) {
	opts := protojson.MarshalOptions{
		Indent:          "  ",
		EmitUnpopulated: true,
	}
	data, err := opts.Marshal(msg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}
