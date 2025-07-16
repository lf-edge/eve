// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package manage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/lf-edge/eve/evetest/testapps/lps/internal/state"
)

const (
	// eventsMime is the Server-Sent Events MIME type.
	eventsMime = "text/event-stream"

	// eventsHeartbeatInterval keeps intermediate proxies from idle-closing
	// a long-lived SSE connection when no real events are flowing.
	eventsHeartbeatInterval = 25 * time.Second

	// eventsWriteTimeout bounds each individual write so a stuck client
	// cannot indefinitely block the goroutine.
	eventsWriteTimeout = 5 * time.Second
)

// events implements GET /manage/v1/events. It is a long-lived Server-Sent
// Events stream that delivers the current LPS state (both config and
// received-from-EVE data) to the UI as soon as anything changes. The
// first event on every new connection is a "snapshot" event carrying
// the full current state, so the UI does not have to make a separate
// priming request.
//
// Wire format: Server-Sent Events (text/event-stream). Two event names
// are used:
//
//	event: snapshot    — initial full state, sent once on connect.
//	event: update      — full state, sent whenever the broker fires.
//
// Periodic `: heartbeat\n\n` comment lines keep NAT/proxy idle timers
// from silently dropping the connection.
func (h *Handler) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", eventsMime)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")

	rc := http.NewResponseController(w)
	ch, unsub := h.state.Broker().SubscribeAny()
	defer unsub()

	// Initial snapshot so the UI paints immediately without a separate
	// priming request.
	if err := h.emitSnapshot(w, rc, "snapshot"); err != nil {
		log.Printf("events: initial write failed: %v", err)
		return
	}
	flusher.Flush()

	ctx := r.Context()
	heartbeat := time.NewTicker(eventsHeartbeatInterval)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			if err := h.emitSnapshot(w, rc, "update"); err != nil {
				log.Printf("events: update write failed: %v", err)
				return
			}
			flusher.Flush()
		case <-heartbeat.C:
			if err := writeHeartbeat(w, rc); err != nil {
				log.Printf("events: heartbeat write failed: %v", err)
				return
			}
			flusher.Flush()
		}
	}
}

// emitSnapshot serializes the current LPS state as a single SSE event
// of the given name.
func (h *Handler) emitSnapshot(w http.ResponseWriter,
	rc *http.ResponseController, event string) error {
	cfg, recv := h.state.GetAll()
	payload, err := marshalStateJSON(cfg, recv)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := rc.SetWriteDeadline(time.Now().Add(eventsWriteTimeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, payload)
	return err
}

// writeHeartbeat emits an SSE comment line. Proxies see this as
// non-empty traffic and do not idle-close the connection. The browser
// EventSource ignores it (no event is dispatched).
func writeHeartbeat(w http.ResponseWriter, rc *http.ResponseController) error {
	if err := rc.SetWriteDeadline(time.Now().Add(eventsWriteTimeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	_, err := fmt.Fprint(w, ": heartbeat\n\n")
	return err
}

// protojsonOpts emits zero-valued scalar fields (EmitUnpopulated=true),
// so the receiver can distinguish "absent" from "false" for booleans
// like NetworkPortConfig.local_modifications_allowed. Matches the
// options used by writeProtoJSON for the individual /manage/v1/*
// endpoints.
var protojsonOpts = protojson.MarshalOptions{EmitUnpopulated: true}

// marshalStateJSON emits the current LPS state as a single JSON object.
// Proto-typed fields are serialized via protojson (canonical camelCase
// field names, RFC3339 timestamps, symbolic enums, and flattened oneof
// fields) to match the wire format of the individual /manage/v1/*
// endpoints; plain Go structs use encoding/json with their explicit tags.
func marshalStateJSON(cfg state.Config, recv state.Received) ([]byte, error) {
	appCmds, err := marshalProtoList(protoMessages(cfg.AppCommands))
	if err != nil {
		return nil, err
	}
	appBoot, err := marshalProtoList(protoMessages(cfg.AppBootConfigs))
	if err != nil {
		return nil, err
	}
	lnc, err := marshalProtoMaybe(cfg.LocalNetworkConfig)
	if err != nil {
		return nil, err
	}
	rs, err := marshalProtoMaybe(recv.RadioStatus)
	if err != nil {
		return nil, err
	}
	ail, err := marshalProtoMaybe(recv.AppInfoList)
	if err != nil {
		return nil, err
	}
	di, err := marshalProtoMaybe(recv.DevInfo)
	if err != nil {
		return nil, err
	}
	loc, err := marshalProtoMaybe(recv.Location)
	if err != nil {
		return nil, err
	}
	ni, err := marshalProtoMaybe(recv.NetworkInfo)
	if err != nil {
		return nil, err
	}
	abi, err := marshalProtoMaybe(recv.AppBootInfo)
	if err != nil {
		return nil, err
	}

	return json.Marshal(map[string]any{
		"config": map[string]any{
			"serverToken":        cfg.ServerToken,
			"profile":            cfg.Profile,
			"radioSilence":       cfg.RadioSilence,
			"appCommands":        appCmds,
			"devCommand":         cfg.DevCommand,
			"appBootConfigs":     appBoot,
			"localNetworkConfig": lnc,
		},
		"received": map[string]any{
			"radioStatus": rs,
			"appInfoList": ail,
			"devInfo":     di,
			"location":    loc,
			"networkInfo": ni,
			"appBootInfo": abi,
		},
	})
}

// protoMessages widens a typed slice of proto.Message pointers into a
// []proto.Message for uniform handling by marshalProtoList.
func protoMessages[T proto.Message](ms []T) []proto.Message {
	out := make([]proto.Message, len(ms))
	for i, m := range ms {
		out[i] = m
	}
	return out
}

// marshalProtoMaybe serializes a single proto message using canonical
// JSON. Returns the raw string "null" for a nil or typed-nil pointer.
func marshalProtoMaybe(m proto.Message) (json.RawMessage, error) {
	if m == nil {
		return json.RawMessage("null"), nil
	}
	v := reflect.ValueOf(m)
	if v.Kind() == reflect.Ptr && v.IsNil() {
		return json.RawMessage("null"), nil
	}
	b, err := protojsonOpts.Marshal(m)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// marshalProtoList serializes a slice of proto messages as a JSON array
// using canonical JSON. Returns "[]" for an empty or nil slice.
func marshalProtoList(ms []proto.Message) (json.RawMessage, error) {
	if len(ms) == 0 {
		return json.RawMessage("[]"), nil
	}
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, m := range ms {
		if i > 0 {
			buf.WriteByte(',')
		}
		b, err := protojsonOpts.Marshal(m)
		if err != nil {
			return nil, err
		}
		buf.Write(b)
	}
	buf.WriteByte(']')
	return buf.Bytes(), nil
}
