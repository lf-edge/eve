// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
)

// TestRequestTimeoutBoundsCallsNotWatches checks both sides of the
// client split. A call that the apiserver never answers must stop at
// requestTimeout. A watch that stays open longer than requestTimeout
// must still deliver its events. Discovery keeps its own default.
func TestRequestTimeoutBoundsCallsNotWatches(t *testing.T) {
	saved := requestTimeout
	requestTimeout = 300 * time.Millisecond
	defer func() { requestTimeout = saved }()
	eventDelay := 3 * requestTimeout

	const event = `{"type":"ADDED","object":{"apiVersion":"v1","kind":"ConfigMap",` +
		`"metadata":{"name":"cm","namespace":"default","resourceVersion":"2"}}}` + "\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") == "" {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-time.After(eventDelay):
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, event)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()

	kc, err := newFromConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatalf("newFromConfig: %v", err)
	}

	start := time.Now()
	_, err = kc.Clientset.CoreV1().ConfigMaps("default").
		Get(context.Background(), "cm", metav1.GetOptions{})
	if err == nil {
		t.Error("Get against a hung apiserver returned no error")
	}
	if elapsed := time.Since(start); elapsed > requestTimeout+2*time.Second {
		t.Errorf("Get took %v; requestTimeout is %v", elapsed, requestTimeout)
	}

	// Discovery has no context, so its bound is the 32s default that
	// client-go sets when the config has no Timeout.
	disco, ok := kc.Discovery.RESTClient().(*rest.RESTClient)
	if !ok {
		t.Fatalf("Discovery.RESTClient() is %T, want *rest.RESTClient", kc.Discovery.RESTClient())
	}
	if got := disco.Client.Timeout; got != 32*time.Second {
		t.Errorf("discovery client timeout %v, want 32s", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), eventDelay+5*time.Second)
	defer cancel()
	w, err := kc.WatchClientset.CoreV1().ConfigMaps("default").Watch(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	defer w.Stop()
	ev, ok := <-w.ResultChan()
	if !ok {
		t.Fatal("watch closed before its first event; " +
			"the watch clients must not carry requestTimeout")
	}
	if ev.Type != watch.Added {
		t.Errorf("event type %s, want %s", ev.Type, watch.Added)
	}
}
