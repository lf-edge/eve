// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"

	"github.com/lf-edge/eve/evetest/testapps/lps/internal/lpsapi"
	"github.com/lf-edge/eve/evetest/testapps/lps/internal/manage"
	"github.com/lf-edge/eve/evetest/testapps/lps/internal/state"
)

//go:embed all:ui
var uiFS embed.FS

func main() {
	port := flag.Int("port", 8888, "HTTP server port")
	token := flag.String("token", "", "initial server token")
	flag.Parse()

	s := state.New()
	if *token != "" {
		s.SetServerToken(*token)
	}

	mux := http.NewServeMux()

	// LPS protocol endpoints
	lpsHandler := lpsapi.New(s)
	lpsHandler.Register(mux)

	// Management REST API
	manageHandler := manage.New(s)
	manageHandler.Register(mux)

	// Web UI
	uiContent, _ := fs.Sub(uiFS, "ui")
	mux.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(http.FS(uiContent))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/ui/", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("LPS starting on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
