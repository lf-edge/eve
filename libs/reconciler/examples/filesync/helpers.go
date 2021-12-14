// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Just some helper methods created *specifically* for this example.

package main

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/lf-edge/eve/libs/depgraph"
)

const (
	gvRedirectHost = "127.0.0.1:8080"
	gvRedirectURL = "http://" + gvRedirectHost
	gvCurrentState = "/CurrentState"
	gvIntendedState = "/IntendedState"
	gvMergedState = "/MergedState"
	gvRedirectTarget = "http://dreampuf.github.io/GraphvizOnline"
)

const (
	colorReset = "\033[0m"
	colorGreen = "\033[32m"
)

func (d *demo) redirect(dot string, exportErr error, target *url.URL,
	w http.ResponseWriter, r *http.Request) {
	if exportErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, "depgraph export to DOT failed: %v\n", exportErr)
		return
	}
	target.Fragment = dot
	// Do not let the client to cache.
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate") // HTTP 1.1.
	w.Header().Set("Pragma", "no-cache") // HTTP 1.0.
	w.Header().Set("Expires", "0") // Proxies.
	http.Redirect(w, r, target.String(), 302)
}

// Run local http server that redirects requests to dreampuf.github.io/GraphvizOnline
// for visual rendering of dependency graphs with the intended and the current state.
func (d *demo) redirectGraphvizRendering() {
	target, err := url.Parse(gvRedirectTarget)
	if err != nil {
		panic(err)
	}

	intendedState := func(w http.ResponseWriter, r *http.Request) {
		e := depgraph.DotExporter{CheckDeps: true}
		dot, err := e.Export(d.intendedState)
		d.redirect(dot, err, target, w, r)
	}
	currentState := func(w http.ResponseWriter, r *http.Request) {
		e := depgraph.DotExporter{CheckDeps: true}
		dot, err := e.Export(d.currentState)
		d.redirect(dot, err, target, w, r)
	}
	mergedState := func(w http.ResponseWriter, r *http.Request) {
		e := depgraph.DotExporter{CheckDeps: true}
		dot, err := e.ExportTransition(d.currentState, d.intendedState)
		d.redirect(dot, err, target, w, r)
	}
	http.HandleFunc(gvCurrentState, currentState)
	http.HandleFunc(gvIntendedState, intendedState)
	http.HandleFunc(gvMergedState, mergedState)

	go func() {
		err := http.ListenAndServe(gvRedirectHost, nil)
		if err != nil {
			panic(err)
		}
	}()
}

func (d *demo) printReport(format string, args ...interface{}) {
	fmt.Printf(colorGreen + format + "\n" + colorReset, args...)
}

func (d *demo) svgImageCircles(numOfCircles int) string {
	image := "<svg height=\"300\" width=\"200\">\n"
	for i:=0; i < numOfCircles; i++ {
		image += fmt.Sprintf("<circle cx=\"50\" cy=\"%d\" r=\"20\" fill=\"red\"/>\n",
			50+i*50)
	}
	image += "</svg>"
	return image
}

func (d *demo) svgImageSquares(numOfSquares int) string {
	image := "<svg height=\"300\" width=\"200\">\n"
	for i:=0; i < numOfSquares; i++ {
		image += fmt.Sprintf("<rect width=\"50\" height=\"50\" x=\"50\" y=\"%d\" fill=\"blue\"/>\n",
			50+i*50)
	}
	image += "</svg>"
	return image
}

func (d *demo) shellScript(cmds string) string {
	return fmt.Sprintf("#!/bin/sh\n%s", cmds)
}