// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/elazarl/goproxy"
	"github.com/elazarl/goproxy/ext/auth"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/sdn/vm/cmd/goproxy/config"
	log "github.com/sirupsen/logrus"
)

func installProxyHandler(rule *api.ProxyRule, https bool, proxy *goproxy.ProxyHttpServer) {
	notConnect := goproxy.Not(goproxy.ReqConditionFunc(isConnect))

	switch rule.GetAction() {
	case api.ProxyAction_PX_FORWARD:
		// Forward HTTP/HTTPS CONNECT
		proxy.OnRequest(dstHostIs(rule.GetReqHost())).HandleConnect(
			goproxy.FuncHttpsHandler(forwardConnect))
		if !https {
			// Forward HTTP GET, POST, etc. (but not CONNECT)
			proxy.OnRequest(dstHostIs(rule.GetReqHost()), notConnect).DoFunc(
				forwardHTTP)
		}

	case api.ProxyAction_PX_REJECT:
		// Reject HTTP/HTTPS CONNECT
		proxy.OnRequest(dstHostIs(rule.GetReqHost())).HandleConnect(
			goproxy.AlwaysReject)
		if !https {
			// Reject HTTP GET, POST, etc. (but not CONNECT)
			proxy.OnRequest(dstHostIs(rule.GetReqHost()), notConnect).DoFunc(
				rejectHTTP)
		}

	case api.ProxyAction_PX_MITM:
		if https {
			// CONNECT before establishing TLS tunnel
			proxy.OnRequest(dstHostIs(rule.GetReqHost())).HandleConnect(
				goproxy.AlwaysMitm)
		} else {
			// CONNECT is plain HTTP tunneling
			proxy.OnRequest(dstHostIs(rule.GetReqHost())).HandleConnect(
				goproxy.FuncHttpsHandler(mitmHTTPConnect))
			// non-CONNECT methods are simply forwarded
			proxy.OnRequest(dstHostIs(rule.GetReqHost()), notConnect).DoFunc(
				forwardHTTP)
		}
	}
}

func installProxyHandlers(proxyConfig config.ProxyConfig, https, transparent bool,
	proxy *goproxy.ProxyHttpServer) {
	// Add mark to differentiate between CONNECT and other HTTP methods.
	proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(markConnect))
	// Configure basic authentication if requested.
	isConnect := goproxy.ReqConditionFunc(isConnect)
	notConnect := goproxy.Not(isConnect)
	if len(proxyConfig.Users) > 0 {
		userAuth := func(user, passwd string) bool {
			for i := range proxyConfig.Users {
				if proxyConfig.Users[i].Username == user {
					return proxyConfig.Users[i].Password == passwd
				}
			}
			// No such user.
			return false
		}
		proxy.OnRequest(notConnect).Do(auth.Basic(authRealm, userAuth))
		proxy.OnRequest().HandleConnect(basicAuthForConnect(userAuth))
	}
	// Make sure HTTP and HTTPS are not mixed.
	matchTraffic := dstPortIs(80, 80)
	if https {
		matchTraffic = goproxy.Not(dstPortIs(80, 443))
	}
	proxy.OnRequest(goproxy.Not(matchTraffic)).DoFunc(rejectHTTP)
	// For transparent MITM HTTPS proxy it is necessary to fix the host inside
	// the request URL to contain the proxied port (which may be something else than 443).
	// This is basically a workaround for bug in elazarl/goproxy.
	if transparent {
		proxy.OnRequest(isConnect).DoFunc(copyHostToURL)
	}
	// Install handlers for rules configured by the user.
	var defaultRule *api.ProxyRule
	for _, rule := range proxyConfig.ProxyRules {
		if rule.ReqHost == "" {
			defaultRule = rule
			continue
		}
		installProxyHandler(rule, https, proxy)
	}
	if defaultRule == nil {
		defaultRule = &api.ProxyRule{Action: api.ProxyAction_PX_FORWARD}
	}
	installProxyHandler(defaultRule, https, proxy)
}

func dstPortIs(port, defaultPort uint16) goproxy.ReqConditionFunc {
	return func(req *http.Request, ctx *goproxy.ProxyCtx) bool {
		_, dstPortStr, err := net.SplitHostPort(req.URL.Host)
		if err == nil {
			dstPort, err := strconv.Atoi(dstPortStr)
			if err != nil {
				log.Errorf("Failed to convert dst port: %v", err)
				return false
			}
			log.Debugf("dstPortIs %v: %d vs. %d", req, dstPort, port)
			return dstPort == int(port)
		}
		log.Debugf("dstPortIs %v: %d vs. %d", req, defaultPort, port)
		return port == defaultPort
	}
}

func dstHostIs(host string) goproxy.ReqConditionFunc {
	return func(req *http.Request, ctx *goproxy.ProxyCtx) bool {
		if host == "" {
			// default rule matching any host
			return true
		}
		dstHost, _, _ := net.SplitHostPort(req.URL.Host)
		log.Debugf("dstHostIs %v: %s vs. %s", req, dstHost, host)
		return dstHost == host
	}
}

func isConnect(req *http.Request, ctx *goproxy.ProxyCtx) bool {
	_, hasConnectMark := ctx.UserData.(connectMark)
	log.Debugf("isConnect %v: %t", req, hasConnectMark)
	return hasConnectMark
}

func nonProxyHandler(proxy *goproxy.ProxyHttpServer) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Host == "" {
			_, err := fmt.Fprintln(
				w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			if err != nil {
				log.Warnf("Failed to write response: %v", err)
			}
			return
		}
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
		proxy.ServeHTTP(w, req)
	}
}

func forwardConnect(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	log.Debugf("forwardConnect: %s", host)
	return goproxy.OkConnect, host
}

func mitmHTTPConnect(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	log.Debugf("mitmHTTPConnect: %s", host)
	return goproxy.HTTPMitmConnect, host
}

type connectMark struct {
	session int64
}

func markConnect(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	ctx.UserData = connectMark{
		session: ctx.Session,
	}
	return nil, host // continue with other handlers
}

func basicAuthForConnect(f func(user, passwd string) bool) goproxy.HttpsHandler {
	authHandler := auth.BasicConnect(authRealm, f)
	return goproxy.FuncHttpsHandler(
		func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			log.Debugf("basicAuthForConnect: %s", host)
			action, host := authHandler.HandleConnect(host, ctx)
			if action == goproxy.OkConnect {
				// Return nil action, do not overshadow other handlers in the queue.
				return nil, host
			}
			return action, host
		})
}

func forwardHTTP(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	log.Debugf("forwardHTTP: %v", req)
	resp, err := ctx.RoundTrip(req)
	if err != nil {
		return req, goproxy.NewResponse(req,
			goproxy.ContentTypeText, http.StatusInternalServerError, err.Error())
	}
	return req, resp
}

func rejectHTTP(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	log.Debugf("rejectHTTP: %v", req)
	return req, goproxy.NewResponse(req,
		goproxy.ContentTypeText, http.StatusForbidden, "Forbidden by proxy!")
}

func copyHostToURL(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	log.Debugf("copyHostToURL: %v copied to %v", req.Host, req.URL.String())
	req.URL.Host = req.Host
	return req, nil
}
