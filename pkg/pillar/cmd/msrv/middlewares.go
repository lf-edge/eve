// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package msrv

import (
	"context"
	"fmt"
	"golang.org/x/time/rate"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type middlewareKeys int

const (
	patchEnvelopesContextKey middlewareKeys = iota
	appUUIDContextKey
)

// PrometheusMetricsConf structure storing global config
// for request limiter
type PrometheusMetricsConf struct {
	RPS         int
	Burst       int
	IdleTimeout time.Duration
}

// Get default values for PrometheusMetrics needed for testing
func defaultPrometheusMetricsConf() *PrometheusMetricsConf {
	return &PrometheusMetricsConf{
		RPS:         1,
		Burst:       10,
		IdleTimeout: 4 * time.Minute,
	}
}

// withPatchEnvelopesByIP is a middleware for Patch Envelopes which adds
// to a context patchEnvelope variable containing available patch envelopes
// for given IP address (it gets resolved to app instance UUID)
// in case there is no patch envelopes available it returns StatusNoContent
func (msrv *Msrv) withPatchEnvelopesByIP() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
			anStatus := msrv.lookupAppNetworkStatusByAppIP(remoteIP)
			if anStatus == nil {
				w.WriteHeader(http.StatusNoContent)
				msrv.Log.Errorf("No AppNetworkStatus for %s",
					remoteIP.String())
				return
			}

			appUUID := anStatus.UUIDandVersion.UUID

			accessablePe := msrv.PatchEnvelopes.Get(appUUID.String())
			if len(accessablePe.Envelopes) == 0 {
				sendError(w, http.StatusNotFound, fmt.Sprintf("No envelopes for %s", appUUID.String()))
			}

			ctx := context.WithValue(r.Context(), patchEnvelopesContextKey, accessablePe)
			ctx = context.WithValue(ctx, appUUIDContextKey, appUUID.String())

			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

type ipEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// withRateLimiterPerIP is a middleware that limits incoming HTTP requests per IP address.
// It enforces a rate limit with the given RPS and burst size, and automatically removes
// inactive IPs after the specified idle timeout.
func (msrv *Msrv) withRateLimiterPerIP() func(http.Handler) http.Handler {
	return rateLimiterPerIP(func() (rate.Limit, int, time.Duration) {
		return rate.Limit(msrv.pmc.RPS), msrv.pmc.Burst, msrv.pmc.IdleTimeout
	})
}

// rateLimiterPerIP limits requests per source IP to the rate and burst conf
// returns, dropping IPs idle longer than its idle timeout.
func rateLimiterPerIP(conf func() (rate.Limit, int, time.Duration)) func(http.Handler) http.Handler {
	var (
		mu       sync.Mutex
		visitors = make(map[string]*ipEntry)
	)

	// goroutine to cleanup idle IPs
	go func() {
		for {
			time.Sleep(time.Minute)
			_, _, idle := conf()
			mu.Lock()
			now := time.Now()
			for ip, v := range visitors {
				if now.Sub(v.lastSeen) > idle {
					delete(visitors, ip)
				}
			}
			mu.Unlock()
		}
	}()

	getLimiter := func(ip string) *rate.Limiter {
		limit, burst, _ := conf()
		mu.Lock()
		defer mu.Unlock()

		v, exists := visitors[ip]
		if !exists {
			limiter := rate.NewLimiter(limit, burst)
			visitors[ip] = &ipEntry{limiter: limiter, lastSeen: time.Now()}
			return limiter
		}

		if v.limiter.Limit() != limit || v.limiter.Burst() != burst {
			v.limiter.SetLimit(limit)
			v.limiter.SetBurst(burst)
		}

		v.lastSeen = time.Now()
		return v.limiter
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				http.Error(w, "Invalid IP address", http.StatusInternalServerError)
				return
			}

			limiter := getLimiter(ip)
			if !limiter.Allow() {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// withWriteDeadline replaces the server's write deadline, past which a reply
// is lost, with one d from now.
func withWriteDeadline(d time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(d))
			next.ServeHTTP(w, r)
		})
	}
}
