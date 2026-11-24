// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	dsListPath  = "GET /apis/apps/v1/namespaces/kube-system/daemonsets"
	svcPath     = "/api/v1/namespaces/kube-system/services/traefik"
	chartPath   = "GET /apis/helm.cattle.io/v1/namespaces/kube-system/helmcharts/traefik"
	secretsPath = "GET /api/v1/namespaces/kube-system/secrets"
	cmsPath     = "GET /api/v1/namespaces/kube-system/configmaps"
	dsName      = "svclb-traefik-c9639a91"
	dsDelete    = "DELETE /apis/apps/v1/namespaces/kube-system/daemonsets/" + dsName
)

func TestKubeletAllowsSysctl(t *testing.T) {
	cases := []struct {
		name    string
		configz string
		want    bool
		wantErr bool
	}{
		{"servicelb enabled",
			`{"kubeletconfig":{"allowedUnsafeSysctls":["net.ipv4.ip_forward","net.ipv6.conf.all.forwarding"]}}`,
			true, false},
		{"pattern", `{"kubeletconfig":{"allowedUnsafeSysctls":["net.ipv4.*"]}}`, true, false},
		{"other pattern", `{"kubeletconfig":{"allowedUnsafeSysctls":["net.ipv6.*"]}}`, false, false},
		{"servicelb disabled", `{"kubeletconfig":{"cpuManagerPolicy":"static"}}`, false, false},
		{"empty allowlist", `{"kubeletconfig":{"allowedUnsafeSysctls":[]}}`, false, false},
		// An unrecognised answer must not read as "servicelb off".
		{"no kubeletconfig", `{"other":{}}`, false, true},
		{"not JSON", `<html>`, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := kubeletAllowsSysctl([]byte(c.configz), servicelbSysctl)
			if (err != nil) != c.wantErr || got != c.want {
				t.Errorf("got %v, %v; want %v, error=%v", got, err, c.want, c.wantErr)
			}
		})
	}
}

func TestIsPackagedTraefikService(t *testing.T) {
	if !isPackagedTraefikService(packagedTraefikService()) {
		t.Error("k3s's packaged Traefik Service not recognised")
	}
	if isPackagedTraefikService(nil) {
		t.Error("nil Service recognised")
	}
	for name, mutate := range map[string]func(*corev1.Service){
		"ClusterIP":         func(s *corev1.Service) { s.Spec.Type = corev1.ServiceTypeClusterIP },
		"not Helm":          func(s *corev1.Service) { delete(s.Labels, "app.kubernetes.io/managed-by") },
		"other release":     func(s *corev1.Service) { s.Annotations["meta.helm.sh/release-name"] = "edge-traefik" },
		"release elsewhere": func(s *corev1.Service) { s.Annotations["meta.helm.sh/release-namespace"] = "traefik" },
		"other namespace":   func(s *corev1.Service) { s.Namespace = "default" },
	} {
		svc := packagedTraefikService()
		mutate(svc)
		if isPackagedTraefikService(svc) {
			t.Errorf("%s: recognised as k3s's packaged Traefik", name)
		}
	}
}

func TestFinalizerRemovalPatch(t *testing.T) {
	patch, err := finalizerRemovalPatch(
		[]string{"example.com/keep", lbCleanupFinalizer}, lbCleanupFinalizer, "42")
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"metadata":{"finalizers":["example.com/keep"],"resourceVersion":"42"}}`; string(patch) != want {
		t.Errorf("patch = %s; want %s", patch, want)
	}

	// The last finalizer becomes an empty list, not null.
	patch, err = finalizerRemovalPatch([]string{lbCleanupFinalizer}, lbCleanupFinalizer, "7")
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"metadata":{"finalizers":[],"resourceVersion":"7"}}`; string(patch) != want {
		t.Errorf("patch = %s; want %s", patch, want)
	}

	patch, err = finalizerRemovalPatch([]string{"example.com/keep"}, lbCleanupFinalizer, "7")
	if err != nil || patch != nil {
		t.Errorf("finalizer absent: got %s, %v; want no patch", patch, err)
	}
}

// Nothing left behind: two reads, no node is asked anything, settled.
func TestCleanupServiceLBOrphans_NothingToDo(t *testing.T) {
	api := newFakeAPI(t)
	api.daemonSets()
	api.notFound("GET " + svcPath)

	res := api.pass(t, time.Now())
	wantResult(t, res, true, "")
	api.wantRequests(t, dsListPath, "GET "+svcPath)
}

// A Traefik Service that is not k3s's (here the user's own ClusterIP one)
// is not a reason to look further.
func TestCleanupServiceLBOrphans_LeavesOtherTraefikService(t *testing.T) {
	api := newFakeAPI(t)
	api.daemonSets()
	svc := packagedTraefikService()
	svc.Spec.Type = corev1.ServiceTypeClusterIP
	api.object("GET "+svcPath, svc)

	res := api.pass(t, time.Now())
	wantResult(t, res, true, "")
	api.wantRequests(t, dsListPath, "GET "+svcPath)
}

// The state after an upgrade from a servicelb-on build: servicelb is off
// everywhere and the DaemonSet and Service are left behind with nothing
// owning the release.
func TestCleanupServiceLBOrphans_DeletesLeftovers(t *testing.T) {
	api := newFakeAPI(t)
	api.daemonSets(servicelbDaemonSet(dsName, "ds-uid"))
	api.object("GET "+svcPath, packagedTraefikService())
	api.nodes(readyNode("n1"), readyNode("n2"), notReadyNode("n3"))
	api.configz("n1", false)
	api.configz("n2", false)
	// n3 is NotReady and must not be asked.
	api.status("GET /api/v1/nodes/n3/proxy/configz", http.StatusServiceUnavailable)
	api.noReleaseOwner()
	api.success(dsDelete)
	api.success("DELETE " + svcPath)

	res := api.pass(t, time.Now())
	// Not settled: the next tick checks that the deletes took.
	wantResult(t, res, false, "")
	api.wantRequests(t,
		dsListPath,
		"GET "+svcPath,
		"GET /api/v1/nodes",
		"GET /api/v1/nodes/n1/proxy/configz",
		"GET /api/v1/nodes/n2/proxy/configz",
		dsDelete,
		chartPath,
		secretsPath,
		cmsPath,
		"DELETE "+svcPath,
	)
	if q := api.query(dsListPath); q.Get("labelSelector") != servicelbSvcNameLabel {
		t.Errorf("DaemonSet list query = %v; want the servicelb label selector", q)
	}
	for _, path := range []string{secretsPath, cmsPath} {
		if q := api.query(path); q.Get("labelSelector") != "owner=helm,name=traefik" {
			t.Errorf("%s query = %v; want owner=helm,name=traefik", path, q)
		}
		// Release records hold the release's values; never fetch them.
		if a := api.accept(path); !strings.Contains(a, "as=PartialObjectMetadataList") {
			t.Errorf("%s Accept = %q; want metadata only", path, a)
		}
	}

	var del metav1.DeleteOptions
	api.body(t, dsDelete, &del)
	if del.Preconditions == nil || del.Preconditions.UID == nil || *del.Preconditions.UID != "ds-uid" {
		t.Errorf("DaemonSet delete has no UID precondition: %+v", del)
	}
	if del.PropagationPolicy == nil || *del.PropagationPolicy != metav1.DeletePropagationBackground {
		t.Errorf("DaemonSet delete does not take its pods with it: %+v", del)
	}
	var svcDel metav1.DeleteOptions
	api.body(t, "DELETE "+svcPath, &svcDel)
	if svcDel.Preconditions == nil || svcDel.Preconditions.UID == nil || *svcDel.Preconditions.UID != "svc-uid" {
		t.Errorf("Service delete has no UID precondition: %+v", svcDel)
	}
}

// A node running servicelb owns these objects: nothing is deleted, and
// the node is left to clean up on its own k3s start.
func TestCleanupServiceLBOrphans_HeldWhileServiceLBEnabledOnANode(t *testing.T) {
	api := newFakeAPI(t)
	api.daemonSets(servicelbDaemonSet(dsName, "ds-uid"))
	api.object("GET "+svcPath, packagedTraefikService())
	api.nodes(readyNode("n1"), readyNode("n2"))
	api.configz("n1", false)
	api.configz("n2", true)

	res := api.pass(t, time.Now())
	wantResult(t, res, true, "node n2")
	api.wantNoWrites(t)
}

// Not knowing is not "off": an unreadable kubelet config holds the
// cleanup back and is retried.
func TestCleanupServiceLBOrphans_HeldWhenAKubeletCannotBeRead(t *testing.T) {
	api := newFakeAPI(t)
	api.daemonSets(servicelbDaemonSet(dsName, "ds-uid"))
	api.notFound("GET " + svcPath)
	api.nodes(readyNode("n1"), readyNode("n2"))
	api.configz("n1", false)
	api.status("GET /api/v1/nodes/n2/proxy/configz", http.StatusBadGateway)

	res := api.pass(t, time.Now())
	if res.err == nil || res.settled {
		t.Errorf("got %+v; want an error and not settled", res)
	}
	api.wantNoWrites(t)
}

func TestCleanupServiceLBOrphans_HeldWithNoReadyNode(t *testing.T) {
	api := newFakeAPI(t)
	api.daemonSets(servicelbDaemonSet(dsName, "ds-uid"))
	api.notFound("GET " + svcPath)
	api.nodes(notReadyNode("n1"))

	if res := api.pass(t, time.Now()); res.err == nil || res.settled {
		t.Errorf("got %+v; want an error and not settled", res)
	}
	api.wantNoWrites(t)
}

// A Traefik release something still owns is left alone; the dead
// DaemonSets still go. A HelmChart means helm-controller is mid-change,
// so it is retried; a release record means someone else's Traefik.
func TestCleanupServiceLBOrphans_LeavesOwnedTraefikRelease(t *testing.T) {
	for _, c := range []struct {
		name        string
		owned       func(*fakeAPI)
		wantSettled bool
		wantReason  string
	}{
		{"HelmChart", func(api *fakeAPI) {
			api.raw(chartPath, http.StatusOK,
				`{"apiVersion":"helm.cattle.io/v1","kind":"HelmChart","metadata":{"name":"traefik","namespace":"kube-system"}}`)
		}, false, "still owned by HelmChart"},
		{"release Secret", func(api *fakeAPI) {
			api.notFound(chartPath)
			api.releaseRecords(secretsPath, "sh.helm.release.v1.traefik.v1")
		}, true, "secrets/sh.helm.release.v1.traefik.v1"},
		{"release ConfigMap", func(api *fakeAPI) {
			api.notFound(chartPath)
			api.releaseRecords(secretsPath)
			api.releaseRecords(cmsPath, "sh.helm.release.v1.traefik.v1")
		}, true, "configmaps/sh.helm.release.v1.traefik.v1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			api := newFakeAPI(t)
			api.daemonSets()
			api.object("GET "+svcPath, packagedTraefikService())
			api.nodes(readyNode("n1"))
			api.configz("n1", false)
			c.owned(api)

			res := api.pass(t, time.Now())
			wantResult(t, res, c.wantSettled, c.wantReason)
			api.wantNoWrites(t)
		})
	}
}

// Dead DaemonSets go even when the Service is left alone, and the pass
// is not settled until a later one finds them gone.
func TestCleanupServiceLBOrphans_DeletesDaemonSetsBesideOwnedService(t *testing.T) {
	api := newFakeAPI(t)
	api.daemonSets(servicelbDaemonSet(dsName, "ds-uid"))
	api.object("GET "+svcPath, packagedTraefikService())
	api.nodes(readyNode("n1"))
	api.configz("n1", false)
	api.notFound(chartPath)
	api.releaseRecords(secretsPath, "sh.helm.release.v1.traefik.v1")
	api.success(dsDelete)

	res := api.pass(t, time.Now())
	wantResult(t, res, false, "owned by Helm release record")
	if !api.saw(dsDelete) {
		t.Error("DaemonSet not deleted")
	}
}

// A Service stuck terminating on the load-balancer finalizer gets a grace
// period for a provider to release it, then the finalizer is removed,
// conditional on the resourceVersion read.
func TestCleanupServiceLBOrphans_ReleasesStuckFinalizerAfterGrace(t *testing.T) {
	deleting := time.Date(2026, 11, 24, 18, 0, 0, 0, time.UTC)
	svc := packagedTraefikService()
	svc.DeletionTimestamp = &metav1.Time{Time: deleting}
	svc.Finalizers = []string{lbCleanupFinalizer}
	svc.ResourceVersion = "1234"

	setup := func() *fakeAPI {
		api := newFakeAPI(t)
		api.daemonSets()
		api.object("GET "+svcPath, svc)
		api.nodes(readyNode("n1"))
		api.configz("n1", false)
		api.noReleaseOwner()
		api.object("PATCH "+svcPath, svc)
		return api
	}

	api := setup()
	res := api.pass(t, deleting.Add(lbFinalizerGrace/2))
	wantResult(t, res, false, "is terminating")
	api.wantNoWrites(t)

	api = setup()
	res = api.pass(t, deleting.Add(lbFinalizerGrace))
	wantResult(t, res, false, "")
	if got := api.contentType("PATCH " + svcPath); got != string(types.MergePatchType) {
		t.Errorf("patch content type = %q; want %s", got, types.MergePatchType)
	}
	var patch map[string]map[string]any
	api.body(t, "PATCH "+svcPath, &patch)
	if rv := patch["metadata"]["resourceVersion"]; rv != "1234" {
		t.Errorf("patch resourceVersion = %v; want 1234", rv)
	}
	if f, ok := patch["metadata"]["finalizers"].([]any); !ok || len(f) != 0 {
		t.Errorf("patch finalizers = %v; want []", patch["metadata"]["finalizers"])
	}
	if api.saw("DELETE " + svcPath) {
		t.Error("a terminating Service was deleted again")
	}
}

// A terminating Service held only by someone else's finalizer is left.
func TestCleanupServiceLBOrphans_LeavesOtherFinalizers(t *testing.T) {
	svc := packagedTraefikService()
	svc.DeletionTimestamp = &metav1.Time{Time: time.Now().Add(-time.Hour)}
	svc.Finalizers = []string{"example.com/keep"}
	api := newFakeAPI(t)
	api.daemonSets()
	api.object("GET "+svcPath, svc)
	api.nodes(readyNode("n1"))
	api.configz("n1", false)
	api.noReleaseOwner()

	wantResult(t, api.pass(t, time.Now()), true, "not ours")
	api.wantNoWrites(t)
}

// Run stops calling the API once a pass settles, until Reset.
func TestServiceLBCleanup_IdleOnceSettledUntilReset(t *testing.T) {
	api := newFakeAPI(t)
	api.daemonSets()
	api.notFound("GET " + svcPath)
	var c ServiceLBCleanup

	api.runCleanup(t, &c)
	api.runCleanup(t, &c)
	if n := len(api.requests()); n != 2 {
		t.Errorf("%d requests over two settled ticks; want 2 (one pass)", n)
	}
	c.Reset()
	api.runCleanup(t, &c)
	if n := len(api.requests()); n != 4 {
		t.Errorf("%d requests after Reset; want 4 (a second pass)", n)
	}
}

// A lasting error is retried every tick but logged once.
func TestServiceLBCleanup_LogsALastingErrorOnce(t *testing.T) {
	api := newFakeAPI(t)
	api.status(dsListPath, http.StatusInternalServerError)
	var c ServiceLBCleanup
	logs := captureLog(t)

	for range 3 {
		api.runCleanup(t, &c)
	}
	if n := len(api.requests()); n != 3 {
		t.Errorf("%d requests over three failing ticks; want 3 (retried each tick)", n)
	}
	if n := strings.Count(logs.String(), "WARNING"); n != 1 {
		t.Errorf("warning logged %d times; want once:\n%s", n, logs)
	}
}

// The whole pass gives up within servicelbPassBudget, however many calls
// it would make, so the serial health worker is not held.
func TestServiceLBCleanup_PassGivesUpWithinItsBudget(t *testing.T) {
	oldPass, oldCall := servicelbPassBudget, servicelbAPICallBudget
	servicelbPassBudget, servicelbAPICallBudget = 300*time.Millisecond, 10*time.Second
	t.Cleanup(func() { servicelbPassBudget, servicelbAPICallBudget = oldPass, oldCall })
	srv := httptest.NewServer(http.HandlerFunc(hungAPI))
	t.Cleanup(srv.Close)
	cs, dyn := clientsFor(t, srv.URL)
	var c ServiceLBCleanup
	captureLog(t)

	start := time.Now()
	c.run(workerContext(t), cs, dyn, time.Now())
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("pass took %v; its budget is %v", elapsed, servicelbPassBudget)
	}
	if c.settled.Load() {
		t.Error("a failed pass settled")
	}
}

// Each call also gives up on its own.
func TestCleanupServiceLBOrphans_GivesUpOnAHungAPI(t *testing.T) {
	old := servicelbAPICallBudget
	servicelbAPICallBudget = 200 * time.Millisecond
	t.Cleanup(func() { servicelbAPICallBudget = old })
	srv := httptest.NewServer(http.HandlerFunc(hungAPI))
	t.Cleanup(srv.Close)
	cs, dyn := clientsFor(t, srv.URL)

	start := time.Now()
	if res := cleanupServiceLBOrphans(workerContext(t), cs, dyn, time.Now()); res.err == nil {
		t.Fatal("expected an error from a hung apiserver")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("cleanup took %v; each call must give up near %v", elapsed, servicelbAPICallBudget)
	}
}

func wantResult(t *testing.T, res passResult, settled bool, reasonPart string) {
	t.Helper()
	if res.err != nil {
		t.Fatalf("unexpected error: %v", res.err)
	}
	if res.settled != settled {
		t.Errorf("settled = %v; want %v (reason %q)", res.settled, settled, res.reason)
	}
	if reasonPart == "" && res.reason != "" || !strings.Contains(res.reason, reasonPart) {
		t.Errorf("reason = %q; want it to contain %q", res.reason, reasonPart)
	}
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

// --- fake apiserver ---

type fakeResponse struct {
	code int
	body string
}

type fakeRequest struct {
	key, query, contentType, accept string
	body                            []byte
}

// fakeAPI answers scripted "METHOD path" routes and records every request.
// An unscripted request fails the test.
type fakeAPI struct {
	t      *testing.T
	routes map[string]fakeResponse
	mu     sync.Mutex
	log    []fakeRequest
	srv    *httptest.Server
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	api := &fakeAPI{t: t, routes: map[string]fakeResponse{}}
	api.srv = httptest.NewServer(http.HandlerFunc(api.serve))
	t.Cleanup(api.srv.Close)
	return api
}

func (a *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	key := r.Method + " " + r.URL.Path
	a.mu.Lock()
	a.log = append(a.log, fakeRequest{key, r.URL.RawQuery,
		r.Header.Get("Content-Type"), r.Header.Get("Accept"), body})
	resp, ok := a.routes[key]
	a.mu.Unlock()
	if !ok {
		a.t.Errorf("unexpected request %s", key)
		resp = fakeResponse{http.StatusNotImplemented, ""}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.code)
	_, _ = io.WriteString(w, resp.body)
}

func (a *fakeAPI) raw(key string, code int, body string) {
	a.routes[key] = fakeResponse{code, body}
}

func (a *fakeAPI) object(key string, obj any) {
	b, err := json.Marshal(obj)
	if err != nil {
		a.t.Fatal(err)
	}
	a.raw(key, http.StatusOK, string(b))
}

func (a *fakeAPI) status(key string, code int) {
	a.raw(key, code, `{"kind":"Status","apiVersion":"v1","status":"Failure","code":`+strconv.Itoa(code)+`}`)
}

func (a *fakeAPI) notFound(key string) {
	a.raw(key, http.StatusNotFound,
		`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`)
}

func (a *fakeAPI) success(key string) {
	a.raw(key, http.StatusOK, `{"kind":"Status","apiVersion":"v1","status":"Success"}`)
}

func (a *fakeAPI) daemonSets(items ...appsv1.DaemonSet) {
	a.object(dsListPath, &appsv1.DaemonSetList{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSetList", APIVersion: "apps/v1"}, Items: items})
}

func (a *fakeAPI) nodes(items ...corev1.Node) {
	a.object("GET /api/v1/nodes", &corev1.NodeList{
		TypeMeta: metav1.TypeMeta{Kind: "NodeList", APIVersion: "v1"}, Items: items})
}

func (a *fakeAPI) configz(node string, servicelbOn bool) {
	allowed := `[]`
	if servicelbOn {
		allowed = `["net.ipv4.ip_forward","net.ipv6.conf.all.forwarding"]`
	}
	a.raw("GET /api/v1/nodes/"+node+"/proxy/configz", http.StatusOK,
		`{"kubeletconfig":{"cpuManagerPolicy":"static","allowedUnsafeSysctls":`+allowed+`}}`)
}

// releaseRecords answers a metadata-only list of Helm release records.
func (a *fakeAPI) releaseRecords(key string, names ...string) {
	list := metav1.PartialObjectMetadataList{
		TypeMeta: metav1.TypeMeta{Kind: "PartialObjectMetadataList", APIVersion: "meta.k8s.io/v1"}}
	for _, n := range names {
		list.Items = append(list.Items, metav1.PartialObjectMetadata{
			ObjectMeta: metav1.ObjectMeta{Name: n, Namespace: "kube-system"}})
	}
	a.object(key, &list)
}

// noReleaseOwner scripts the traefik release as owned by nothing.
func (a *fakeAPI) noReleaseOwner() {
	a.notFound(chartPath)
	a.releaseRecords(secretsPath)
	a.releaseRecords(cmsPath)
}

func (a *fakeAPI) pass(t *testing.T, now time.Time) passResult {
	t.Helper()
	cs, dyn := clientsFor(t, a.srv.URL)
	return cleanupServiceLBOrphans(workerContext(t), cs, dyn, now)
}

func (a *fakeAPI) runCleanup(t *testing.T, c *ServiceLBCleanup) {
	t.Helper()
	cs, dyn := clientsFor(t, a.srv.URL)
	c.run(workerContext(t), cs, dyn, time.Now())
}

func (a *fakeAPI) requests() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	keys := make([]string, len(a.log))
	for i, r := range a.log {
		keys[i] = r.key
	}
	return keys
}

func (a *fakeAPI) find(key string) *fakeRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.log {
		if a.log[i].key == key {
			return &a.log[i]
		}
	}
	return nil
}

func (a *fakeAPI) saw(key string) bool { return a.find(key) != nil }

func (a *fakeAPI) query(key string) url.Values {
	if r := a.find(key); r != nil {
		q, _ := url.ParseQuery(r.query)
		return q
	}
	return nil
}

func (a *fakeAPI) contentType(key string) string {
	if r := a.find(key); r != nil {
		return r.contentType
	}
	return ""
}

func (a *fakeAPI) accept(key string) string {
	if r := a.find(key); r != nil {
		return r.accept
	}
	return ""
}

func (a *fakeAPI) body(t *testing.T, key string, into any) {
	t.Helper()
	r := a.find(key)
	if r == nil {
		t.Fatalf("no request %s", key)
	}
	if err := json.Unmarshal(r.body, into); err != nil {
		t.Fatalf("%s body %q: %v", key, r.body, err)
	}
}

func (a *fakeAPI) wantRequests(t *testing.T, want ...string) {
	t.Helper()
	got := a.requests()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("requests:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

func (a *fakeAPI) wantNoWrites(t *testing.T) {
	t.Helper()
	for _, r := range a.requests() {
		if !strings.HasPrefix(r, "GET ") {
			t.Errorf("unexpected write %s", r)
		}
	}
}

func clientsFor(t *testing.T, host string) (kubernetes.Interface, dynamic.Interface) {
	t.Helper()
	// JSON rather than client-go's protobuf default, so the test can
	// read what was sent.
	cfg := &rest.Config{Host: host, ContentConfig: rest.ContentConfig{
		ContentType: "application/json", AcceptContentTypes: "application/json"}}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return cs, dyn
}

// --- fixtures ---

func packagedTraefikService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "traefik", Namespace: "kube-system", UID: "svc-uid",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "Helm",
				"app.kubernetes.io/name":       "traefik",
			},
			Annotations: map[string]string{
				"meta.helm.sh/release-name":      "traefik",
				"meta.helm.sh/release-namespace": "kube-system",
			},
		},
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
	}
}

func servicelbDaemonSet(name, uid string) appsv1.DaemonSet {
	return appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Name: name, Namespace: "kube-system", UID: types.UID(uid),
		Labels: map[string]string{
			servicelbSvcNameLabel:      "traefik",
			servicelbSvcNamespaceLabel: "kube-system",
		},
	}}
}

func readyNode(name string) corev1.Node {
	return nodeWithReady(name, corev1.ConditionTrue)
}

func notReadyNode(name string) corev1.Node {
	return nodeWithReady(name, corev1.ConditionUnknown)
}

func nodeWithReady(name string, status corev1.ConditionStatus) corev1.Node {
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
			{Type: corev1.NodeReady, Status: status},
		}},
	}
}
