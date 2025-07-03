// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package zedkube

import (
	"context"
	"net"
	"sort"

	"github.com/lf-edge/eve/pkg/pillar/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var (
	kubeServiceCIDR *net.IPNet
)

// Define the excluded namespaces map at package level
var excludedKubeNamespaces = map[string]struct{}{
	"kube-system":     {},
	"kubevirt":        {},
	"longhorn-system": {},
	"cdi":             {},
	"eve-kube-app":    {},
}

func (z *zedkube) initKubePrefixes() error {
	var err error
	_, kubeServiceCIDR, err = net.ParseCIDR(types.KubeServicePrefix)
	return err
}

func (z *zedkube) collectKubeSvcs() {
	log.Functionf("collectKubeStats: Started collecting kube stats")

	clientset, err := getKubeClientSet()
	if err != nil {
		log.Errorf("collectKubeSvcs: can't get clientset %v", err)
		return
	}

	// Get services
	serviceInfoList, err := z.GetAllKubeServices(clientset)
	if err != nil {
		log.Errorf("collectKubeSvcs: can't get services %v", err)
		return
	}

	// Get ingresses, passing the service list to avoid redundant API calls
	ingressInfoList, err := z.GetAllKubeIngresses(clientset, serviceInfoList)
	if err != nil {
		log.Errorf("collectKubeSvcs: can't get ingresses %v", err)
		// Continue anyway, we might have some services
	}

	// Create new KubeUserServices struct with collected data
	newKubeUserServices := types.KubeUserServices{
		UserService: serviceInfoList,
		UserIngress: ingressInfoList,
	}

	// Get previous published data to compare
	currentInfoPtr, err := z.pubKubeUserServices.Get("global")
	var currentInfo types.KubeUserServices
	if err == nil && currentInfoPtr != nil {
		currentInfo = currentInfoPtr.(types.KubeUserServices)
	}

	// Only publish if there are changes
	if !currentInfo.Equal(newKubeUserServices) {
		log.Tracef("collectKubeSvcs: detected changes in services/ingresses, publishing updates")
		z.pubKubeUserServices.Publish("global", newKubeUserServices)
	} else {
		log.Tracef("collectKubeSvcs: no changes detected in services/ingresses, skipping publish")
	}

	log.Functionf("collectKubeSvcs: found %d services, %d ingress", len(newKubeUserServices.UserService), len(newKubeUserServices.UserIngress))
}

// GetAllKubeServices returns a slice of KubeServiceInfo containing all Kubernetes services across namespaces,
// excluding kube-system, kubevirt, longhorn-system, cdi namespaces,
// and the 'kubernetes' service in the default namespace.
func (z *zedkube) GetAllKubeServices(clientset *kubernetes.Clientset) ([]types.KubeServiceInfo, error) {
	// List all services across all namespaces
	services, err := clientset.CoreV1().Services("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("GetAllKubeServices: can't get services: %v", err)
		return nil, err
	}

	var serviceInfoList []types.KubeServiceInfo

	for _, svc := range services.Items {
		// Skip services in excluded namespaces
		if _, excluded := excludedKubeNamespaces[svc.Namespace]; excluded {
			continue
		}

		// Skip the 'kubernetes' service in the 'default' namespace
		if svc.Namespace == "default" && svc.Name == "kubernetes" {
			continue
		}

		// Skip the 'zks-cluster-agent' service in the 'cattle-system' namespace
		if svc.Namespace == "cattle-system" && svc.Name == "zks-cluster-agent" {
			continue
		}

		// Include all service types, including ClusterIP services
		// ClusterIP services might be referenced by ingresses, so we need to include them
		// to determine the service type for ingresses

		// Extract port information for each service
		for _, port := range svc.Spec.Ports {
			// Initialize service info
			serviceInfo := types.KubeServiceInfo{
				Name:      svc.Name,
				Namespace: svc.Namespace,
				Protocol:  port.Protocol,
				Port:      port.Port,
				NodePort:  port.NodePort, // Store the NodePort separately
				Type:      svc.Spec.Type,
			}

			// Special handling for cattle-system services with port 443
			// Convert to NodePort with port 6443 to allow kubeconfig access via api-server
			if svc.Namespace == "cattle-system" && port.Port == 443 {
				serviceInfo.Type = corev1.ServiceTypeNodePort
				serviceInfo.Port = 6443
				serviceInfo.ACEenabled = true // Enabled ACE for kubectl access locally
			}

			var loadbalancerIP string
			// For LoadBalancer services, look for an external IP
			if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
				// First, check if LoadBalancerIP is explicitly specified in the Spec
				// This is the IP the user has requested from the provider (e.g. 192.168.86.200)
				if svc.Spec.LoadBalancerIP != "" {
					loadbalancerIP = svc.Spec.LoadBalancerIP
				}

				// If no Spec.LoadBalancerIP, check external IPs
				if loadbalancerIP == "" && len(svc.Spec.ExternalIPs) > 0 {
					loadbalancerIP = svc.Spec.ExternalIPs[0]
				}

				// If still no IP, check annotations for kube-vip loadbalancer IPs
				if loadbalancerIP == "" {
					if ip, ok := svc.Annotations["kube-vip.io/loadbalancerIPs"]; ok && ip != "" {
						loadbalancerIP = ip
					}
				}

				// If we have a LoadBalancerIP, check if it's within the K8s service CIDR range
				if loadbalancerIP != "" {
					ipAddr := net.ParseIP(loadbalancerIP)
					if ipAddr != nil && kubeServiceCIDR.Contains(ipAddr) {
						log.Functionf("GetAllKubeServices: skipping service %s/%s with LoadBalancerIP %s as it's in the K8s service CIDR range",
							svc.Namespace, svc.Name, loadbalancerIP)
						continue // Skip this service port
					}
				} else {
					continue // Skip LoadBalancer services without an IP
				}
				serviceInfo.LoadBalancerIP = loadbalancerIP

				// Note: Deliberately not using LoadBalancer.Ingress IPs as fallback
				// as these are typically internal IPs assigned by the LoadBalancer controller
				// rather than the external IPs that we want to target with specific rules
			}

			serviceInfoList = append(serviceInfoList, serviceInfo)
		}
	}

	log.Functionf("GetAllKubeServices: found %d service ports", len(serviceInfoList))
	return serviceInfoList, nil
}

// GetAllKubeIngresses returns a list of all Kubernetes ingresses across namespaces,
// excluding the same namespaces that we exclude for services.
// It takes the serviceInfoList to avoid making redundant API calls for service information.
func (z *zedkube) GetAllKubeIngresses(clientset *kubernetes.Clientset, serviceInfoList []types.KubeServiceInfo) ([]types.KubeIngressInfo, error) {
	// List all ingresses across all namespaces
	ingresses, err := clientset.NetworkingV1().Ingresses("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("GetAllKubeIngresses: can't get ingresses: %v", err)
		return nil, err
	}

	var ingressInfoList []types.KubeIngressInfo

	for _, ing := range ingresses.Items {
		// Skip ingresses in excluded namespaces
		if _, excluded := excludedKubeNamespaces[ing.Namespace]; excluded {
			continue
		}

		// Get the IP addresses of the ingress (if any)
		var ingressIPs []string
		for _, lbIngress := range ing.Status.LoadBalancer.Ingress {
			if lbIngress.IP != "" {
				// Check if the IP is on one of our interfaces and log accordingly
				isDeviceIP := z.isDeviceInterfaceIP(lbIngress.IP)
				if isDeviceIP {
					log.Functionf("Ingress %s/%s includes IP %s that matches a device interface",
						ing.Namespace, ing.Name, lbIngress.IP)
					// Only add the IP if it belongs to one of our interfaces
					ingressIPs = append(ingressIPs, lbIngress.IP)
				}
			} else if lbIngress.Hostname != "" {
				ingressIPs = append(ingressIPs, lbIngress.Hostname) // Use hostname if IP is not available
			}
		}

		// Sort the IPs to ensure consistent order
		if len(ingressIPs) > 1 {
			sort.Strings(ingressIPs)
			log.Functionf("Sorted %d ingress IPs for %s/%s", len(ingressIPs), ing.Namespace, ing.Name)
		}

		// Process each rule in the ingress
		for _, rule := range ing.Spec.Rules {
			hostname := rule.Host
			if rule.HTTP == nil {
				continue
			}

			// Process each path in the rule
			for _, path := range rule.HTTP.Paths {
				if path.Backend.Service == nil {
					continue
				}

				// Default to HTTP, check for TLS configuration
				protocol := "http"
				for _, tls := range ing.Spec.TLS {
					for _, host := range tls.Hosts {
						if host == hostname || host == "" {
							protocol = "https"
							break
						}
					}
					if protocol == "https" {
						break
					}
				}

				// Create ingress info object
				pathType := ""
				if path.PathType != nil {
					pathType = string(*path.PathType)
				}

				// Get the service type by looking up the service in already fetched serviceInfoList
				var serviceType corev1.ServiceType = corev1.ServiceTypeClusterIP // default if not found
				serviceName := path.Backend.Service.Name
				serviceNamespace := ing.Namespace

				// Look for the service in our already fetched serviceInfoList
				serviceFound := false
				for _, svcInfo := range serviceInfoList {
					if svcInfo.Name == serviceName && svcInfo.Namespace == serviceNamespace {
						serviceType = svcInfo.Type
						serviceFound = true

						// Add more detailed logging for LoadBalancer and NodePort services
						if serviceType == corev1.ServiceTypeLoadBalancer {
							log.Functionf("GetAllKubeIngresses: found LoadBalancer service %s/%s (LB IP: %s)",
								serviceNamespace, serviceName, svcInfo.LoadBalancerIP)
						} else if serviceType == corev1.ServiceTypeNodePort {
							log.Functionf("GetAllKubeIngresses: found NodePort service %s/%s (NodePort: %d)",
								serviceNamespace, serviceName, svcInfo.NodePort)
						} else {
							log.Functionf("GetAllKubeIngresses: found service %s/%s with type %s in serviceInfoList",
								serviceNamespace, serviceName, serviceType)
						}
						break
					}
				}

				// If not found in our list (which should include all services now),
				// try to get it directly - this might happen in rare cases like race conditions
				if !serviceFound {
					log.Warningf("GetAllKubeIngresses: service %s/%s not found in serviceInfoList, fetching directly",
						serviceNamespace, serviceName)

					svc, err := clientset.CoreV1().Services(serviceNamespace).Get(
						context.Background(), serviceName, metav1.GetOptions{})
					if err != nil {
						log.Warningf("GetAllKubeIngresses: couldn't get service %s/%s: %v",
							serviceNamespace, serviceName, err)
					} else {
						serviceType = svc.Spec.Type
						log.Functionf("GetAllKubeIngresses: direct fetch of service %s/%s found type %s",
							serviceNamespace, serviceName, serviceType)
					}
				}

				ingressInfo := types.KubeIngressInfo{
					Name:        ing.Name,
					Namespace:   ing.Namespace,
					Hostname:    hostname,
					Path:        path.Path,
					PathType:    pathType,
					Protocol:    protocol,
					Service:     serviceName,
					ServicePort: path.Backend.Service.Port.Number,
					ServiceType: serviceType,
					IngressIP:   ingressIPs,
				}
				ingressInfoList = append(ingressInfoList, ingressInfo)
			}
		}
	}

	log.Functionf("GetAllKubeIngresses: found %d ingress paths", len(ingressInfoList))
	return ingressInfoList, nil
}

// isDeviceInterfaceIP checks if the given IP is assigned to any of the device's network interfaces
func (z *zedkube) isDeviceInterfaceIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		// Not a valid IP
		return false
	}

	// Check each port in deviceNetworkStatus
	for _, port := range z.deviceNetworkStatus.Ports {
		// Check each address in the port's AddrInfoList
		for _, addrInfo := range port.AddrInfoList {
			if addrInfo.Addr.Equal(ip) {
				log.Functionf("Found matching interface IP %s on port %s", ipStr, port.IfName)
				return true
			}
		}
	}

	// IP is not on any of our interfaces
	return false
}
