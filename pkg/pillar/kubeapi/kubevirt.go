// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package kubeapi

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	v1 "kubevirt.io/api/core/v1"
)

// KubevirtClientset interface representing what a clientset that understands kubevirt should implement
type KubevirtClientset interface {
	VirtualMachineInstance(namespace string) VirtualMachineInstanceInterface
}

type kubevirtClient struct {
	restClient *rest.RESTClient
	*kubernetes.Clientset
}

// VirtualMachineInstance returns a VirtualMachineInstanceInterface capable of interacting with the VirtualMachineInstance resource
func (k *kubevirtClient) VirtualMachineInstance(namespace string) VirtualMachineInstanceInterface {
	return &vmis{
		restClient: k.restClient,
		clientSet:  k.Clientset,
		namespace:  namespace,
		resource:   "virtualmachineinstances",
	}
}

// VirtualMachineInstanceInterface is an interface for interacting with the VirtualMachineInstance resource
type VirtualMachineInstanceInterface interface {
	Get(ctx context.Context, name string, options *metav1.GetOptions) (*v1.VirtualMachineInstance, error)
	List(ctx context.Context, opts *metav1.ListOptions) (*v1.VirtualMachineInstanceList, error)
	Create(ctx context.Context, instance *v1.VirtualMachineInstance) (*v1.VirtualMachineInstance, error)
	Update(ctx context.Context, instance *v1.VirtualMachineInstance) (*v1.VirtualMachineInstance, error)
	Delete(ctx context.Context, name string, options *metav1.DeleteOptions) error
}

type vmis struct {
	restClient *rest.RESTClient
	clientSet  *kubernetes.Clientset
	namespace  string
	resource   string
	master     string
	kubeconfig string
}

// Get returns a VirtualMachineInstance resource
func (v *vmis) Get(ctx context.Context, name string, options *metav1.GetOptions) (vmi *v1.VirtualMachineInstance, err error) {
	vmi = &v1.VirtualMachineInstance{}
	err = v.restClient.Get().
		Resource(v.resource).
		Namespace(v.namespace).
		Name(name).
		VersionedParams(options, scheme.ParameterCodec).
		Do(ctx).
		Into(vmi)
	vmi.SetGroupVersionKind(v1.VirtualMachineInstanceGroupVersionKind)
	return
}

// List returns a list of VirtualMachineInstance resources
func (v *vmis) List(ctx context.Context, options *metav1.ListOptions) (vmiList *v1.VirtualMachineInstanceList, err error) {
	vmiList = &v1.VirtualMachineInstanceList{}
	err = v.restClient.Get().
		Resource(v.resource).
		Namespace(v.namespace).
		VersionedParams(options, scheme.ParameterCodec).
		Do(ctx).
		Into(vmiList)
	for i := range vmiList.Items {
		vmiList.Items[i].SetGroupVersionKind(v1.VirtualMachineInstanceGroupVersionKind)
	}

	return
}

// Create creates a VirtualMachineInstance resource
func (v *vmis) Create(ctx context.Context, vmi *v1.VirtualMachineInstance) (result *v1.VirtualMachineInstance, err error) {
	result = &v1.VirtualMachineInstance{}
	err = v.restClient.Post().
		Namespace(v.namespace).
		Resource(v.resource).
		Body(vmi).
		Do(ctx).
		Into(result)
	result.SetGroupVersionKind(v1.VirtualMachineInstanceGroupVersionKind)
	return
}

// Update updates a VirtualMachineInstance resource
func (v *vmis) Update(ctx context.Context, vmi *v1.VirtualMachineInstance) (result *v1.VirtualMachineInstance, err error) {
	result = &v1.VirtualMachineInstance{}
	err = v.restClient.Put().
		Name(vmi.ObjectMeta.Name).
		Namespace(v.namespace).
		Resource(v.resource).
		Body(vmi).
		Do(ctx).
		Into(result)
	result.SetGroupVersionKind(v1.VirtualMachineInstanceGroupVersionKind)
	return
}

// Delete deletes a VirtualMachineInstance resource
func (v *vmis) Delete(ctx context.Context, name string, options *metav1.DeleteOptions) error {
	return v.restClient.Delete().
		Namespace(v.namespace).
		Resource(v.resource).
		Name(name).
		Body(options).
		Do(ctx).
		Error()
}
