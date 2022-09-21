// Copyright 2022 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	"time"

	v1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	scheme "antrea.io/antrea/pkg/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// SupportBundleCollectionsGetter has a method to return a SupportBundleCollectionInterface.
// A group's client should implement this interface.
type SupportBundleCollectionsGetter interface {
	SupportBundleCollections() SupportBundleCollectionInterface
}

// SupportBundleCollectionInterface has methods to work with SupportBundleCollection resources.
type SupportBundleCollectionInterface interface {
	Create(ctx context.Context, supportBundleCollection *v1alpha1.SupportBundleCollection, opts v1.CreateOptions) (*v1alpha1.SupportBundleCollection, error)
	Update(ctx context.Context, supportBundleCollection *v1alpha1.SupportBundleCollection, opts v1.UpdateOptions) (*v1alpha1.SupportBundleCollection, error)
	UpdateStatus(ctx context.Context, supportBundleCollection *v1alpha1.SupportBundleCollection, opts v1.UpdateOptions) (*v1alpha1.SupportBundleCollection, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.SupportBundleCollection, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.SupportBundleCollectionList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.SupportBundleCollection, err error)
	SupportBundleCollectionExpansion
}

// supportBundleCollections implements SupportBundleCollectionInterface
type supportBundleCollections struct {
	client rest.Interface
}

// newSupportBundleCollections returns a SupportBundleCollections
func newSupportBundleCollections(c *CrdV1alpha1Client) *supportBundleCollections {
	return &supportBundleCollections{
		client: c.RESTClient(),
	}
}

// Get takes name of the supportBundleCollection, and returns the corresponding supportBundleCollection object, and an error if there is any.
func (c *supportBundleCollections) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.SupportBundleCollection, err error) {
	result = &v1alpha1.SupportBundleCollection{}
	err = c.client.Get().
		Resource("supportbundlecollections").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of SupportBundleCollections that match those selectors.
func (c *supportBundleCollections) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.SupportBundleCollectionList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.SupportBundleCollectionList{}
	err = c.client.Get().
		Resource("supportbundlecollections").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested supportBundleCollections.
func (c *supportBundleCollections) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("supportbundlecollections").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a supportBundleCollection and creates it.  Returns the server's representation of the supportBundleCollection, and an error, if there is any.
func (c *supportBundleCollections) Create(ctx context.Context, supportBundleCollection *v1alpha1.SupportBundleCollection, opts v1.CreateOptions) (result *v1alpha1.SupportBundleCollection, err error) {
	result = &v1alpha1.SupportBundleCollection{}
	err = c.client.Post().
		Resource("supportbundlecollections").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(supportBundleCollection).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a supportBundleCollection and updates it. Returns the server's representation of the supportBundleCollection, and an error, if there is any.
func (c *supportBundleCollections) Update(ctx context.Context, supportBundleCollection *v1alpha1.SupportBundleCollection, opts v1.UpdateOptions) (result *v1alpha1.SupportBundleCollection, err error) {
	result = &v1alpha1.SupportBundleCollection{}
	err = c.client.Put().
		Resource("supportbundlecollections").
		Name(supportBundleCollection.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(supportBundleCollection).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *supportBundleCollections) UpdateStatus(ctx context.Context, supportBundleCollection *v1alpha1.SupportBundleCollection, opts v1.UpdateOptions) (result *v1alpha1.SupportBundleCollection, err error) {
	result = &v1alpha1.SupportBundleCollection{}
	err = c.client.Put().
		Resource("supportbundlecollections").
		Name(supportBundleCollection.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(supportBundleCollection).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the supportBundleCollection and deletes it. Returns an error if one occurs.
func (c *supportBundleCollections) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("supportbundlecollections").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *supportBundleCollections) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("supportbundlecollections").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched supportBundleCollection.
func (c *supportBundleCollections) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.SupportBundleCollection, err error) {
	result = &v1alpha1.SupportBundleCollection{}
	err = c.client.Patch(pt).
		Resource("supportbundlecollections").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}