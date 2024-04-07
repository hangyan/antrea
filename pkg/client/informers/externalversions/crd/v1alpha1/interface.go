// Copyright 2023 Antrea Authors
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

// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	internalinterfaces "antrea.io/antrea/pkg/client/informers/externalversions/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// ClusterNetworkPolicies returns a ClusterNetworkPolicyInformer.
	ClusterNetworkPolicies() ClusterNetworkPolicyInformer
	// ExternalNodes returns a ExternalNodeInformer.
	ExternalNodes() ExternalNodeInformer
	// NetworkPolicies returns a NetworkPolicyInformer.
	NetworkPolicies() NetworkPolicyInformer
	// PacketSamplings returns a PacketSamplingInformer.
	PacketSamplings() PacketSamplingInformer
	// SupportBundleCollections returns a SupportBundleCollectionInformer.
	SupportBundleCollections() SupportBundleCollectionInformer
	// Tiers returns a TierInformer.
	Tiers() TierInformer
	// Traceflows returns a TraceflowInformer.
	Traceflows() TraceflowInformer
}

type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// ClusterNetworkPolicies returns a ClusterNetworkPolicyInformer.
func (v *version) ClusterNetworkPolicies() ClusterNetworkPolicyInformer {
	return &clusterNetworkPolicyInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// ExternalNodes returns a ExternalNodeInformer.
func (v *version) ExternalNodes() ExternalNodeInformer {
	return &externalNodeInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// NetworkPolicies returns a NetworkPolicyInformer.
func (v *version) NetworkPolicies() NetworkPolicyInformer {
	return &networkPolicyInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// PacketSamplings returns a PacketSamplingInformer.
func (v *version) PacketSamplings() PacketSamplingInformer {
	return &packetSamplingInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// SupportBundleCollections returns a SupportBundleCollectionInformer.
func (v *version) SupportBundleCollections() SupportBundleCollectionInformer {
	return &supportBundleCollectionInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// Tiers returns a TierInformer.
func (v *version) Tiers() TierInformer {
	return &tierInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// Traceflows returns a TraceflowInformer.
func (v *version) Traceflows() TraceflowInformer {
	return &traceflowInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}
