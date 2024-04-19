//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// Copyright 2024 Antrea Authors
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

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BundleExternalNodes) DeepCopyInto(out *BundleExternalNodes) {
	*out = *in
	if in.NodeNames != nil {
		in, out := &in.NodeNames, &out.NodeNames
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.NodeSelector != nil {
		in, out := &in.NodeSelector, &out.NodeSelector
		*out = new(v1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BundleExternalNodes.
func (in *BundleExternalNodes) DeepCopy() *BundleExternalNodes {
	if in == nil {
		return nil
	}
	out := new(BundleExternalNodes)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BundleFileServer) DeepCopyInto(out *BundleFileServer) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BundleFileServer.
func (in *BundleFileServer) DeepCopy() *BundleFileServer {
	if in == nil {
		return nil
	}
	out := new(BundleFileServer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BundleNodes) DeepCopyInto(out *BundleNodes) {
	*out = *in
	if in.NodeNames != nil {
		in, out := &in.NodeNames, &out.NodeNames
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.NodeSelector != nil {
		in, out := &in.NodeSelector, &out.NodeSelector
		*out = new(v1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BundleNodes.
func (in *BundleNodes) DeepCopy() *BundleNodes {
	if in == nil {
		return nil
	}
	out := new(BundleNodes)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BundleServerAuthConfiguration) DeepCopyInto(out *BundleServerAuthConfiguration) {
	*out = *in
	if in.AuthSecret != nil {
		in, out := &in.AuthSecret, &out.AuthSecret
		*out = new(corev1.SecretReference)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BundleServerAuthConfiguration.
func (in *BundleServerAuthConfiguration) DeepCopy() *BundleServerAuthConfiguration {
	if in == nil {
		return nil
	}
	out := new(BundleServerAuthConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Destination) DeepCopyInto(out *Destination) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Destination.
func (in *Destination) DeepCopy() *Destination {
	if in == nil {
		return nil
	}
	out := new(Destination)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExternalNode) DeepCopyInto(out *ExternalNode) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExternalNode.
func (in *ExternalNode) DeepCopy() *ExternalNode {
	if in == nil {
		return nil
	}
	out := new(ExternalNode)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ExternalNode) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExternalNodeList) DeepCopyInto(out *ExternalNodeList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ExternalNode, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExternalNodeList.
func (in *ExternalNodeList) DeepCopy() *ExternalNodeList {
	if in == nil {
		return nil
	}
	out := new(ExternalNodeList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ExternalNodeList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExternalNodeSpec) DeepCopyInto(out *ExternalNodeSpec) {
	*out = *in
	if in.Interfaces != nil {
		in, out := &in.Interfaces, &out.Interfaces
		*out = make([]NetworkInterface, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExternalNodeSpec.
func (in *ExternalNodeSpec) DeepCopy() *ExternalNodeSpec {
	if in == nil {
		return nil
	}
	out := new(ExternalNodeSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HTTPProtocol) DeepCopyInto(out *HTTPProtocol) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HTTPProtocol.
func (in *HTTPProtocol) DeepCopy() *HTTPProtocol {
	if in == nil {
		return nil
	}
	out := new(HTTPProtocol)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ICMPEchoRequestHeader) DeepCopyInto(out *ICMPEchoRequestHeader) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ICMPEchoRequestHeader.
func (in *ICMPEchoRequestHeader) DeepCopy() *ICMPEchoRequestHeader {
	if in == nil {
		return nil
	}
	out := new(ICMPEchoRequestHeader)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPBlock) DeepCopyInto(out *IPBlock) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPBlock.
func (in *IPBlock) DeepCopy() *IPBlock {
	if in == nil {
		return nil
	}
	out := new(IPBlock)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPHeader) DeepCopyInto(out *IPHeader) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPHeader.
func (in *IPHeader) DeepCopy() *IPHeader {
	if in == nil {
		return nil
	}
	out := new(IPHeader)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPv6Header) DeepCopyInto(out *IPv6Header) {
	*out = *in
	if in.NextHeader != nil {
		in, out := &in.NextHeader, &out.NextHeader
		*out = new(int32)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPv6Header.
func (in *IPv6Header) DeepCopy() *IPv6Header {
	if in == nil {
		return nil
	}
	out := new(IPv6Header)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *L7Protocol) DeepCopyInto(out *L7Protocol) {
	*out = *in
	if in.HTTP != nil {
		in, out := &in.HTTP, &out.HTTP
		*out = new(HTTPProtocol)
		**out = **in
	}
	if in.TLS != nil {
		in, out := &in.TLS, &out.TLS
		*out = new(TLSProtocol)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new L7Protocol.
func (in *L7Protocol) DeepCopy() *L7Protocol {
	if in == nil {
		return nil
	}
	out := new(L7Protocol)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NamespacedName) DeepCopyInto(out *NamespacedName) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NamespacedName.
func (in *NamespacedName) DeepCopy() *NamespacedName {
	if in == nil {
		return nil
	}
	out := new(NamespacedName)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NetworkInterface) DeepCopyInto(out *NetworkInterface) {
	*out = *in
	if in.IPs != nil {
		in, out := &in.IPs, &out.IPs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NetworkInterface.
func (in *NetworkInterface) DeepCopy() *NetworkInterface {
	if in == nil {
		return nil
	}
	out := new(NetworkInterface)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Packet) DeepCopyInto(out *Packet) {
	*out = *in
	out.IPHeader = in.IPHeader
	if in.IPv6Header != nil {
		in, out := &in.IPv6Header, &out.IPv6Header
		*out = new(IPv6Header)
		(*in).DeepCopyInto(*out)
	}
	in.TransportHeader.DeepCopyInto(&out.TransportHeader)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Packet.
func (in *Packet) DeepCopy() *Packet {
	if in == nil {
		return nil
	}
	out := new(Packet)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PacketCapture) DeepCopyInto(out *PacketCapture) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PacketCapture.
func (in *PacketCapture) DeepCopy() *PacketCapture {
	if in == nil {
		return nil
	}
	out := new(PacketCapture)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *PacketCapture) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PacketCaptureFirstNConfig) DeepCopyInto(out *PacketCaptureFirstNConfig) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PacketCaptureFirstNConfig.
func (in *PacketCaptureFirstNConfig) DeepCopy() *PacketCaptureFirstNConfig {
	if in == nil {
		return nil
	}
	out := new(PacketCaptureFirstNConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PacketCaptureList) DeepCopyInto(out *PacketCaptureList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]PacketCapture, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PacketCaptureList.
func (in *PacketCaptureList) DeepCopy() *PacketCaptureList {
	if in == nil {
		return nil
	}
	out := new(PacketCaptureList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *PacketCaptureList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PacketCaptureSpec) DeepCopyInto(out *PacketCaptureSpec) {
	*out = *in
	if in.FirstNCaptureConfig != nil {
		in, out := &in.FirstNCaptureConfig, &out.FirstNCaptureConfig
		*out = new(PacketCaptureFirstNConfig)
		**out = **in
	}
	out.Source = in.Source
	out.Destination = in.Destination
	in.Packet.DeepCopyInto(&out.Packet)
	out.FileServer = in.FileServer
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PacketCaptureSpec.
func (in *PacketCaptureSpec) DeepCopy() *PacketCaptureSpec {
	if in == nil {
		return nil
	}
	out := new(PacketCaptureSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PacketCaptureStatus) DeepCopyInto(out *PacketCaptureStatus) {
	*out = *in
	if in.StartTime != nil {
		in, out := &in.StartTime, &out.StartTime
		*out = (*in).DeepCopy()
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PacketCaptureStatus.
func (in *PacketCaptureStatus) DeepCopy() *PacketCaptureStatus {
	if in == nil {
		return nil
	}
	out := new(PacketCaptureStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Source) DeepCopyInto(out *Source) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Source.
func (in *Source) DeepCopy() *Source {
	if in == nil {
		return nil
	}
	out := new(Source)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SupportBundleCollection) DeepCopyInto(out *SupportBundleCollection) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SupportBundleCollection.
func (in *SupportBundleCollection) DeepCopy() *SupportBundleCollection {
	if in == nil {
		return nil
	}
	out := new(SupportBundleCollection)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *SupportBundleCollection) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SupportBundleCollectionCondition) DeepCopyInto(out *SupportBundleCollectionCondition) {
	*out = *in
	in.LastTransitionTime.DeepCopyInto(&out.LastTransitionTime)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SupportBundleCollectionCondition.
func (in *SupportBundleCollectionCondition) DeepCopy() *SupportBundleCollectionCondition {
	if in == nil {
		return nil
	}
	out := new(SupportBundleCollectionCondition)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SupportBundleCollectionList) DeepCopyInto(out *SupportBundleCollectionList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]SupportBundleCollection, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SupportBundleCollectionList.
func (in *SupportBundleCollectionList) DeepCopy() *SupportBundleCollectionList {
	if in == nil {
		return nil
	}
	out := new(SupportBundleCollectionList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *SupportBundleCollectionList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SupportBundleCollectionSpec) DeepCopyInto(out *SupportBundleCollectionSpec) {
	*out = *in
	if in.Nodes != nil {
		in, out := &in.Nodes, &out.Nodes
		*out = new(BundleNodes)
		(*in).DeepCopyInto(*out)
	}
	if in.ExternalNodes != nil {
		in, out := &in.ExternalNodes, &out.ExternalNodes
		*out = new(BundleExternalNodes)
		(*in).DeepCopyInto(*out)
	}
	out.FileServer = in.FileServer
	in.Authentication.DeepCopyInto(&out.Authentication)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SupportBundleCollectionSpec.
func (in *SupportBundleCollectionSpec) DeepCopy() *SupportBundleCollectionSpec {
	if in == nil {
		return nil
	}
	out := new(SupportBundleCollectionSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SupportBundleCollectionStatus) DeepCopyInto(out *SupportBundleCollectionStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]SupportBundleCollectionCondition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SupportBundleCollectionStatus.
func (in *SupportBundleCollectionStatus) DeepCopy() *SupportBundleCollectionStatus {
	if in == nil {
		return nil
	}
	out := new(SupportBundleCollectionStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TCPHeader) DeepCopyInto(out *TCPHeader) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TCPHeader.
func (in *TCPHeader) DeepCopy() *TCPHeader {
	if in == nil {
		return nil
	}
	out := new(TCPHeader)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLSProtocol) DeepCopyInto(out *TLSProtocol) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLSProtocol.
func (in *TLSProtocol) DeepCopy() *TLSProtocol {
	if in == nil {
		return nil
	}
	out := new(TLSProtocol)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TransportHeader) DeepCopyInto(out *TransportHeader) {
	*out = *in
	if in.ICMP != nil {
		in, out := &in.ICMP, &out.ICMP
		*out = new(ICMPEchoRequestHeader)
		**out = **in
	}
	if in.UDP != nil {
		in, out := &in.UDP, &out.UDP
		*out = new(UDPHeader)
		**out = **in
	}
	if in.TCP != nil {
		in, out := &in.TCP, &out.TCP
		*out = new(TCPHeader)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TransportHeader.
func (in *TransportHeader) DeepCopy() *TransportHeader {
	if in == nil {
		return nil
	}
	out := new(TransportHeader)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UDPHeader) DeepCopyInto(out *UDPHeader) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UDPHeader.
func (in *UDPHeader) DeepCopy() *UDPHeader {
	if in == nil {
		return nil
	}
	out := new(UDPHeader)
	in.DeepCopyInto(out)
	return out
}
