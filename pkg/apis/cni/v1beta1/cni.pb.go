// Copyright 2019 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v5.26.0
// source: pkg/apis/cni/v1beta1/cni.proto

package v1beta1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	anypb "google.golang.org/protobuf/types/known/anypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ErrorCode int32

const (
	ErrorCode_UNKNOWN                       ErrorCode = 0
	ErrorCode_INCOMPATIBLE_CNI_VERSION      ErrorCode = 1
	ErrorCode_UNSUPPORTED_FIELD             ErrorCode = 2
	ErrorCode_UNKNOWN_CONTAINER             ErrorCode = 3
	ErrorCode_INVALID_ENVIRONMENT_VARIABLES ErrorCode = 4
	ErrorCode_IO_FAILURE                    ErrorCode = 5
	ErrorCode_DECODING_FAILURE              ErrorCode = 6
	ErrorCode_INVALID_NETWORK_CONFIG        ErrorCode = 7
	ErrorCode_TRY_AGAIN_LATER               ErrorCode = 11
	ErrorCode_IPAM_FAILURE                  ErrorCode = 101
	ErrorCode_CONFIG_INTERFACE_FAILURE      ErrorCode = 102
	ErrorCode_CHECK_INTERFACE_FAILURE       ErrorCode = 103
	// these errors are not used by the servers, but we declare them here to
	// make sure they are reserved.
	ErrorCode_UNKNOWN_RPC_ERROR        ErrorCode = 201
	ErrorCode_INCOMPATIBLE_API_VERSION ErrorCode = 202
)

// Enum value maps for ErrorCode.
var (
	ErrorCode_name = map[int32]string{
		0:   "UNKNOWN",
		1:   "INCOMPATIBLE_CNI_VERSION",
		2:   "UNSUPPORTED_FIELD",
		3:   "UNKNOWN_CONTAINER",
		4:   "INVALID_ENVIRONMENT_VARIABLES",
		5:   "IO_FAILURE",
		6:   "DECODING_FAILURE",
		7:   "INVALID_NETWORK_CONFIG",
		11:  "TRY_AGAIN_LATER",
		101: "IPAM_FAILURE",
		102: "CONFIG_INTERFACE_FAILURE",
		103: "CHECK_INTERFACE_FAILURE",
		201: "UNKNOWN_RPC_ERROR",
		202: "INCOMPATIBLE_API_VERSION",
	}
	ErrorCode_value = map[string]int32{
		"UNKNOWN":                       0,
		"INCOMPATIBLE_CNI_VERSION":      1,
		"UNSUPPORTED_FIELD":             2,
		"UNKNOWN_CONTAINER":             3,
		"INVALID_ENVIRONMENT_VARIABLES": 4,
		"IO_FAILURE":                    5,
		"DECODING_FAILURE":              6,
		"INVALID_NETWORK_CONFIG":        7,
		"TRY_AGAIN_LATER":               11,
		"IPAM_FAILURE":                  101,
		"CONFIG_INTERFACE_FAILURE":      102,
		"CHECK_INTERFACE_FAILURE":       103,
		"UNKNOWN_RPC_ERROR":             201,
		"INCOMPATIBLE_API_VERSION":      202,
	}
)

func (x ErrorCode) Enum() *ErrorCode {
	p := new(ErrorCode)
	*p = x
	return p
}

func (x ErrorCode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ErrorCode) Descriptor() protoreflect.EnumDescriptor {
	return file_pkg_apis_cni_v1beta1_cni_proto_enumTypes[0].Descriptor()
}

func (ErrorCode) Type() protoreflect.EnumType {
	return &file_pkg_apis_cni_v1beta1_cni_proto_enumTypes[0]
}

func (x ErrorCode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ErrorCode.Descriptor instead.
func (ErrorCode) EnumDescriptor() ([]byte, []int) {
	return file_pkg_apis_cni_v1beta1_cni_proto_rawDescGZIP(), []int{0}
}

type CniCmdArgs struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ContainerId          string `protobuf:"bytes,1,opt,name=container_id,json=containerId,proto3" json:"container_id,omitempty"`
	Netns                string `protobuf:"bytes,2,opt,name=netns,proto3" json:"netns,omitempty"`
	Ifname               string `protobuf:"bytes,3,opt,name=ifname,proto3" json:"ifname,omitempty"`
	Args                 string `protobuf:"bytes,4,opt,name=args,proto3" json:"args,omitempty"`
	Path                 string `protobuf:"bytes,5,opt,name=path,proto3" json:"path,omitempty"`
	NetworkConfiguration []byte `protobuf:"bytes,6,opt,name=network_configuration,json=networkConfiguration,proto3" json:"network_configuration,omitempty"`
}

func (x *CniCmdArgs) Reset() {
	*x = CniCmdArgs{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_apis_cni_v1beta1_cni_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CniCmdArgs) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CniCmdArgs) ProtoMessage() {}

func (x *CniCmdArgs) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_apis_cni_v1beta1_cni_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CniCmdArgs.ProtoReflect.Descriptor instead.
func (*CniCmdArgs) Descriptor() ([]byte, []int) {
	return file_pkg_apis_cni_v1beta1_cni_proto_rawDescGZIP(), []int{0}
}

func (x *CniCmdArgs) GetContainerId() string {
	if x != nil {
		return x.ContainerId
	}
	return ""
}

func (x *CniCmdArgs) GetNetns() string {
	if x != nil {
		return x.Netns
	}
	return ""
}

func (x *CniCmdArgs) GetIfname() string {
	if x != nil {
		return x.Ifname
	}
	return ""
}

func (x *CniCmdArgs) GetArgs() string {
	if x != nil {
		return x.Args
	}
	return ""
}

func (x *CniCmdArgs) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *CniCmdArgs) GetNetworkConfiguration() []byte {
	if x != nil {
		return x.NetworkConfiguration
	}
	return nil
}

type CniCmdRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CniArgs *CniCmdArgs `protobuf:"bytes,1,opt,name=cni_args,json=cniArgs,proto3" json:"cni_args,omitempty"`
}

func (x *CniCmdRequest) Reset() {
	*x = CniCmdRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_apis_cni_v1beta1_cni_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CniCmdRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CniCmdRequest) ProtoMessage() {}

func (x *CniCmdRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_apis_cni_v1beta1_cni_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CniCmdRequest.ProtoReflect.Descriptor instead.
func (*CniCmdRequest) Descriptor() ([]byte, []int) {
	return file_pkg_apis_cni_v1beta1_cni_proto_rawDescGZIP(), []int{1}
}

func (x *CniCmdRequest) GetCniArgs() *CniCmdArgs {
	if x != nil {
		return x.CniArgs
	}
	return nil
}

type Error struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Code    ErrorCode    `protobuf:"varint,1,opt,name=code,proto3,enum=antrea_io.antrea.pkg.apis.cni.v1beta1.ErrorCode" json:"code,omitempty"`
	Message string       `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	Details []*anypb.Any `protobuf:"bytes,3,rep,name=details,proto3" json:"details,omitempty"`
}

func (x *Error) Reset() {
	*x = Error{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_apis_cni_v1beta1_cni_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Error) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Error) ProtoMessage() {}

func (x *Error) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_apis_cni_v1beta1_cni_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Error.ProtoReflect.Descriptor instead.
func (*Error) Descriptor() ([]byte, []int) {
	return file_pkg_apis_cni_v1beta1_cni_proto_rawDescGZIP(), []int{2}
}

func (x *Error) GetCode() ErrorCode {
	if x != nil {
		return x.Code
	}
	return ErrorCode_UNKNOWN
}

func (x *Error) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

func (x *Error) GetDetails() []*anypb.Any {
	if x != nil {
		return x.Details
	}
	return nil
}

type CniCmdResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CniResult []byte `protobuf:"bytes,1,opt,name=cni_result,json=cniResult,proto3" json:"cni_result,omitempty"`
	Error     *Error `protobuf:"bytes,2,opt,name=error,proto3" json:"error,omitempty"`
}

func (x *CniCmdResponse) Reset() {
	*x = CniCmdResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_apis_cni_v1beta1_cni_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CniCmdResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CniCmdResponse) ProtoMessage() {}

func (x *CniCmdResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_apis_cni_v1beta1_cni_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CniCmdResponse.ProtoReflect.Descriptor instead.
func (*CniCmdResponse) Descriptor() ([]byte, []int) {
	return file_pkg_apis_cni_v1beta1_cni_proto_rawDescGZIP(), []int{3}
}

func (x *CniCmdResponse) GetCniResult() []byte {
	if x != nil {
		return x.CniResult
	}
	return nil
}

func (x *CniCmdResponse) GetError() *Error {
	if x != nil {
		return x.Error
	}
	return nil
}

var File_pkg_apis_cni_v1beta1_cni_proto protoreflect.FileDescriptor

var file_pkg_apis_cni_v1beta1_cni_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x70, 0x6b, 0x67, 0x2f, 0x61, 0x70, 0x69, 0x73, 0x2f, 0x63, 0x6e, 0x69, 0x2f, 0x76,
	0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x63, 0x6e, 0x69, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x25, 0x61, 0x6e, 0x74, 0x72, 0x65, 0x61, 0x5f, 0x69, 0x6f, 0x2e, 0x61, 0x6e, 0x74, 0x72,
	0x65, 0x61, 0x2e, 0x70, 0x6b, 0x67, 0x2e, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6e, 0x69, 0x2e,
	0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xba, 0x01, 0x0a, 0x0a, 0x43, 0x6e, 0x69, 0x43, 0x6d, 0x64, 0x41, 0x72, 0x67,
	0x73, 0x12, 0x21, 0x0a, 0x0c, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x5f, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e,
	0x65, 0x72, 0x49, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x6e, 0x65, 0x74, 0x6e, 0x73, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x05, 0x6e, 0x65, 0x74, 0x6e, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x69, 0x66,
	0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x69, 0x66, 0x6e, 0x61,
	0x6d, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x61, 0x72, 0x67, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x61, 0x72, 0x67, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x61, 0x74, 0x68, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x70, 0x61, 0x74, 0x68, 0x12, 0x33, 0x0a, 0x15, 0x6e, 0x65,
	0x74, 0x77, 0x6f, 0x72, 0x6b, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x14, 0x6e, 0x65, 0x74, 0x77, 0x6f,
	0x72, 0x6b, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22,
	0x5d, 0x0a, 0x0d, 0x43, 0x6e, 0x69, 0x43, 0x6d, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x4c, 0x0a, 0x08, 0x63, 0x6e, 0x69, 0x5f, 0x61, 0x72, 0x67, 0x73, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x31, 0x2e, 0x61, 0x6e, 0x74, 0x72, 0x65, 0x61, 0x5f, 0x69, 0x6f, 0x2e, 0x61,
	0x6e, 0x74, 0x72, 0x65, 0x61, 0x2e, 0x70, 0x6b, 0x67, 0x2e, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63,
	0x6e, 0x69, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x43, 0x6e, 0x69, 0x43, 0x6d,
	0x64, 0x41, 0x72, 0x67, 0x73, 0x52, 0x07, 0x63, 0x6e, 0x69, 0x41, 0x72, 0x67, 0x73, 0x22, 0x97,
	0x01, 0x0a, 0x05, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x44, 0x0a, 0x04, 0x63, 0x6f, 0x64, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x30, 0x2e, 0x61, 0x6e, 0x74, 0x72, 0x65, 0x61, 0x5f,
	0x69, 0x6f, 0x2e, 0x61, 0x6e, 0x74, 0x72, 0x65, 0x61, 0x2e, 0x70, 0x6b, 0x67, 0x2e, 0x61, 0x70,
	0x69, 0x73, 0x2e, 0x63, 0x6e, 0x69, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x45,
	0x72, 0x72, 0x6f, 0x72, 0x43, 0x6f, 0x64, 0x65, 0x52, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x12, 0x18,
	0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x2e, 0x0a, 0x07, 0x64, 0x65, 0x74, 0x61,
	0x69, 0x6c, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e, 0x79, 0x52,
	0x07, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x22, 0x73, 0x0a, 0x0e, 0x43, 0x6e, 0x69, 0x43,
	0x6d, 0x64, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x6e,
	0x69, 0x5f, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09,
	0x63, 0x6e, 0x69, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x42, 0x0a, 0x05, 0x65, 0x72, 0x72,
	0x6f, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2c, 0x2e, 0x61, 0x6e, 0x74, 0x72, 0x65,
	0x61, 0x5f, 0x69, 0x6f, 0x2e, 0x61, 0x6e, 0x74, 0x72, 0x65, 0x61, 0x2e, 0x70, 0x6b, 0x67, 0x2e,
	0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6e, 0x69, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31,
	0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x2a, 0xe2, 0x02,
	0x0a, 0x09, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x43, 0x6f, 0x64, 0x65, 0x12, 0x0b, 0x0a, 0x07, 0x55,
	0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x00, 0x12, 0x1c, 0x0a, 0x18, 0x49, 0x4e, 0x43, 0x4f,
	0x4d, 0x50, 0x41, 0x54, 0x49, 0x42, 0x4c, 0x45, 0x5f, 0x43, 0x4e, 0x49, 0x5f, 0x56, 0x45, 0x52,
	0x53, 0x49, 0x4f, 0x4e, 0x10, 0x01, 0x12, 0x15, 0x0a, 0x11, 0x55, 0x4e, 0x53, 0x55, 0x50, 0x50,
	0x4f, 0x52, 0x54, 0x45, 0x44, 0x5f, 0x46, 0x49, 0x45, 0x4c, 0x44, 0x10, 0x02, 0x12, 0x15, 0x0a,
	0x11, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x5f, 0x43, 0x4f, 0x4e, 0x54, 0x41, 0x49, 0x4e,
	0x45, 0x52, 0x10, 0x03, 0x12, 0x21, 0x0a, 0x1d, 0x49, 0x4e, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x5f,
	0x45, 0x4e, 0x56, 0x49, 0x52, 0x4f, 0x4e, 0x4d, 0x45, 0x4e, 0x54, 0x5f, 0x56, 0x41, 0x52, 0x49,
	0x41, 0x42, 0x4c, 0x45, 0x53, 0x10, 0x04, 0x12, 0x0e, 0x0a, 0x0a, 0x49, 0x4f, 0x5f, 0x46, 0x41,
	0x49, 0x4c, 0x55, 0x52, 0x45, 0x10, 0x05, 0x12, 0x14, 0x0a, 0x10, 0x44, 0x45, 0x43, 0x4f, 0x44,
	0x49, 0x4e, 0x47, 0x5f, 0x46, 0x41, 0x49, 0x4c, 0x55, 0x52, 0x45, 0x10, 0x06, 0x12, 0x1a, 0x0a,
	0x16, 0x49, 0x4e, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x5f, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b,
	0x5f, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x10, 0x07, 0x12, 0x13, 0x0a, 0x0f, 0x54, 0x52, 0x59,
	0x5f, 0x41, 0x47, 0x41, 0x49, 0x4e, 0x5f, 0x4c, 0x41, 0x54, 0x45, 0x52, 0x10, 0x0b, 0x12, 0x10,
	0x0a, 0x0c, 0x49, 0x50, 0x41, 0x4d, 0x5f, 0x46, 0x41, 0x49, 0x4c, 0x55, 0x52, 0x45, 0x10, 0x65,
	0x12, 0x1c, 0x0a, 0x18, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47, 0x5f, 0x49, 0x4e, 0x54, 0x45, 0x52,
	0x46, 0x41, 0x43, 0x45, 0x5f, 0x46, 0x41, 0x49, 0x4c, 0x55, 0x52, 0x45, 0x10, 0x66, 0x12, 0x1b,
	0x0a, 0x17, 0x43, 0x48, 0x45, 0x43, 0x4b, 0x5f, 0x49, 0x4e, 0x54, 0x45, 0x52, 0x46, 0x41, 0x43,
	0x45, 0x5f, 0x46, 0x41, 0x49, 0x4c, 0x55, 0x52, 0x45, 0x10, 0x67, 0x12, 0x16, 0x0a, 0x11, 0x55,
	0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x5f, 0x52, 0x50, 0x43, 0x5f, 0x45, 0x52, 0x52, 0x4f, 0x52,
	0x10, 0xc9, 0x01, 0x12, 0x1d, 0x0a, 0x18, 0x49, 0x4e, 0x43, 0x4f, 0x4d, 0x50, 0x41, 0x54, 0x49,
	0x42, 0x4c, 0x45, 0x5f, 0x41, 0x50, 0x49, 0x5f, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4f, 0x4e, 0x10,
	0xca, 0x01, 0x32, 0xf2, 0x02, 0x0a, 0x03, 0x43, 0x6e, 0x69, 0x12, 0x77, 0x0a, 0x06, 0x43, 0x6d,
	0x64, 0x41, 0x64, 0x64, 0x12, 0x34, 0x2e, 0x61, 0x6e, 0x74, 0x72, 0x65, 0x61, 0x5f, 0x69, 0x6f,
	0x2e, 0x61, 0x6e, 0x74, 0x72, 0x65, 0x61, 0x2e, 0x70, 0x6b, 0x67, 0x2e, 0x61, 0x70, 0x69, 0x73,
	0x2e, 0x63, 0x6e, 0x69, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x43, 0x6e, 0x69,
	0x43, 0x6d, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x35, 0x2e, 0x61, 0x6e, 0x74,
	0x72, 0x65, 0x61, 0x5f, 0x69, 0x6f, 0x2e, 0x61, 0x6e, 0x74, 0x72, 0x65, 0x61, 0x2e, 0x70, 0x6b,
	0x67, 0x2e, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6e, 0x69, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74,
	0x61, 0x31, 0x2e, 0x43, 0x6e, 0x69, 0x43, 0x6d, 0x64, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x22, 0x00, 0x12, 0x79, 0x0a, 0x08, 0x43, 0x6d, 0x64, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x12,
	0x34, 0x2e, 0x61, 0x6e, 0x74, 0x72, 0x65, 0x61, 0x5f, 0x69, 0x6f, 0x2e, 0x61, 0x6e, 0x74, 0x72,
	0x65, 0x61, 0x2e, 0x70, 0x6b, 0x67, 0x2e, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6e, 0x69, 0x2e,
	0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x43, 0x6e, 0x69, 0x43, 0x6d, 0x64, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x35, 0x2e, 0x61, 0x6e, 0x74, 0x72, 0x65, 0x61, 0x5f, 0x69,
	0x6f, 0x2e, 0x61, 0x6e, 0x74, 0x72, 0x65, 0x61, 0x2e, 0x70, 0x6b, 0x67, 0x2e, 0x61, 0x70, 0x69,
	0x73, 0x2e, 0x63, 0x6e, 0x69, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x43, 0x6e,
	0x69, 0x43, 0x6d, 0x64, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x77,
	0x0a, 0x06, 0x43, 0x6d, 0x64, 0x44, 0x65, 0x6c, 0x12, 0x34, 0x2e, 0x61, 0x6e, 0x74, 0x72, 0x65,
	0x61, 0x5f, 0x69, 0x6f, 0x2e, 0x61, 0x6e, 0x74, 0x72, 0x65, 0x61, 0x2e, 0x70, 0x6b, 0x67, 0x2e,
	0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6e, 0x69, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31,
	0x2e, 0x43, 0x6e, 0x69, 0x43, 0x6d, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x35,
	0x2e, 0x61, 0x6e, 0x74, 0x72, 0x65, 0x61, 0x5f, 0x69, 0x6f, 0x2e, 0x61, 0x6e, 0x74, 0x72, 0x65,
	0x61, 0x2e, 0x70, 0x6b, 0x67, 0x2e, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6e, 0x69, 0x2e, 0x76,
	0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x43, 0x6e, 0x69, 0x43, 0x6d, 0x64, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x16, 0x5a, 0x14, 0x70, 0x6b, 0x67, 0x2f, 0x61,
	0x70, 0x69, 0x73, 0x2f, 0x63, 0x6e, 0x69, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_pkg_apis_cni_v1beta1_cni_proto_rawDescOnce sync.Once
	file_pkg_apis_cni_v1beta1_cni_proto_rawDescData = file_pkg_apis_cni_v1beta1_cni_proto_rawDesc
)

func file_pkg_apis_cni_v1beta1_cni_proto_rawDescGZIP() []byte {
	file_pkg_apis_cni_v1beta1_cni_proto_rawDescOnce.Do(func() {
		file_pkg_apis_cni_v1beta1_cni_proto_rawDescData = protoimpl.X.CompressGZIP(file_pkg_apis_cni_v1beta1_cni_proto_rawDescData)
	})
	return file_pkg_apis_cni_v1beta1_cni_proto_rawDescData
}

var file_pkg_apis_cni_v1beta1_cni_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_pkg_apis_cni_v1beta1_cni_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_pkg_apis_cni_v1beta1_cni_proto_goTypes = []interface{}{
	(ErrorCode)(0),         // 0: antrea_io.antrea.pkg.apis.cni.v1beta1.ErrorCode
	(*CniCmdArgs)(nil),     // 1: antrea_io.antrea.pkg.apis.cni.v1beta1.CniCmdArgs
	(*CniCmdRequest)(nil),  // 2: antrea_io.antrea.pkg.apis.cni.v1beta1.CniCmdRequest
	(*Error)(nil),          // 3: antrea_io.antrea.pkg.apis.cni.v1beta1.Error
	(*CniCmdResponse)(nil), // 4: antrea_io.antrea.pkg.apis.cni.v1beta1.CniCmdResponse
	(*anypb.Any)(nil),      // 5: google.protobuf.Any
}
var file_pkg_apis_cni_v1beta1_cni_proto_depIdxs = []int32{
	1, // 0: antrea_io.antrea.pkg.apis.cni.v1beta1.CniCmdRequest.cni_args:type_name -> antrea_io.antrea.pkg.apis.cni.v1beta1.CniCmdArgs
	0, // 1: antrea_io.antrea.pkg.apis.cni.v1beta1.Error.code:type_name -> antrea_io.antrea.pkg.apis.cni.v1beta1.ErrorCode
	5, // 2: antrea_io.antrea.pkg.apis.cni.v1beta1.Error.details:type_name -> google.protobuf.Any
	3, // 3: antrea_io.antrea.pkg.apis.cni.v1beta1.CniCmdResponse.error:type_name -> antrea_io.antrea.pkg.apis.cni.v1beta1.Error
	2, // 4: antrea_io.antrea.pkg.apis.cni.v1beta1.Cni.CmdAdd:input_type -> antrea_io.antrea.pkg.apis.cni.v1beta1.CniCmdRequest
	2, // 5: antrea_io.antrea.pkg.apis.cni.v1beta1.Cni.CmdCheck:input_type -> antrea_io.antrea.pkg.apis.cni.v1beta1.CniCmdRequest
	2, // 6: antrea_io.antrea.pkg.apis.cni.v1beta1.Cni.CmdDel:input_type -> antrea_io.antrea.pkg.apis.cni.v1beta1.CniCmdRequest
	4, // 7: antrea_io.antrea.pkg.apis.cni.v1beta1.Cni.CmdAdd:output_type -> antrea_io.antrea.pkg.apis.cni.v1beta1.CniCmdResponse
	4, // 8: antrea_io.antrea.pkg.apis.cni.v1beta1.Cni.CmdCheck:output_type -> antrea_io.antrea.pkg.apis.cni.v1beta1.CniCmdResponse
	4, // 9: antrea_io.antrea.pkg.apis.cni.v1beta1.Cni.CmdDel:output_type -> antrea_io.antrea.pkg.apis.cni.v1beta1.CniCmdResponse
	7, // [7:10] is the sub-list for method output_type
	4, // [4:7] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_pkg_apis_cni_v1beta1_cni_proto_init() }
func file_pkg_apis_cni_v1beta1_cni_proto_init() {
	if File_pkg_apis_cni_v1beta1_cni_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pkg_apis_cni_v1beta1_cni_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CniCmdArgs); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_apis_cni_v1beta1_cni_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CniCmdRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_apis_cni_v1beta1_cni_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Error); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_apis_cni_v1beta1_cni_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CniCmdResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_pkg_apis_cni_v1beta1_cni_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_pkg_apis_cni_v1beta1_cni_proto_goTypes,
		DependencyIndexes: file_pkg_apis_cni_v1beta1_cni_proto_depIdxs,
		EnumInfos:         file_pkg_apis_cni_v1beta1_cni_proto_enumTypes,
		MessageInfos:      file_pkg_apis_cni_v1beta1_cni_proto_msgTypes,
	}.Build()
	File_pkg_apis_cni_v1beta1_cni_proto = out.File
	file_pkg_apis_cni_v1beta1_cni_proto_rawDesc = nil
	file_pkg_apis_cni_v1beta1_cni_proto_goTypes = nil
	file_pkg_apis_cni_v1beta1_cni_proto_depIdxs = nil
}
