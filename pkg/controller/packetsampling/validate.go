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

package packetsampling

import (
	"encoding/json"
	"fmt"
	"net"

	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/util/ftp"
)

func Validate(review *admv1.AdmissionReview) *admv1.AdmissionResponse {
	newResponse := func(allowed bool, deniedReason string) *admv1.AdmissionResponse {
		resp := &admv1.AdmissionResponse{
			UID:     review.Request.UID,
			Allowed: allowed,
		}
		if !allowed {
			resp.Result = &metav1.Status{
				Message: deniedReason,
			}
		}
		return resp
	}

	klog.V(2).InfoS("Validating PacketCapture", "request", review.Request)

	var newObj crdv1alpha1.PacketCapture
	if review.Request.Object.Raw != nil {
		if err := json.Unmarshal(review.Request.Object.Raw, &newObj); err != nil {
			klog.ErrorS(err, "Error de-serializing current Traceflow")
			return newResponse(false, err.Error())
		}
	}

	switch review.Request.Operation {
	case admv1.Create:
		klog.V(2).InfoS("Validating CREATE request for PacketCapture", "name", newObj.Name)
		allowed, deniedReason := validate(&newObj)
		return newResponse(allowed, deniedReason)
	case admv1.Update:
		klog.V(2).InfoS("Validating UPDATE request for PacketCapture", "name", newObj.Name)
		allowed, deniedReason := validate(&newObj)
		return newResponse(allowed, deniedReason)
	default:
		err := fmt.Errorf("invalid request operation %s for Traceflow", review.Request.Operation)
		klog.ErrorS(err, "Failed to validate PacketCapture", "name", newObj.Name)
		return newResponse(false, err.Error())
	}
}

func validate(ps *crdv1alpha1.PacketCapture) (allowed bool, deniedReason string) {
	if ps.Spec.Source.Pod == "" && ps.Spec.Destination.Pod == "" {
		return false, fmt.Sprintf("PacketCapture %s has neither source nor destination Pod specified", ps.Name)
	}

	if ps.Spec.Type != crdv1alpha1.FirstNCapture {
		return false, fmt.Sprintf("PacketCapture %s has invalid type %s, supported type is [%s]", ps.Name, ps.Spec.Type, crdv1alpha1.FirstNCapture)
	}

	if ps.Spec.FirstNCaptureConfig == nil {
		return false, fmt.Sprintf("PacketCapture %s has no FirstNCaptureConfig", ps.Name)
	}

	isIPv6 := ps.Spec.Packet.IPv6Header != nil
	if ps.Spec.Source.IP != "" {
		sourceIP := net.ParseIP(ps.Spec.Source.IP)
		if sourceIP == nil {
			return false, "source IP is not valid"
		}
		if isIPv6 != (sourceIP.To4() == nil) {
			return false, "source IP does not match the IP header family"
		}
	}

	if ps.Spec.Destination.IP != "" {
		destIP := net.ParseIP(ps.Spec.Destination.IP)
		if destIP == nil {
			return false, "destination IP is not valid"
		}
		if isIPv6 != (destIP.To4() == nil) {
			return false, "destination IP does not match the IP header family"
		}
	}

	if _, err := ftp.ParseFTPUploadUrl(ps.Spec.FileServer.URL); err != nil {
		return false, fmt.Sprintf("invalid file server address: %s", err.Error())
	}
	return true, ""
}
