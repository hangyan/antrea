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

package packetcapture

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

func TestControllerValidate(t *testing.T) {
	tests := []struct {
		name string

		// input
		oldSpec *crdv1alpha1.PacketCaptureSpec
		newSpec *crdv1alpha1.PacketCaptureSpec

		// expected output
		allowed      bool
		deniedReason string
	}{
		{
			name:         "Traceflow should have either source or destination Pod assigned",
			newSpec:      &crdv1alpha1.PacketCaptureSpec{},
			deniedReason: "PacketCapture ps has neither source nor destination Pod specified",
		},
		{
			name: "Must assign capture type",
			newSpec: &crdv1alpha1.PacketCaptureSpec{
				Source: crdv1alpha1.Source{
					Namespace: "test-ns",
					Pod:       "test-pod",
				},
			},
			deniedReason: "PacketCapture ps has invalid type , supported type is [FirstNCapture]",
		},
		{
			name: "FistNCapture config not set",
			newSpec: &crdv1alpha1.PacketCaptureSpec{
				Source: crdv1alpha1.Source{
					Namespace: "test-ns",
					Pod:       "test-pod",
				},
				Type: crdv1alpha1.FirstNCapture,
			},
			deniedReason: "PacketCapture ps has no FirstNCaptureConfig",
		},
		{
			name: "Source IP family does not match",
			newSpec: &crdv1alpha1.PacketCaptureSpec{
				Source: crdv1alpha1.Source{
					IP: "127.0.0.1",
				},
				Type: crdv1alpha1.FirstNCapture,
				FirstNCaptureConfig: &crdv1alpha1.FirstNCaptureConfig{
					Number: 4,
				},
				Destination: crdv1alpha1.Destination{
					Namespace: "test-ns",
					Pod:       "test-pod",
				},
				Packet: crdv1alpha1.Packet{
					IPv6Header: &crdv1alpha1.IPv6Header{
						HopLimit: 1,
					},
				},
			},
			allowed:      false,
			deniedReason: "source IP does not match the IP header family",
		},
		{
			name: "Destination IP family does not match",
			newSpec: &crdv1alpha1.PacketCaptureSpec{
				Source: crdv1alpha1.Source{
					Namespace: "test-ns",
					Pod:       "test-pod",
				},
				Type: crdv1alpha1.FirstNCapture,
				FirstNCaptureConfig: &crdv1alpha1.FirstNCaptureConfig{
					Number: 4,
				},
				Destination: crdv1alpha1.Destination{
					IP: "fe80::aede:48ff:fe00:1122",
				},
				Packet: crdv1alpha1.Packet{},
			},
			allowed:      false,
			deniedReason: "destination IP does not match the IP header family",
		},
		{
			name: "Destination IP not valid",
			newSpec: &crdv1alpha1.PacketCaptureSpec{
				Source: crdv1alpha1.Source{
					Namespace: "test-ns",
					Pod:       "test-pod",
				},
				Type: crdv1alpha1.FirstNCapture,
				FirstNCaptureConfig: &crdv1alpha1.FirstNCaptureConfig{
					Number: 4,
				},
				Destination: crdv1alpha1.Destination{
					IP: "aaa:111",
				},
				Packet: crdv1alpha1.Packet{},
			},
			allowed:      false,
			deniedReason: "destination IP is not valid",
		},
		{
			name: "source IP not valid",
			newSpec: &crdv1alpha1.PacketCaptureSpec{
				Destination: crdv1alpha1.Destination{
					Namespace: "test-ns",
					Pod:       "test-pod",
				},
				Type: crdv1alpha1.FirstNCapture,
				FirstNCaptureConfig: &crdv1alpha1.FirstNCaptureConfig{
					Number: 4,
				},
				Source: crdv1alpha1.Source{
					IP: "aaa:111",
				},
				Packet: crdv1alpha1.Packet{},
			},
			allowed:      false,
			deniedReason: "source IP is not valid",
		},
		{
			name: "invalid ftp server address",
			newSpec: &crdv1alpha1.PacketCaptureSpec{
				Destination: crdv1alpha1.Destination{
					Namespace: "test-ns",
					Pod:       "test-pod",
				},
				Type: crdv1alpha1.FirstNCapture,
				FirstNCaptureConfig: &crdv1alpha1.FirstNCaptureConfig{
					Number: 4,
				},
				FileServer: crdv1alpha1.BundleFileServer{
					URL: "https://127.0.0.1:22/root/supportbundle",
				},
				Source: crdv1alpha1.Source{
					Namespace: "test-ns",
					Pod:       "test-pod",
				},
				Packet: crdv1alpha1.Packet{},
			},
			allowed:      false,
			deniedReason: "invalid file server address: not sftp protocol",
		},
		{
			name: "Valid request",
			newSpec: &crdv1alpha1.PacketCaptureSpec{
				Source: crdv1alpha1.Source{
					Namespace: "test-ns",
					Pod:       "test-pod",
				},
				Type: crdv1alpha1.FirstNCapture,
				FirstNCaptureConfig: &crdv1alpha1.FirstNCaptureConfig{
					Number: 4,
				},
				FileServer: crdv1alpha1.BundleFileServer{
					URL: "sftp://127.0.0.1:22/root/supportbundle",
				},
			},
			allowed: true,
		},
	}
	for _, ps := range tests {
		t.Run(ps.name, func(t *testing.T) {
			var request *admv1.AdmissionRequest
			if ps.oldSpec != nil && ps.newSpec != nil {
				request = &admv1.AdmissionRequest{
					Operation: admv1.Update,
					OldObject: toRawExtension(ps.oldSpec),
					Object:    toRawExtension(ps.newSpec),
				}
			} else if ps.newSpec != nil {
				request = &admv1.AdmissionRequest{
					Operation: admv1.Create,
					Object:    toRawExtension(ps.newSpec),
				}
			}
			review := &admv1.AdmissionReview{
				Request: request,
			}

			expectedResponse := &admv1.AdmissionResponse{
				Allowed: ps.allowed,
			}
			if !ps.allowed {
				expectedResponse.Result = &metav1.Status{
					Message: ps.deniedReason,
				}
			}

			response := Validate(review)
			assert.Equal(t, expectedResponse, response)
		})
	}
}

func toRawExtension(spec *crdv1alpha1.PacketCaptureSpec) runtime.RawExtension {
	ps := &crdv1alpha1.PacketCapture{Spec: *spec}
	ps.Name = "ps"
	raw, _ := json.Marshal(ps)
	return runtime.RawExtension{Raw: raw}
}
