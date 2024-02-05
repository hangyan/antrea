// Copyright 2024 Antrea Authors
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

package packetsampling

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/gopacket"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

func (c *Controller) HandlePacketIn(pktIn *ofctrl.PacketIn) error {
	klog.V(4).Infof("PacketIn for PacketSampling: %+v", pktIn.PacketIn)
	if !c.packetSamplingSynced() {
		return errors.New("PacketSampling controller is not started")
	}
	oldPS, samplingState, shouldSkip, err := c.parsePacketIn(pktIn)
	if err != nil {
		return fmt.Errorf("parsePacketIn error: %v", err)
	}
	if shouldSkip {
		return nil
	}

	// Retry when update CRD conflict which caused by multiple agents updating one CRD at same time.
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		ps, err := c.packetSamplingInformer.Lister().Get(oldPS.Name)
		if err != nil {
			return fmt.Errorf("get PacketSampling failed: %w", err)
		}

		if samplingState != nil {
			shouldUpdate := samplingState.shouldSyncPackets && (samplingState.updateRateLimiter.Allow() || samplingState.numCapturedPackets == samplingState.maxNumCapturedPackets)
			if !shouldUpdate {
				return nil
			}
		}

		update := ps.DeepCopy()
		if samplingState != nil {
			update.Status.NumCapturedPackets = samplingState.numCapturedPackets
		}

		_, err = c.crdClient.CrdV1alpha1().PacketSamplings().UpdateStatus(context.TODO(), update, v1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("update Traceflow failed: %w", err)
		}
		klog.InfoS("Updated PacketSampling", "ps", klog.KObj(ps), "status", update.Status)
		return nil
	})
	if err != nil {
		return fmt.Errorf("PacketSampling update error: %w", err)
	}

	if samplingState != nil {
		rawData := pktIn.Data.(*util.Buffer).Bytes()
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(rawData),
			Length:        len(rawData),
		}
		err = samplingState.pcapngWriter.WritePacket(ci, rawData)
		if err != nil {
			return fmt.Errorf("couldn't write packet: %w", err)
		}

		if samplingState.numCapturedPackets == oldPS.Spec.FirstNSamplingConfig.Number && samplingState.shouldSyncPackets {
			return c.uploadPacketsFile(oldPS)
		}
	}
	return nil
}

// parsePacketIn parses the packet-in message and returns
// 1. the sampling state of the PacketSampling (on sampling mode),
func (c *Controller) parsePacketIn(pktIn *ofctrl.PacketIn) (_ *crdv1alpha1.PacketSampling, _ *packetSamplingState, shouldSkip bool, _ error) {
	// Get data plane tag.
	// Directly read data plane tag from packet.
	var err error
	var tag uint8
	samplingState := packetSamplingState{}

	etherData := new(protocol.Ethernet)
	if err := etherData.UnmarshalBinary(pktIn.Data.(*util.Buffer).Bytes()); err != nil {
		return nil, nil, false, fmt.Errorf("failed to parse Ethernet packet from packet-in message: %v", err)
	}
	if etherData.Ethertype == protocol.IPv4_MSG {
		ipPacket, ok := etherData.Data.(*protocol.IPv4)
		if !ok {
			return nil, nil, false, fmt.Errorf("invalid PacketSampling ipv4 packet")

		}
		tag = ipPacket.DSCP
	} else if etherData.Ethertype == protocol.IPv6_MSG {
		ipv6Packet, ok := etherData.Data.(*protocol.IPv6)
		if !ok {
			return nil, nil, false, fmt.Errorf("invalid PacketSampling ipv6 packet")
		}
		tag = ipv6Packet.TrafficClass >> 2
	} else {
		return nil, nil, false, fmt.Errorf("unsupported traceflow packet Ethertype: %d", etherData.Ethertype)
	}

	c.runningPacketSamplingsMutex.Lock()
	psState, exists := c.runningPacketSamplings[int8(tag)]
	if exists {
		if psState.numCapturedPackets == psState.maxNumCapturedPackets {
			c.runningPacketSamplingsMutex.Unlock()
			return nil, nil, true, nil
		}
		psState.numCapturedPackets++
		if psState.numCapturedPackets == psState.maxNumCapturedPackets {
			c.ofClient.UninstallPacketSamplingFlows(tag)
		}
		samplingState = *psState

	}
	c.runningPacketSamplingsMutex.Unlock()
	if !exists {
		return nil, nil, false, fmt.Errorf("PacketSampling for dataplane tag %d not found in cache", tag)
	}

	ps, err := c.packetSamplingLister.Get(psState.name)
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to get PacketSampling %s CRD: %v", psState.name, err)
	}

	return ps, &samplingState, false, nil

}

func (c *Controller) uploadPacketsFile(ps *crdv1alpha1.PacketSampling) error {
	name := uidToPath(string(ps.UID))
	file, err := defaultFS.Open(name)
	if err != nil {
		return err
	}
	return c.uploadPackets(ps, file)
}
