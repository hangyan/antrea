// Copyright 2020 Antrea Authors
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
	"net"
	"time"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/google/gopacket"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/openflow"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

func (c *Controller) HandlePacketIn(pktIn *ofctrl.PacketIn) error {
	if !c.packetSamplingSynced() {
		return errors.New("PacketSampling controller is not started")
	}
	oldTf, nodeResult, packet, samplingState, shouldSkip, err := c.parsePacketIn(pktIn)
	if err != nil {
		return fmt.Errorf("parsePacketIn error: %v", err)
	}
	if shouldSkip {
		return nil
	}

	// Retry when update CRD conflict which caused by multiple agents updating one CRD at same time.
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		tf, err := c.traceflowInformer.Lister().Get(oldTf.Name)
		if err != nil {
			return fmt.Errorf("get Traceflow failed: %w", err)
		}

		if samplingState != nil {
			shouldUpdate := samplingState.shouldSyncPackets && (packet != nil ||
				samplingState.updateRateLimiter.Allow() || samplingState.numCapturedPackets == tf.Spec.Sampling.Num)
			if !shouldUpdate {
				return nil
			}
		}

		update := tf.DeepCopy()
		if samplingState != nil {
			update.Status.Sampling.NumCapturedPackets = samplingState.numCapturedPackets
		} else {
			update.Status.Results = append(update.Status.Results, *nodeResult)
		}
		if packet != nil {
			update.Status.CapturedPacket = packet
		}

		_, err = c.traceflowClient.CrdV1alpha1().Traceflows().UpdateStatus(context.TODO(), update, v1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("update Traceflow failed: %w", err)
		}
		klog.InfoS("Updated Traceflow", "tf", klog.KObj(tf), "status", update.Status)
		return nil
	})
	if err != nil {
		return fmt.Errorf("Traceflow update error: %w", err)
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
	}
	return nil
}

// parsePacketIn parses the packet-in message and returns
// 1. the corresponding Traceflow CRD,
// 2. the observed node result,
// 3. the captured packet metadata (if applicable),
// 4. the sampling state of the Traceflow (on sampling mode),
// 5. a flag indicating whether this packet should be skipped,
// 6. unexpected errors.
func (c *Controller) parsePacketIn(pktIn *ofctrl.PacketIn) (_ *crdv1alpha1.Traceflow,
	_ *crdv1alpha1.Packet, _ *packetSamplingState, shouldSkip bool, _ error) {
	matchers := pktIn.GetMatches()

	// Get data plane tag.
	// Directly read data plane tag from packet.
	var err error
	var tag uint8

	etherData := new(protocol.Ethernet)
	if err := etherData.UnmarshalBinary(pktIn.Data.(*util.Buffer).Bytes()); err != nil {
		return nil, nil, nil, false, fmt.Errorf("failed to parse Ethernet packet from packet-in message: %v", err)
	}


	samplingState := packetSamplingState{}
	c.runningPacketSamplingsMutex.Lock()
	psState, exists := c.runningPacketSamplings[tag]
	if exists {

		if psState.numCapturedPackets == psState.maxNumCapturedPackets {
			c.runningPacketSamplingsMutex.Unlock()
			return nil, nil, nil, true, nil
		}
		psState.numCapturedPackets++
		if psState.numCapturedPackets == psState.maxNumCapturedPackets {
			c.ofClient.UninstallPacketSamplingFlows(tag)
		}
		samplingState = *psState

	}
	c.runningPacketSamplingsMutex.Unlock()
	if !exists {
		return nil, nil,, nil, false, fmt.Errorf("Traceflow for dataplane tag %d not found in cache", tag)
	}

	var capturedPacket *crdv1alpha1.Packet

	if samplingState.numCapturedPackets == 1 && samplingState.shouldSyncPackets {
		capturedPacket = parseCapturedPacket(pktIn)
	}

	ps, err := c.packetSamplingLister.Get(psState.name)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("failed to get Traceflow %s CRD: %v", tfState.name, err)
	}

	return ps, capturedPacket, &samplingState, false, nil

}




func parseCapturedPacket(pktIn *ofctrl.PacketIn) *crdv1alpha1.Packet {
	pkt, _ := binding.ParsePacketIn(pktIn)
	capturedPacket := crdv1alpha1.Packet{SrcIP: pkt.SourceIP.String(), DstIP: pkt.DestinationIP.String(), Length: pkt.IPLength}
	if pkt.IsIPv6 {
		ipProto := int32(pkt.IPProto)
		capturedPacket.IPv6Header = &crdv1alpha1.IPv6Header{NextHeader: &ipProto, HopLimit: int32(pkt.TTL)}
	} else {
		capturedPacket.IPHeader.Protocol = int32(pkt.IPProto)
		capturedPacket.IPHeader.TTL = int32(pkt.TTL)
		capturedPacket.IPHeader.Flags = int32(pkt.IPFlags)
	}
	if pkt.IPProto == protocol.Type_TCP {
		capturedPacket.TransportHeader.TCP = &crdv1alpha1.TCPHeader{SrcPort: int32(pkt.SourcePort), DstPort: int32(pkt.DestinationPort), Flags: int32(pkt.TCPFlags)}
	} else if pkt.IPProto == protocol.Type_UDP {
		capturedPacket.TransportHeader.UDP = &crdv1alpha1.UDPHeader{SrcPort: int32(pkt.SourcePort), DstPort: int32(pkt.DestinationPort)}
	} else if pkt.IPProto == protocol.Type_ICMP || pkt.IPProto == protocol.Type_IPv6ICMP {
		capturedPacket.TransportHeader.ICMP = &crdv1alpha1.ICMPEchoRequestHeader{ID: int32(pkt.ICMPEchoID), Sequence: int32(pkt.ICMPEchoSeq)}
	}
	return &capturedPacket
}

