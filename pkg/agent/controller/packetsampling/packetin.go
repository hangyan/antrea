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
	"fmt"
	"time"

	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/google/gopacket"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/openflow"
)

// HandlePacketIn processes PacketIn messages from the OFSwitch. If the DSCP flag match, it will be counted and captured.
// Once the total number reaches the target one, the PacketSampling will be marked as Succeed.
func (c *Controller) HandlePacketIn(pktIn *ofctrl.PacketIn) error {
	klog.V(4).InfoS("PacketIn for PacketSampling", "PacketIn", pktIn.PacketIn)
	samplingState, samplingFinished, err := c.parsePacketIn(pktIn)
	if err != nil {
		return fmt.Errorf("parsePacketIn error: %v", err)
	}
	if samplingFinished {
		return nil
	}
	ps, err := c.packetSamplingInformer.Lister().Get(samplingState.name)
	if err != nil {
		return fmt.Errorf("failed to get PacketSampling: %w", err)
	}
	shouldUpdate := samplingState.shouldSyncPackets && (samplingState.updateRateLimiter.Allow() || samplingState.numCapturedPackets == samplingState.maxNumCapturedPackets)
	if !shouldUpdate {
		return nil
	}
	update := ps.DeepCopy()
	update.Status.NumCapturedPackets = samplingState.numCapturedPackets
	_, err = c.crdClient.CrdV1alpha1().PacketSamplings().UpdateStatus(context.TODO(), update, v1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update the PacketSampling: %w", err)
	}
	klog.InfoS("Updated PacketSampling", "packetsampling", klog.KObj(ps), "status", update.Status)

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
	if samplingState.numCapturedPackets == samplingState.maxNumCapturedPackets && samplingState.shouldSyncPackets {
		ps, err := c.packetSamplingLister.Get(samplingState.name)
		if err != nil {
			return fmt.Errorf("get PacketSampling failed: %w", err)
		}
		return c.uploadPackets(ps, samplingState.pcapngFile)
	}

	return nil
}

// parsePacketIn parses the packet-in message and returns
// 1. the sampling state of the PacketSampling (on sampling mode)
func (c *Controller) parsePacketIn(pktIn *ofctrl.PacketIn) (_ *packetSamplingState, samplingFinished bool, _ error) {
	var tag uint8
	samplingState := packetSamplingState{}
	matchers := pktIn.GetMatches()
	match := openflow.GetMatchFieldByRegID(matchers, openflow.PacketSamplingMark.GetRegID())
	if match != nil {
		value, err := openflow.GetInfoInReg(match, openflow.PacketSamplingMark.GetRange().ToNXRange())
		if err != nil {
			return nil, false, fmt.Errorf("failed to get PacketSampling tag from packet-in message: %v", err)
		}
		tag = uint8(value)
	}
	c.runningPacketSamplingsMutex.RLock()
	psState, exists := c.runningPacketSamplings[tag]
	c.runningPacketSamplingsMutex.RUnlock()
	if exists {
		if psState.numCapturedPackets == psState.maxNumCapturedPackets {
			return nil, true, nil
		}
		psState.numCapturedPackets++
		if psState.numCapturedPackets == psState.maxNumCapturedPackets {
			c.ofClient.UninstallPacketSamplingFlows(tag)
		}
		samplingState = *psState
	}
	if !exists {
		return nil, false, fmt.Errorf("PacketSampling for dataplane tag %d not found in cache", tag)
	}
	return &samplingState, false, nil
}
