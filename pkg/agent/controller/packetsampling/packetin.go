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
	"fmt"
	"time"

	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/google/gopacket"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/openflow"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

// HandlePacketIn processes PacketIn messages from the OFSwitch. If the register value match, it will be counted and captured.
// Once the total number reaches the target, the PacketSampling will be marked as Succeed.
func (c *Controller) HandlePacketIn(pktIn *ofctrl.PacketIn) error {
	klog.V(4).InfoS("PacketIn for PacketSampling", "PacketIn", pktIn.PacketIn)
	samplingState, samplingFinished, err := c.parsePacketIn(pktIn)
	if err != nil {
		return fmt.Errorf("parsePacketIn error: %w", err)
	}
	if samplingFinished {
		return nil
	}
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
	reachTarget := samplingState.numCapturedPackets == samplingState.maxNumCapturedPackets
	// use rate limiter to reduce the times we need to update status.
	if reachTarget || samplingState.updateRateLimiter.Allow() {
		ps, err := c.packetSamplingLister.Get(samplingState.name)
		if err != nil {
			return fmt.Errorf("get PacketSampling failed: %w", err)
		}
		// if reach the target. flush the file and upload it.
		if reachTarget {
			if err := samplingState.pcapngWriter.Flush(); err != nil {
				return err
			}
			if err := c.uploadPackets(ps, samplingState.pcapngFile); err != nil {
				return err
			}
		}
		err = c.updatePacketSamplingStatus(ps, crdv1alpha1.PacketSamplingRunning, "", samplingState.numCapturedPackets)
		if err != nil {
			return fmt.Errorf("failed to update the PacketSampling: %w", err)
		}
		klog.InfoS("Updated PacketSampling", "PacketSampling", klog.KObj(ps), "numCapturedPackets", samplingState.numCapturedPackets)
	}
	return nil
}

// parsePacketIn parses the packet-in message. If the value in register match with existing PacketSampling's state(tag),
// it will be counted. If the total count reach the target, the ovs flow will be uninstalled.
func (c *Controller) parsePacketIn(pktIn *ofctrl.PacketIn) (_ *packetSamplingState, samplingFinished bool, _ error) {
	var tag uint8
	matchers := pktIn.GetMatches()
	match := openflow.GetMatchFieldByRegID(matchers, openflow.PacketSamplingMark.GetRegID())
	if match != nil {
		value, err := openflow.GetInfoInReg(match, openflow.PacketSamplingMark.GetRange().ToNXRange())
		if err != nil {
			return nil, false, fmt.Errorf("failed to get PacketSampling tag from packet-in message: %w", err)
		}
		tag = uint8(value)
	}
	c.runningPacketSamplingsMutex.Lock()
	defer c.runningPacketSamplingsMutex.Unlock()
	psState, exists := c.runningPacketSamplings[tag]
	if !exists {
		return nil, false, fmt.Errorf("PacketSampling for dataplane tag %d not found in cache", tag)
	}
	if psState.numCapturedPackets == psState.maxNumCapturedPackets {
		return nil, true, nil
	}
	psState.numCapturedPackets++
	if psState.numCapturedPackets == psState.maxNumCapturedPackets {
		err := c.ofClient.UninstallPacketSamplingFlows(tag)
		if err != nil {
			return nil, false, fmt.Errorf("uninstall PacketSampling ovs flow failed: %v", err)
		}
	}
	return psState, false, nil
}
