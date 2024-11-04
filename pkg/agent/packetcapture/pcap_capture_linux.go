// Copyright 2024 Antrea Authors.
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

package packetcapture

import (
	"context"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	netBpf "golang.org/x/net/bpf"
	klog "k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/packetcapture/bpf"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

const (
	// Max packet size for pcap capture.
	maxSnapshotBytes = 65536
)

type PcapCapture struct {
	*pcapgo.EthernetHandle
}

func NewPcapCapture(device string) (PacketCapturer, error) {
	eth, err := pcapgo.NewEthernetHandle(device)
	if err != nil {
		return nil, err
	}
	ps := PcapCapture{eth}
	return &ps, nil
}

func (p *PcapCapture) Capture(ctx context.Context, device string, srcIP, dstIP net.IP, packet *crdv1alpha1.Packet) (chan gopacket.Packet, error) {
	p.SetPromiscuous(false)
	p.SetCaptureLength(maxSnapshotBytes)

	inst := bpf.CompilePacketFilter(packet, srcIP, dstIP)
	klog.V(5).InfoS("Generated bpf instructions for Packetcapture", "device", device, "srcIP", srcIP, "dstIP", dstIP, "packetSpec", packet, "bpf instructions", inst)
	rawInst, err := netBpf.Assemble(inst)
	if err != nil {
		return nil, err
	}
	err = p.SetBPF(rawInst)
	if err != nil {
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(p, layers.LinkTypeEthernet)
	packetSource.NoCopy = true
	return packetSource.PacketsCtx(ctx), nil

}
