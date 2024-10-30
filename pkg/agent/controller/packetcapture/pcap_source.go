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

//go:build linux

package packetcapture

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"golang.org/x/net/bpf"
)

type PcapSource struct {
	Handle          *pcapgo.EthernetHandle
	BpfInstructions []bpf.Instruction
}

func NewPcapSource(device string, inst []bpf.Instruction) (PacketSource, error) {
	eth, err := pcapgo.NewEthernetHandle(device)
	if err != nil {
		return nil, err
	}

	ps := PcapSource{
		Handle:          eth,
		BpfInstructions: inst,
	}

	return &ps, nil

}

func (p *PcapSource) Capture(options *CaptureOptions) (chan gopacket.Packet, error) {
	if options.MaxCaptureLength > 0 {
		p.Handle.SetCaptureLength(options.MaxCaptureLength)
	}
	p.Handle.SetPromiscuous(options.Promiscuous)

	if p.BpfInstructions != nil {
		rawInst, err := bpf.Assemble(p.BpfInstructions)
		if err != nil {
			return nil, err
		}
		err = p.Handle.SetBPF(rawInst)
		if err != nil {
			return nil, err
		}
	}

	packetSource := gopacket.NewPacketSource(p.Handle, layers.LinkTypeEthernet)
	packetSource.NoCopy = true

	return packetSource.Packets(), nil
}
