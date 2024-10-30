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

package bpf

import (
	"encoding/binary"
	"strings"

	"golang.org/x/net/bpf"

	"k8s.io/apimachinery/pkg/util/intstr"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

// CompilePacketFilter compile the CRD spec to bpf instructions. For now, we only focus on
// ipv4 traffic. Compare to the raw BPF filter supported by libpcap, we only need to support
// limited user cases, so an expression parser is not needed.
func CompilePacketFilter(packetSpec *crdv1alpha1.Packet, matchPacket *binding.Packet) []bpf.Instruction {
	size := uint8(calInstructionsSize(packetSpec))

	// ipv4 check
	inst := []bpf.Instruction{loadEtherKind}
	// skip means how many instructions we need to skip if the compare fails.
	// for example, for now we have 2 instructions, and the total size is 17, if ipv4
	// check failed, we need to jump to to the end (ret #0), skip 17-3=14 instructions.
	// if check succeed, skipTrue means we jump to the next instruction.
	inst = append(inst, compareProtocolIP4(0, size-3))

	packet := packetSpec
	if packet != nil {
		if packet.Protocol != nil {
			var proto uint32
			if packet.Protocol.Type == intstr.Int {
				proto = uint32(packet.Protocol.IntVal)
			} else {
				//TODO: check this earlier
				if val, ok := protocolMap[strings.ToLower(packet.Protocol.StrVal)]; ok {
					proto = val
				}
			}
			inst = append(inst, loadIPv4Protocol)
			inst = append(inst, compareProtocol(proto, 0, size-5))
		}
	}

	// source ip
	addr := matchPacket.SourceIP
	if addr != nil {
		inst = append(inst, loadIPv4SourceAddress)
		addrVal := binary.BigEndian.Uint32(addr[len(addr)-4:])
		// from here we need to check the inst length to calculate skipFalse. If no protocol is set, there will be no related bpf instructions.
		inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: addrVal, SkipTrue: 0, SkipFalse: size - uint8(len(inst)) - 2})

	}
	// dst ip
	addr = matchPacket.DestinationIP
	if addr != nil {
		inst = append(inst, loadIPv4DestinationAddress)
		addrVal := binary.BigEndian.Uint32(addr[len(addr)-4:])
		inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: addrVal, SkipTrue: 0, SkipFalse: size - uint8(len(inst)) - 2})
	}

	srcPort := matchPacket.SourcePort
	dstPort := matchPacket.DestinationPort
	if srcPort > 0 || dstPort > 0 {
		skipTrue := size - uint8(len(inst)) - 3
		inst = append(inst, loadIPv4HeaderOffset(skipTrue)...)
		if srcPort > 0 {
			inst = append(inst, loadIPv4SourcePort)
			inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(srcPort), SkipTrue: 0, SkipFalse: size - uint8(len(inst)) - 2})
		}
		if dstPort > 0 {
			inst = append(inst, loadIPv4DestinationPort)
			inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(dstPort), SkipTrue: 0, SkipFalse: size - uint8(len(inst)) - 2})
		}

	}

	// return
	inst = append(inst, returnKeep)
	inst = append(inst, returnDrop)

	return inst

}

// We need to figure out how long the instruction list will be first. IT will be used in the instructions' jump case.
// For example, If you provide all the filter supported by `PacketCapture`, it will ends with the following BPF filter string:
// 'ip proto 6 and src host 127.0.0.1 and dst host 127.0.0.1 and src port 123 and dst port 124'
// And using `tcpdump -i <device> '<filter>' -d` will generate the following BPF instructions:
// (000) ldh      [12]                                     # Load 2B at 12 (Ethertype)
// (001) jeq      #0x800           jt 2	jf 16              # Ethertype: If IPv4, goto #2, else #16
// (002) ldb      [23]                                     # Load 1B at 23 (IPv4 Protocol)
// (003) jeq      #0x6             jt 4	jf 16              # IPv4 Protocol: If TCP, goto #4, #16
// (004) ld       [26]                                     # Load 4B at 26 (source address)
// (005) jeq      #0x7f000001      jt 6	jf 16              # If bytes match(127.0.0.1), goto #6, else #16
// (006) ld       [30]                                     # Load 4B at 30 (dest address)
// (007) jeq      #0x7f000001      jt 8	jf 16              # If bytes match(127.0.0.1), goto #8, else #16
// (008) ldh      [20]                                     # Load 2B at 20 (13b Fragment Offset)
// (009) jset     #0x1fff          jt 16	jf 10      # Use 0x1fff as a mask for fragment offset; If fragment offset != 0, #10, else #16
// (010) ldxb     4*([14]&0xf)                             # x = IP header length
// (011) ldh      [x + 14]                                 # Load 2B at x+14 (TCP Source Port)
// (012) jeq      #0x7b            jt 13	jf 16      # TCP Source Port: If 123, goto #13, else #16
// (013) ldh      [x + 16]                                 # Load 2B at x+16 (TCP dst port)
// (014) jeq      #0x7c            jt 15	jf 16      # TCP dst port: If 123, goto $15, else #16
// (015) ret      #262144                                  # MATCH
// (016) ret      #0                                       # NOMATCH

func calInstructionsSize(packet *crdv1alpha1.Packet) int {
	count := 0
	// load ethertype
	count++
	// ip check
	count++

	if packet != nil {
		// protocol check
		if packet.Protocol != nil {
			count += 2
		}
		transPort := packet.TransportHeader
		if transPort.TCP != nil {
			// load Fragment Offset
			count += 3
			if transPort.TCP.SrcPort != nil {
				count += 2
			}
			if transPort.TCP.DstPort != nil {
				count += 2
			}

		} else if transPort.UDP != nil {
			count += 3
			if transPort.UDP.SrcPort != nil {
				count += 2
			}
			if transPort.UDP.DstPort != nil {
				count += 2
			}
		}
	}
	// src and dst ip
	count += 4

	// ret command
	count += 2
	return count

}
