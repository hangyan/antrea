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

const (
	lengthByte    int    = 1
	lengthHalf    int    = 2
	lengthWord    int    = 4
	bitsPerWord   int    = 32
	etherTypeIPv4 uint32 = 0x0800

	jumpMask           uint32 = 0x1fff
	ipProtocolTCP      uint32 = 0x06
	ipProtocolUDP      uint32 = 0x11
	ipProtocolICMP     uint32 = 0x1
	ipProtocolSctp     uint32 = 0x84
	ip6SourcePort      uint32 = 54
	ip6DestinationPort uint32 = 56
	ip4SourcePort      uint32 = 14
	ip4DestinationPort uint32 = 16
	ip4HeaderSize      uint32 = 14
	ip4HeaderFlags     uint32 = 20
)
