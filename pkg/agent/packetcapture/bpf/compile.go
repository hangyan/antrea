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
	"golang.org/x/net/bpf"
)

var (
	returnDrop              = bpf.RetConstant{Val: 0}
	returnKeep              = bpf.RetConstant{Val: 0x40000}
	loadIPv4SourcePort      = bpf.LoadIndirect{Off: ip4SourcePort, Size: lengthHalf}
	loadIPv4DestinationPort = bpf.LoadIndirect{Off: ip4DestinationPort, Size: lengthHalf}

	loadEtherKind              = bpf.LoadAbsolute{Off: 12, Size: lengthHalf}
	loadIPv4SourceAddress      = bpf.LoadAbsolute{Off: 26, Size: lengthWord}
	loadIPv4DestinationAddress = bpf.LoadAbsolute{Off: 30, Size: lengthWord}

	loadIPv4Protocol = bpf.LoadAbsolute{Off: 23, Size: lengthByte}
)

func loadIPv4HeaderOffset(skipTrue uint8) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadAbsolute{Off: ip4HeaderFlags, Size: lengthHalf},              // flags+fragment offset, since we need to calc where the src/dst port is
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: jumpMask, SkipTrue: skipTrue}, // check do we have a L4 header
		bpf.LoadMemShift{Off: ip4HeaderSize},                                 // calculate the size of IP header
	}
}

func compareProtocolIP4(skipTrue, skipFalse uint8) bpf.Instruction {
	return bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherTypeIPv4, SkipTrue: skipTrue, SkipFalse: skipFalse}
}

func compareProtocol(protocol uint32, skipTrue, skipFalse uint8) bpf.Instruction {
	return bpf.JumpIf{Cond: bpf.JumpEqual, Val: protocol, SkipTrue: skipTrue, SkipFalse: skipFalse}
}
