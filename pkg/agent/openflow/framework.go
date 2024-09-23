// Copyright 2022 Antrea Authors
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

package openflow

import (
	"antrea.io/libOpenflow/openflow15"

	"antrea.io/antrea/pkg/agent/config"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

// OVS pipelines are generated by a framework called FlexiblePipeline. There are some abstractions introduced in this
// framework.
//                +--------------+         +--------------+                                 +--------------+
//                |  feature F1  |         |  feature F2  |                                 |  feature F3  |
//                +--------------+         +--------------+                                 +--------------+
//                /       |       \           /        \                                      /         \
//               /        |        \         /          \                                    /           \
//              /         |         \       /            \                                  /             \
// +-------------+ +-------------+ +-------------+ +-------------+ +-------------+ +-------------+ +-------------+
// |   table A   | |   table B   | |   table C   | |   table D   | |   table E   | |   table F   | |   table G   |
// |   stage S1  | |           stage S2          | |           stage S1          | |          stage S4           |
// |                   pipeline P                | |                          pipeline Q                         |
// +-------------+ +-------------+ +-------------+ +-------------+ +-------------+ +-------------+ +-------------+
//          \              |              /                \                          |                  /
//           \             |             /                  \ ------ \                |          /-----/
//            \            |            /                             \               |         /
//            +------------------------+                              +-------------------------+
//            |       pipeline P       |                              |        pipeline Q       |
//            |       - table A        |                              |        - table D        |
//            |       - table B        |                              |        - table F        |
//            |       - table C        |                              |        - table G        |
//            +------------------------+                              +-------------------------+

// feature is the interface to program a major function in Antrea data path. The following structures implement this interface:
//
// - featurePodConnectivity, implementation of connectivity for Pods, activated by default.
// - featureNetworkPolicy, implementation of K8s NetworkPolicy and Antrea NetworkPolicy, activated by default.
// - featureService, implementation of K8s Service, activated by default.
// - featureEgress, implementation of Egress, activation is determined by feature gate Egress.
// - featureMulticast, implementation of multicast, activation is determined by feature gate Multicast,
// - featureTraceflow, implementation of Traceflow.
type feature interface {
	// getFeatureName returns the name of the feature.
	getFeatureName() string
	// getRequiredTables returns a slice of required tables of the feature.
	getRequiredTables() []*Table
	// initGroups returns the OpenFlow groups of the feature needed in the initialization.
	initGroups() []binding.OFEntry
	// initFlows returns the Openflow messages of initial flows of the feature.
	initFlows() []*openflow15.FlowMod
	// replayMeters returns the fixed and cached Openflow meters that need to be replayed after OVS is reconnected.
	replayMeters() []binding.OFEntry
	// replayGroups returns the fixed and cached Openflow groups that need to be replayed after OVS is reconnected.
	replayGroups() []binding.OFEntry
	// replayFlows returns the Openflow messages of fixed and cached flows that need to be replayed after OVS is reconnected.
	replayFlows() []*openflow15.FlowMod
}

const (
	// Pipeline is used to implement a major function in Antrea data path. At this moment, we have the following pipelines:

	// pipelineRoot is used to classify packets to pipelineARP / pipelineIP.
	pipelineRoot binding.PipelineID = iota
	// pipelineARP is used to process ARP packets.
	pipelineARP
	// pipelineIP is used to process IPv4/IPv6 packets
	pipelineIP
	// pipelineMulticast is used to process multicast packets.
	pipelineMulticast
	// pipelineNonIP is used to process the traffic of non-IP packets. This pipeline is used when ExternalNode feature
	// is enabled.
	pipelineNonIP

	firstPipeline = pipelineRoot
	lastPipeline  = pipelineNonIP
)

const (
	// Stage is used to group tables which implement similar functions in a pipeline. At this moment, we have the following
	// stages:

	// stageStart is only used to initialize PipelineRootClassifierTable.
	stageStart binding.StageID = iota
	// Classify packets "category" (tunnel, local gateway or local Pod, etc).
	stageClassifier
	// Validate packets.
	stageValidation
	// Transform committed packets in CT zones.
	stageConntrackState
	// Similar to PREROUTING chain of nat table in iptables. DNAT for Service connections is performed in this stage.
	stagePreRouting
	// Install egress rules for K8s NetworkPolicy and Antrea NetworkPolicy.
	stageEgressSecurity
	// L3 Forwarding of packets.
	stageRouting
	// Similar to POSTROUTING chain of nat table in iptables. SNAT for Service connections is performed in this stage.
	stagePostRouting
	// L2 Forwarding of packets.
	stageSwitching
	// Install ingress rules for K8s NetworkPolicy and Antrea NetworkPolicy.
	stageIngressSecurity
	// Commit non-Service connections.
	stageConntrack
	// Output packets to target port.
	stageOutput
)

// Table in FlexiblePipeline is the basic unit to build OVS pipelines. A Table can be referenced by one or more features,
// but its member struct ofTable will be initialized and realized on OVS only when it is referenced by any activated features.
type Table struct {
	name       string
	stage      binding.StageID
	pipeline   binding.PipelineID
	missAction binding.MissActionType
	ofTable    binding.Table
}

// tableOrderCache is used to save the order of all defined tables located in file pkg/agent/openflow/pipeline.go. The tables
// have the same pipeline ID are saved in a slice by order of definition. When building a pipeline, the required table list
// is aggregated from all activated features, and the order of the required tables is decided by the saved order.
var tableOrderCache = make(map[binding.PipelineID][]*Table)

// Option is a modifier for Table.
type Option func(*Table)

var defaultDrop = func(table *Table) {
	table.missAction = binding.TableMissActionDrop
}

// newTable is used to declare a Table. A table should belong to a stage and pipeline defined in current file.
func newTable(tableName string, stage binding.StageID, pipeline binding.PipelineID, options ...Option) *Table {
	table := &Table{
		name:     tableName,
		stage:    stage,
		pipeline: pipeline,
	}
	for _, option := range options {
		option(table)
	}
	tableOrderCache[pipeline] = append(tableOrderCache[pipeline], table)
	return table
}

func (t *Table) IsInitialized() bool {
	return t.ofTable != nil
}

func (t *Table) GetID() uint8 {
	return t.ofTable.GetID()
}

func (t *Table) GetNext() uint8 {
	return t.ofTable.GetNext()
}

func (t *Table) GetName() string {
	return t.name
}

func (t *Table) GetMissAction() binding.MissActionType {
	return t.ofTable.GetMissAction()
}

func (f *featurePodConnectivity) getRequiredTables() []*Table {
	tables := []*Table{
		ClassifierTable,
		SpoofGuardTable,
		ConntrackTable,
		ConntrackStateTable,
		L3ForwardingTable,
		L3DecTTLTable,
		L2ForwardingCalcTable,
		ConntrackCommitTable,
		OutputTable,
	}

	for _, ipProtocol := range f.ipProtocols {
		switch ipProtocol {
		case binding.ProtocolIPv6:
			tables = append(tables, IPv6Table)
		case binding.ProtocolIP:
			tables = append(tables,
				ARPSpoofGuardTable,
				ARPResponderTable)
			if f.enableMulticast {
				tables = append(tables, PipelineIPClassifierTable)
			}
			if f.connectUplinkToBridge {
				tables = append(tables, VLANTable)
			}
		}
	}
	if f.enableTrafficControl || f.enableL7FlowExporter {
		tables = append(tables, TrafficControlTable)
	}

	return tables
}

func (f *featureNetworkPolicy) getRequiredTables() []*Table {
	tables := []*Table{
		EgressRuleTable,
		EgressDefaultTable,
		EgressMetricTable,
		IngressSecurityClassifierTable,
		IngressRuleTable,
		IngressDefaultTable,
		IngressMetricTable,
	}
	if f.enableAntreaPolicy {
		tables = append(tables,
			AntreaPolicyEgressRuleTable,
			AntreaPolicyIngressRuleTable,
		)
		if f.enableL7NetworkPolicy {
			tables = append(tables, TrafficControlTable) // For L7 NetworkPolicy.
		}
		if f.enableMulticast {
			tables = append(tables,
				MulticastEgressRuleTable,
				MulticastEgressPodMetricTable,
				MulticastEgressMetricTable,
				MulticastIngressRuleTable,
				MulticastIngressPodMetricTable,
				MulticastIngressMetricTable,
			)
		}
	}
	if f.nodeType == config.ExternalNode {
		tables = append(tables,
			EgressSecurityClassifierTable,
		)
	}
	return tables
}

func (f *featureService) getRequiredTables() []*Table {
	if !f.enableProxy {
		return []*Table{DNATTable}
	}
	tables := []*Table{
		UnSNATTable,
		PreRoutingClassifierTable,
		SessionAffinityTable,
		ServiceLBTable,
		EndpointDNATTable,
		L3ForwardingTable,
		SNATMarkTable,
		SNATTable,
		ConntrackCommitTable,
		OutputTable,
	}
	if f.proxyAll {
		tables = append(tables, NodePortMarkTable)
	}
	if f.enableDSR {
		tables = append(tables, DSRServiceMarkTable)
	}
	return tables
}

func (f *featureEgress) getRequiredTables() []*Table {
	tables := []*Table{
		L3ForwardingTable,
		EgressMarkTable,
	}
	if f.enableEgressTrafficShaping {
		tables = append(tables, EgressQoSTable)
	}
	return tables
}

func (f *featureMulticast) getRequiredTables() []*Table {
	tables := []*Table{
		MulticastRoutingTable,
		MulticastOutputTable,
		MulticastEgressPodMetricTable,
		MulticastIngressPodMetricTable,
	}
	return tables
}

func (f *featureMulticluster) getRequiredTables() []*Table {
	return []*Table{
		ClassifierTable,
		ConntrackTable,
		L3ForwardingTable,
		SNATTable,
		UnSNATTable,
		SNATMarkTable,
		OutputTable,
	}
}

func (f *featureTraceflow) getRequiredTables() []*Table {
	return nil
}

func (f *featurePacketCapture) getRequiredTables() []*Table {
	return nil
}

func (f *featureExternalNodeConnectivity) getRequiredTables() []*Table {
	return []*Table{
		ConntrackTable,
		ConntrackStateTable,
		L2ForwardingCalcTable,
		ConntrackCommitTable,
		OutputTable,
		NonIPTable,
	}
}

// traceableFeature is the interface to support Traceflow in Antrea data path. Any other feature expected to trace the
// packet status with its flow entries needs to implement this interface. The following structures implement this interface:
// - featurePodConnectivity.
// - featureNetworkPolicy.
// - featureService.
type traceableFeature interface {
	// flowsToTrace returns the flows to be installed when a packet tracing request is created.
	flowsToTrace(dataplaneTag uint8,
		ovsMetersAreSupported,
		liveTraffic,
		droppedOnly,
		receiverOnly bool,
		packet *binding.Packet,
		ofPort uint32,
		timeoutSeconds uint16) []binding.Flow
}
