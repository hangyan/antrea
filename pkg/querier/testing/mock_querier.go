// Copyright 2024 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// Code generated by MockGen. DO NOT EDIT.
// Source: antrea.io/antrea/pkg/querier (interfaces: AgentNetworkPolicyInfoQuerier,AgentMulticastInfoQuerier,EgressQuerier,AgentBGPPolicyInfoQuerier)
//
// Generated by this command:
//
//	mockgen -copyright_file hack/boilerplate/license_header.raw.txt -destination pkg/querier/testing/mock_querier.go -package testing antrea.io/antrea/pkg/querier AgentNetworkPolicyInfoQuerier,AgentMulticastInfoQuerier,EgressQuerier,AgentBGPPolicyInfoQuerier
//

// Package testing is a generated GoMock package.
package testing

import (
	context "context"
	reflect "reflect"

	bgp "antrea.io/antrea/pkg/agent/bgp"
	interfacestore "antrea.io/antrea/pkg/agent/interfacestore"
	multicast "antrea.io/antrea/pkg/agent/multicast"
	types "antrea.io/antrea/pkg/agent/types"
	v1beta2 "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	querier "antrea.io/antrea/pkg/querier"
	gomock "go.uber.org/mock/gomock"
	types0 "k8s.io/apimachinery/pkg/types"
)

// MockAgentNetworkPolicyInfoQuerier is a mock of AgentNetworkPolicyInfoQuerier interface.
type MockAgentNetworkPolicyInfoQuerier struct {
	ctrl     *gomock.Controller
	recorder *MockAgentNetworkPolicyInfoQuerierMockRecorder
	isgomock struct{}
}

// MockAgentNetworkPolicyInfoQuerierMockRecorder is the mock recorder for MockAgentNetworkPolicyInfoQuerier.
type MockAgentNetworkPolicyInfoQuerierMockRecorder struct {
	mock *MockAgentNetworkPolicyInfoQuerier
}

// NewMockAgentNetworkPolicyInfoQuerier creates a new mock instance.
func NewMockAgentNetworkPolicyInfoQuerier(ctrl *gomock.Controller) *MockAgentNetworkPolicyInfoQuerier {
	mock := &MockAgentNetworkPolicyInfoQuerier{ctrl: ctrl}
	mock.recorder = &MockAgentNetworkPolicyInfoQuerierMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAgentNetworkPolicyInfoQuerier) EXPECT() *MockAgentNetworkPolicyInfoQuerierMockRecorder {
	return m.recorder
}

// GetAddressGroupNum mocks base method.
func (m *MockAgentNetworkPolicyInfoQuerier) GetAddressGroupNum() int {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAddressGroupNum")
	ret0, _ := ret[0].(int)
	return ret0
}

// GetAddressGroupNum indicates an expected call of GetAddressGroupNum.
func (mr *MockAgentNetworkPolicyInfoQuerierMockRecorder) GetAddressGroupNum() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAddressGroupNum", reflect.TypeOf((*MockAgentNetworkPolicyInfoQuerier)(nil).GetAddressGroupNum))
}

// GetAddressGroups mocks base method.
func (m *MockAgentNetworkPolicyInfoQuerier) GetAddressGroups() []v1beta2.AddressGroup {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAddressGroups")
	ret0, _ := ret[0].([]v1beta2.AddressGroup)
	return ret0
}

// GetAddressGroups indicates an expected call of GetAddressGroups.
func (mr *MockAgentNetworkPolicyInfoQuerierMockRecorder) GetAddressGroups() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAddressGroups", reflect.TypeOf((*MockAgentNetworkPolicyInfoQuerier)(nil).GetAddressGroups))
}

// GetAppliedNetworkPolicies mocks base method.
func (m *MockAgentNetworkPolicyInfoQuerier) GetAppliedNetworkPolicies(pod, namespace string, npFilter *querier.NetworkPolicyQueryFilter) []v1beta2.NetworkPolicy {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAppliedNetworkPolicies", pod, namespace, npFilter)
	ret0, _ := ret[0].([]v1beta2.NetworkPolicy)
	return ret0
}

// GetAppliedNetworkPolicies indicates an expected call of GetAppliedNetworkPolicies.
func (mr *MockAgentNetworkPolicyInfoQuerierMockRecorder) GetAppliedNetworkPolicies(pod, namespace, npFilter any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAppliedNetworkPolicies", reflect.TypeOf((*MockAgentNetworkPolicyInfoQuerier)(nil).GetAppliedNetworkPolicies), pod, namespace, npFilter)
}

// GetAppliedToGroupNum mocks base method.
func (m *MockAgentNetworkPolicyInfoQuerier) GetAppliedToGroupNum() int {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAppliedToGroupNum")
	ret0, _ := ret[0].(int)
	return ret0
}

// GetAppliedToGroupNum indicates an expected call of GetAppliedToGroupNum.
func (mr *MockAgentNetworkPolicyInfoQuerierMockRecorder) GetAppliedToGroupNum() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAppliedToGroupNum", reflect.TypeOf((*MockAgentNetworkPolicyInfoQuerier)(nil).GetAppliedToGroupNum))
}

// GetAppliedToGroups mocks base method.
func (m *MockAgentNetworkPolicyInfoQuerier) GetAppliedToGroups() []v1beta2.AppliedToGroup {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAppliedToGroups")
	ret0, _ := ret[0].([]v1beta2.AppliedToGroup)
	return ret0
}

// GetAppliedToGroups indicates an expected call of GetAppliedToGroups.
func (mr *MockAgentNetworkPolicyInfoQuerierMockRecorder) GetAppliedToGroups() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAppliedToGroups", reflect.TypeOf((*MockAgentNetworkPolicyInfoQuerier)(nil).GetAppliedToGroups))
}

// GetControllerConnectionStatus mocks base method.
func (m *MockAgentNetworkPolicyInfoQuerier) GetControllerConnectionStatus() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetControllerConnectionStatus")
	ret0, _ := ret[0].(bool)
	return ret0
}

// GetControllerConnectionStatus indicates an expected call of GetControllerConnectionStatus.
func (mr *MockAgentNetworkPolicyInfoQuerierMockRecorder) GetControllerConnectionStatus() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetControllerConnectionStatus", reflect.TypeOf((*MockAgentNetworkPolicyInfoQuerier)(nil).GetControllerConnectionStatus))
}

// GetNetworkPolicies mocks base method.
func (m *MockAgentNetworkPolicyInfoQuerier) GetNetworkPolicies(npFilter *querier.NetworkPolicyQueryFilter) []v1beta2.NetworkPolicy {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNetworkPolicies", npFilter)
	ret0, _ := ret[0].([]v1beta2.NetworkPolicy)
	return ret0
}

// GetNetworkPolicies indicates an expected call of GetNetworkPolicies.
func (mr *MockAgentNetworkPolicyInfoQuerierMockRecorder) GetNetworkPolicies(npFilter any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNetworkPolicies", reflect.TypeOf((*MockAgentNetworkPolicyInfoQuerier)(nil).GetNetworkPolicies), npFilter)
}

// GetNetworkPolicyByRuleFlowID mocks base method.
func (m *MockAgentNetworkPolicyInfoQuerier) GetNetworkPolicyByRuleFlowID(ruleFlowID uint32) *v1beta2.NetworkPolicyReference {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNetworkPolicyByRuleFlowID", ruleFlowID)
	ret0, _ := ret[0].(*v1beta2.NetworkPolicyReference)
	return ret0
}

// GetNetworkPolicyByRuleFlowID indicates an expected call of GetNetworkPolicyByRuleFlowID.
func (mr *MockAgentNetworkPolicyInfoQuerierMockRecorder) GetNetworkPolicyByRuleFlowID(ruleFlowID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNetworkPolicyByRuleFlowID", reflect.TypeOf((*MockAgentNetworkPolicyInfoQuerier)(nil).GetNetworkPolicyByRuleFlowID), ruleFlowID)
}

// GetNetworkPolicyNum mocks base method.
func (m *MockAgentNetworkPolicyInfoQuerier) GetNetworkPolicyNum() int {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNetworkPolicyNum")
	ret0, _ := ret[0].(int)
	return ret0
}

// GetNetworkPolicyNum indicates an expected call of GetNetworkPolicyNum.
func (mr *MockAgentNetworkPolicyInfoQuerierMockRecorder) GetNetworkPolicyNum() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNetworkPolicyNum", reflect.TypeOf((*MockAgentNetworkPolicyInfoQuerier)(nil).GetNetworkPolicyNum))
}

// GetRuleByFlowID mocks base method.
func (m *MockAgentNetworkPolicyInfoQuerier) GetRuleByFlowID(ruleFlowID uint32) *types.PolicyRule {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRuleByFlowID", ruleFlowID)
	ret0, _ := ret[0].(*types.PolicyRule)
	return ret0
}

// GetRuleByFlowID indicates an expected call of GetRuleByFlowID.
func (mr *MockAgentNetworkPolicyInfoQuerierMockRecorder) GetRuleByFlowID(ruleFlowID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRuleByFlowID", reflect.TypeOf((*MockAgentNetworkPolicyInfoQuerier)(nil).GetRuleByFlowID), ruleFlowID)
}

// MockAgentMulticastInfoQuerier is a mock of AgentMulticastInfoQuerier interface.
type MockAgentMulticastInfoQuerier struct {
	ctrl     *gomock.Controller
	recorder *MockAgentMulticastInfoQuerierMockRecorder
	isgomock struct{}
}

// MockAgentMulticastInfoQuerierMockRecorder is the mock recorder for MockAgentMulticastInfoQuerier.
type MockAgentMulticastInfoQuerierMockRecorder struct {
	mock *MockAgentMulticastInfoQuerier
}

// NewMockAgentMulticastInfoQuerier creates a new mock instance.
func NewMockAgentMulticastInfoQuerier(ctrl *gomock.Controller) *MockAgentMulticastInfoQuerier {
	mock := &MockAgentMulticastInfoQuerier{ctrl: ctrl}
	mock.recorder = &MockAgentMulticastInfoQuerierMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAgentMulticastInfoQuerier) EXPECT() *MockAgentMulticastInfoQuerierMockRecorder {
	return m.recorder
}

// CollectIGMPReportNPStats mocks base method.
func (m *MockAgentMulticastInfoQuerier) CollectIGMPReportNPStats() (map[types0.UID]map[string]*types.RuleMetric, map[types0.UID]map[string]*types.RuleMetric) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CollectIGMPReportNPStats")
	ret0, _ := ret[0].(map[types0.UID]map[string]*types.RuleMetric)
	ret1, _ := ret[1].(map[types0.UID]map[string]*types.RuleMetric)
	return ret0, ret1
}

// CollectIGMPReportNPStats indicates an expected call of CollectIGMPReportNPStats.
func (mr *MockAgentMulticastInfoQuerierMockRecorder) CollectIGMPReportNPStats() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CollectIGMPReportNPStats", reflect.TypeOf((*MockAgentMulticastInfoQuerier)(nil).CollectIGMPReportNPStats))
}

// GetAllPodsStats mocks base method.
func (m *MockAgentMulticastInfoQuerier) GetAllPodsStats() map[*interfacestore.InterfaceConfig]*multicast.PodTrafficStats {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAllPodsStats")
	ret0, _ := ret[0].(map[*interfacestore.InterfaceConfig]*multicast.PodTrafficStats)
	return ret0
}

// GetAllPodsStats indicates an expected call of GetAllPodsStats.
func (mr *MockAgentMulticastInfoQuerierMockRecorder) GetAllPodsStats() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAllPodsStats", reflect.TypeOf((*MockAgentMulticastInfoQuerier)(nil).GetAllPodsStats))
}

// GetGroupPods mocks base method.
func (m *MockAgentMulticastInfoQuerier) GetGroupPods() map[string][]v1beta2.PodReference {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGroupPods")
	ret0, _ := ret[0].(map[string][]v1beta2.PodReference)
	return ret0
}

// GetGroupPods indicates an expected call of GetGroupPods.
func (mr *MockAgentMulticastInfoQuerierMockRecorder) GetGroupPods() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroupPods", reflect.TypeOf((*MockAgentMulticastInfoQuerier)(nil).GetGroupPods))
}

// GetPodStats mocks base method.
func (m *MockAgentMulticastInfoQuerier) GetPodStats(podName, podNamespace string) *multicast.PodTrafficStats {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPodStats", podName, podNamespace)
	ret0, _ := ret[0].(*multicast.PodTrafficStats)
	return ret0
}

// GetPodStats indicates an expected call of GetPodStats.
func (mr *MockAgentMulticastInfoQuerierMockRecorder) GetPodStats(podName, podNamespace any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPodStats", reflect.TypeOf((*MockAgentMulticastInfoQuerier)(nil).GetPodStats), podName, podNamespace)
}

// MockEgressQuerier is a mock of EgressQuerier interface.
type MockEgressQuerier struct {
	ctrl     *gomock.Controller
	recorder *MockEgressQuerierMockRecorder
	isgomock struct{}
}

// MockEgressQuerierMockRecorder is the mock recorder for MockEgressQuerier.
type MockEgressQuerierMockRecorder struct {
	mock *MockEgressQuerier
}

// NewMockEgressQuerier creates a new mock instance.
func NewMockEgressQuerier(ctrl *gomock.Controller) *MockEgressQuerier {
	mock := &MockEgressQuerier{ctrl: ctrl}
	mock.recorder = &MockEgressQuerierMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockEgressQuerier) EXPECT() *MockEgressQuerierMockRecorder {
	return m.recorder
}

// GetEgress mocks base method.
func (m *MockEgressQuerier) GetEgress(podNamespace, podName string) (string, string, string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetEgress", podNamespace, podName)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(string)
	ret3, _ := ret[3].(error)
	return ret0, ret1, ret2, ret3
}

// GetEgress indicates an expected call of GetEgress.
func (mr *MockEgressQuerierMockRecorder) GetEgress(podNamespace, podName any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetEgress", reflect.TypeOf((*MockEgressQuerier)(nil).GetEgress), podNamespace, podName)
}

// GetEgressIPByMark mocks base method.
func (m *MockEgressQuerier) GetEgressIPByMark(mark uint32) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetEgressIPByMark", mark)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetEgressIPByMark indicates an expected call of GetEgressIPByMark.
func (mr *MockEgressQuerierMockRecorder) GetEgressIPByMark(mark any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetEgressIPByMark", reflect.TypeOf((*MockEgressQuerier)(nil).GetEgressIPByMark), mark)
}

// MockAgentBGPPolicyInfoQuerier is a mock of AgentBGPPolicyInfoQuerier interface.
type MockAgentBGPPolicyInfoQuerier struct {
	ctrl     *gomock.Controller
	recorder *MockAgentBGPPolicyInfoQuerierMockRecorder
	isgomock struct{}
}

// MockAgentBGPPolicyInfoQuerierMockRecorder is the mock recorder for MockAgentBGPPolicyInfoQuerier.
type MockAgentBGPPolicyInfoQuerierMockRecorder struct {
	mock *MockAgentBGPPolicyInfoQuerier
}

// NewMockAgentBGPPolicyInfoQuerier creates a new mock instance.
func NewMockAgentBGPPolicyInfoQuerier(ctrl *gomock.Controller) *MockAgentBGPPolicyInfoQuerier {
	mock := &MockAgentBGPPolicyInfoQuerier{ctrl: ctrl}
	mock.recorder = &MockAgentBGPPolicyInfoQuerierMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAgentBGPPolicyInfoQuerier) EXPECT() *MockAgentBGPPolicyInfoQuerierMockRecorder {
	return m.recorder
}

// GetBGPPeerStatus mocks base method.
func (m *MockAgentBGPPolicyInfoQuerier) GetBGPPeerStatus(ctx context.Context) ([]bgp.PeerStatus, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBGPPeerStatus", ctx)
	ret0, _ := ret[0].([]bgp.PeerStatus)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetBGPPeerStatus indicates an expected call of GetBGPPeerStatus.
func (mr *MockAgentBGPPolicyInfoQuerierMockRecorder) GetBGPPeerStatus(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBGPPeerStatus", reflect.TypeOf((*MockAgentBGPPolicyInfoQuerier)(nil).GetBGPPeerStatus), ctx)
}

// GetBGPPolicyInfo mocks base method.
func (m *MockAgentBGPPolicyInfoQuerier) GetBGPPolicyInfo() (string, string, int32, int32) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBGPPolicyInfo")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(int32)
	ret3, _ := ret[3].(int32)
	return ret0, ret1, ret2, ret3
}

// GetBGPPolicyInfo indicates an expected call of GetBGPPolicyInfo.
func (mr *MockAgentBGPPolicyInfoQuerierMockRecorder) GetBGPPolicyInfo() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBGPPolicyInfo", reflect.TypeOf((*MockAgentBGPPolicyInfoQuerier)(nil).GetBGPPolicyInfo))
}
