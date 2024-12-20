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
// Source: antrea.io/antrea/pkg/antctl (interfaces: AntctlClient)
//
// Generated by this command:
//
//	mockgen -copyright_file hack/boilerplate/license_header.raw.txt -destination pkg/antctl/mock_antctl_test.go -package antctl antrea.io/antrea/pkg/antctl AntctlClient
//

// Package antctl is a generated GoMock package.
package antctl

import (
	io "io"
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// MockAntctlClient is a mock of AntctlClient interface.
type MockAntctlClient struct {
	ctrl     *gomock.Controller
	recorder *MockAntctlClientMockRecorder
	isgomock struct{}
}

// MockAntctlClientMockRecorder is the mock recorder for MockAntctlClient.
type MockAntctlClientMockRecorder struct {
	mock *MockAntctlClient
}

// NewMockAntctlClient creates a new mock instance.
func NewMockAntctlClient(ctrl *gomock.Controller) *MockAntctlClient {
	mock := &MockAntctlClient{ctrl: ctrl}
	mock.recorder = &MockAntctlClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAntctlClient) EXPECT() *MockAntctlClientMockRecorder {
	return m.recorder
}

// request mocks base method.
func (m *MockAntctlClient) request(opt *requestOption) (io.Reader, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "request", opt)
	ret0, _ := ret[0].(io.Reader)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// request indicates an expected call of request.
func (mr *MockAntctlClientMockRecorder) request(opt any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "request", reflect.TypeOf((*MockAntctlClient)(nil).request), opt)
}
