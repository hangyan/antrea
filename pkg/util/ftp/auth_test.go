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

package ftp

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/pkg/apis/controlplane"
)

const (
	informerDefaultResync = 30 * time.Second

	testKeyString   = "it is a valid API key"
	testTokenString = "it is a valid token"
)

type secretConfig struct {
	name string
	data map[string][]byte
}

func prepareSecrets(ns string, secretConfigs []secretConfig) []*corev1.Secret {
	secrets := make([]*corev1.Secret, 0)
	for _, s := range secretConfigs {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      s.name,
				Namespace: ns,
			},
			Data: s.data,
		}
		secrets = append(secrets, secret)
	}
	return secrets
}

type testClient struct {
	client          kubernetes.Interface
	informerFactory informers.SharedInformerFactory
}

func (c *testClient) start(stopCh <-chan struct{}) {
	c.informerFactory.Start(stopCh)
}

func (c *testClient) waitForSync(stopCh <-chan struct{}) {
	c.informerFactory.WaitForCacheSync(stopCh)
}

func newTestClient(coreObjects []runtime.Object, crdObjects []runtime.Object) *testClient {
	client := fake.NewSimpleClientset(coreObjects...)
	return &testClient{
		client:          client,
		informerFactory: informers.NewSharedInformerFactory(client, informerDefaultResync),
	}
}

type testAuthConfig struct {
	AuthType   FileServerAuthType
	AuthSecret *corev1.SecretReference
}

func TestParseFileServerAuth(t *testing.T) {
	ns := "ns-auth"
	apiKey := testKeyString
	token := testTokenString
	usr := "user"
	pwd := "pwd123456"
	var secretObjects []runtime.Object
	for _, s := range prepareSecrets(ns, []secretConfig{
		{name: "s1", data: map[string][]byte{secretKeyWithAPIKey: []byte(apiKey)}},
		{name: "s2", data: map[string][]byte{secretKeyWithBearerToken: []byte(token)}},
		{name: "s3", data: map[string][]byte{secretKeyWithUsername: []byte(usr), secretKeyWithPassword: []byte(pwd)}},
		{name: "invalid-base64", data: map[string][]byte{secretKeyWithAPIKey: []byte("invalid string to decode with base64")}},
		{name: "invalid-secret", data: map[string][]byte{"unknown": []byte(apiKey)}},
	}) {
		secretObjects = append(secretObjects, s)
	}

	testClient := newTestClient(secretObjects, nil)
	stopCh := make(chan struct{})
	testClient.start(stopCh)
	testClient.waitForSync(stopCh)

	for _, tc := range []struct {
		authentication testAuthConfig
		expectedError  string
		expectedAuth   *FileServerAuthConfiguration
	}{
		{
			authentication: testAuthConfig{
				AuthType: APIKey,
				AuthSecret: &corev1.SecretReference{
					Namespace: ns,
					Name:      "s1",
				},
			},
			expectedAuth: &FileServerAuthConfiguration{
				APIKey: testKeyString,
			},
		},
		{
			authentication: testAuthConfig{
				AuthType: BearerToken,
				AuthSecret: &corev1.SecretReference{
					Namespace: ns,
					Name:      "s2",
				},
			},
			expectedAuth: &FileServerAuthConfiguration{
				BearerToken: testTokenString,
			},
		},
		{
			authentication: testAuthConfig{
				AuthType: BasicAuthentication,
				AuthSecret: &corev1.SecretReference{
					Namespace: ns,
					Name:      "s3",
				},
			},
			expectedAuth: &FileServerAuthConfiguration{
				BasicAuthentication: &controlplane.BasicAuthentication{
					Username: usr,
					Password: pwd,
				},
			},
		},
		{
			authentication: testAuthConfig{
				AuthType: BearerToken,
				AuthSecret: &corev1.SecretReference{
					Namespace: ns,
					Name:      "invalid-secret",
				},
			},
			expectedError: fmt.Sprintf("not found authentication in Secret %s/invalid-secret with key %s", ns, secretKeyWithBearerToken),
		},
		{
			authentication: testAuthConfig{
				AuthType: BearerToken,
				AuthSecret: &corev1.SecretReference{
					Namespace: ns,
					Name:      "not-exist",
				},
			},
			expectedError: fmt.Sprintf("unable to get Secret with name not-exist in Namespace %s", ns),
		},
		{
			authentication: testAuthConfig{
				AuthType:   APIKey,
				AuthSecret: nil,
			},
			expectedError: "authentication is not specified",
		},
	} {
		auth, err := ParseFileServerAuth(tc.authentication.AuthType, tc.authentication.AuthSecret, testClient.client)
		if tc.expectedError != "" {
			assert.Contains(t, err.Error(), tc.expectedError)
		} else {
			assert.Equal(t, tc.expectedAuth, auth)
		}
	}
}
