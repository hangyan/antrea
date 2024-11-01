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
	"bytes"
	"context"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"

	"antrea.io/antrea/pkg/apis/controlplane"
)

const (
	secretKeyWithAPIKey      = "apikey"
	secretKeyWithBearerToken = "token"
	secretKeyWithUsername    = "username"
	secretKeyWithPassword    = "password"
)

// FileServerAuthType defines the authentication type to access a file server.
type FileServerAuthType string

const (
	APIKey              FileServerAuthType = "APIKey"
	BearerToken         FileServerAuthType = "BearerToken"
	BasicAuthentication FileServerAuthType = "BasicAuthentication"
)

type FileServerAuthConfiguration struct {
	BearerToken         string
	APIKey              string
	BasicAuthentication *controlplane.BasicAuthentication
}

// GenSSHClientConfig generates ssh.ClientConfig from username and password
func GenSSHClientConfig(username, password string) *ssh.ClientConfig {
	cfg := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{ssh.Password(password)},
		// #nosec G106: skip host key check here and users can specify their own checks if needed
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Second,
	}
	return cfg
}

// ParseFileServerAuth returns the authentication from the Secret provided..
// The authentication is stored in the Secret Data with a key decided by the authType, and encoded using base64.
func ParseFileServerAuth(authType FileServerAuthType, secretRef *v1.SecretReference, kubeClient clientset.Interface) (*FileServerAuthConfiguration, error) {
	if secretRef == nil {
		return nil, fmt.Errorf("authentication is not specified")
	}
	secret, err := kubeClient.CoreV1().Secrets(secretRef.Namespace).Get(context.TODO(), secretRef.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get Secret with name %s in Namespace %s: %v", secretRef.Name, secretRef.Namespace, err)
	}
	parseAuthValue := func(secretData map[string][]byte, key string) (string, error) {
		authValue, found := secret.Data[key]
		if !found {
			return "", fmt.Errorf("not found authentication in Secret %s/%s with key %s", secretRef.Namespace, secretRef.Name, key)
		}
		return bytes.NewBuffer(authValue).String(), nil
	}
	switch authType {
	case APIKey:
		value, err := parseAuthValue(secret.Data, secretKeyWithAPIKey)
		if err != nil {
			return nil, err
		}
		return &FileServerAuthConfiguration{
			APIKey: value,
		}, nil
	case BearerToken:
		value, err := parseAuthValue(secret.Data, secretKeyWithBearerToken)
		if err != nil {
			return nil, err
		}
		return &FileServerAuthConfiguration{
			BearerToken: value,
		}, nil
	case BasicAuthentication:
		username, err := parseAuthValue(secret.Data, secretKeyWithUsername)
		if err != nil {
			return nil, err
		}
		password, err := parseAuthValue(secret.Data, secretKeyWithPassword)
		if err != nil {
			return nil, err
		}
		return &FileServerAuthConfiguration{
			BasicAuthentication: &controlplane.BasicAuthentication{
				Username: username,
				Password: password,
			},
		}, nil
	}
	return nil, fmt.Errorf("unsupported authentication type %s", authType)
}
