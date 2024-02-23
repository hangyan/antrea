package auth

import (
	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"bytes"
	"context"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
)

const (
	secretKeyWithAPIKey      = "apikey"
	secretKeyWithBearerToken = "token"
	secretKeyWithUsername    = "username"
	secretKeyWithPassword    = "password"
)

// ParseBundleAuth returns the authentication from the Secret provided in BundleServerAuthConfiguration.
// The authentication is stored in the Secret Data with a key decided by the AuthType, and encoded using base64.
func ParseBundleAuth(authentication crdv1alpha1.BundleServerAuthConfiguration, kubeClient clientset.Interface) (*controlplane.BundleServerAuthConfiguration, error) {
	secretReference := authentication.AuthSecret
	if secretReference == nil {
		return nil, fmt.Errorf("authentication is not specified")
	}
	secret, err := kubeClient.CoreV1().Secrets(secretReference.Namespace).Get(context.TODO(), secretReference.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get Secret with name %s in Namespace %s: %v", secretReference.Name, secretReference.Namespace, err)
	}
	parseAuthValue := func(secretData map[string][]byte, key string) (string, error) {
		authValue, found := secret.Data[key]
		if !found {
			return "", fmt.Errorf("not found authentication in Secret %s/%s with key %s", secretReference.Namespace, secretReference.Name, key)
		}
		return bytes.NewBuffer(authValue).String(), nil
	}
	switch authentication.AuthType {
	case crdv1alpha1.APIKey:
		value, err := parseAuthValue(secret.Data, secretKeyWithAPIKey)
		if err != nil {
			return nil, err
		}
		return &controlplane.BundleServerAuthConfiguration{
			APIKey: value,
		}, nil
	case crdv1alpha1.BearerToken:
		value, err := parseAuthValue(secret.Data, secretKeyWithBearerToken)
		if err != nil {
			return nil, err
		}
		return &controlplane.BundleServerAuthConfiguration{
			BearerToken: value,
		}, nil
	case crdv1alpha1.BasicAuthentication:
		username, err := parseAuthValue(secret.Data, secretKeyWithUsername)
		if err != nil {
			return nil, err
		}
		password, err := parseAuthValue(secret.Data, secretKeyWithPassword)
		if err != nil {
			return nil, err
		}
		return &controlplane.BundleServerAuthConfiguration{
			BasicAuthentication: &controlplane.BasicAuthentication{
				Username: username,
				Password: password,
			},
		}, nil
	}
	return nil, fmt.Errorf("unsupported authentication type %s", authentication.AuthType)
}
