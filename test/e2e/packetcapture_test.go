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

package e2e

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	controllerconfig "antrea.io/antrea/pkg/config/controller"
	"antrea.io/antrea/pkg/features"
)

var (
	pcSecretNamespace = "kube-system"
	// #nosec G101
	pcSecretName     = "antrea-packetcapture-fileserver-auth"
	tcpServerPodName = "tcp-server"
	pcToolboxPodName = "toolbox"
	udpServerPodName = "udp-server"
	nonExistPodName  = "non-existing-pod"
	dstServiceName   = "svc"
	dstServiceIP     = ""
)

type pcTestCase struct {
	name           string
	pc             *crdv1alpha1.PacketCapture
	expectedPhase  crdv1alpha1.PacketCapturePhase
	expectedReason string
	expectedNum    int32
	// required IP version, skip if not match.
	ipVersion int
	// Source Pod to run ping for live-traffic PacketCapture.
	srcPod string
}

func genSFTPService() *v1.Service {
	selector := map[string]string{"app": "sftp"}
	return &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "sftp",
			Labels: selector,
		},
		Spec: v1.ServiceSpec{
			Type:     v1.ServiceTypeNodePort,
			Selector: selector,
			Ports: []v1.ServicePort{
				{
					Port:       22,
					TargetPort: intstr.FromInt32(22),
					NodePort:   30010,
				},
			},
		},
	}
}

func genSFTPDeployment() *appsv1.Deployment {
	replicas := int32(1)
	selector := map[string]string{"app": "sftp"}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "sftp",
			Labels: selector,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: selector,
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "sftp",
					Labels: selector,
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:            "sftp",
							Image:           "antrea/sftp",
							ImagePullPolicy: v1.PullIfNotPresent,
							Args:            []string{"foo:pass:::upload"},
						},
					},
				},
			},
		},
	}
}

func createUDPServerPod(name string, ns string, portNum int32, serverNode string) error {
	port := v1.ContainerPort{Name: fmt.Sprintf("port-%d", portNum), ContainerPort: portNum}
	return NewPodBuilder(name, ns, agnhostImage).
		OnNode(serverNode).
		WithContainerName("agnhost").
		WithArgs([]string{"serve-hostname", "--udp", "--http=false", "--port", fmt.Sprint(portNum)}).
		WithPorts([]v1.ContainerPort{port}).
		Create(testData)
}

// TestPacketCapture is the top-level test which contains all subtests for
// PacketCapture related test cases so they can share setup, teardown.
func TestPacketCapture(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	var previousAgentPacketCaptureEnableState bool
	var previousControllerPacketCaptureEnableState bool

	ac := func(config *agentconfig.AgentConfig) {
		previousAgentPacketCaptureEnableState = config.FeatureGates[string(features.PacketCapture)]
		config.FeatureGates[string(features.PacketCapture)] = true
	}
	cc := func(config *controllerconfig.ControllerConfig) {
		previousControllerPacketCaptureEnableState = config.FeatureGates[string(features.PacketCapture)]
		config.FeatureGates[string(features.PacketCapture)] = true
	}
	if err := data.mutateAntreaConfigMap(cc, ac, true, true); err != nil {
		t.Fatalf("Failed to enable PacketCapture flag: %v", err)
	}
	defer func() {
		ac := func(config *agentconfig.AgentConfig) {
			config.FeatureGates[string(features.PacketCapture)] = previousAgentPacketCaptureEnableState
		}
		cc := func(config *controllerconfig.ControllerConfig) {
			config.FeatureGates[string(features.PacketCapture)] = previousControllerPacketCaptureEnableState
		}
		if err := data.mutateAntreaConfigMap(cc, ac, true, true); err != nil {
			t.Errorf("Failed to disable PacketCapture flag: %v", err)
		}
	}()

	// setup sftp server for test.
	secretUserName := "foo"
	secretPassword := "pass"
	_, err = data.clientset.AppsV1().Deployments(data.testNamespace).Create(context.TODO(), genSFTPDeployment(), metav1.CreateOptions{})
	require.NoError(t, err)
	_, err = data.clientset.CoreV1().Services(data.testNamespace).Create(context.TODO(), genSFTPService(), metav1.CreateOptions{})
	require.NoError(t, err)
	failOnError(data.waitForDeploymentReady(t, data.testNamespace, "sftp", defaultTimeout), t)

	sec := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pcSecretName,
			Namespace: pcSecretNamespace,
		},
		Data: map[string][]byte{
			"username": []byte(secretUserName),
			"password": []byte(secretPassword),
		},
	}
	_, err = data.clientset.CoreV1().Secrets(pcSecretNamespace).Create(context.TODO(), sec, metav1.CreateOptions{})
	require.NoError(t, err)
	defer data.clientset.CoreV1().Secrets(pcSecretNamespace).Delete(context.TODO(), pcSecretName, metav1.DeleteOptions{})

	t.Run("testPacketCaptureBasic", func(t *testing.T) {
		testPacketCaptureBasic(t, data)
	})
	t.Run("testPacketCapture", func(t *testing.T) {
		testPacketCapture(t, data)
	})
}

func testPacketCapture(t *testing.T, data *TestData) {
	nodeIdx := 0
	if len(clusterInfo.windowsNodes) != 0 {
		nodeIdx = clusterInfo.windowsNodes[0]
	}
	node1 := nodeName(nodeIdx)

	err := data.createServerPodWithLabels(tcpServerPodName, data.testNamespace, serverPodPort, nil)
	require.NoError(t, err)
	err = data.createToolboxPodOnNode(pcToolboxPodName, data.testNamespace, node1, false)
	require.NoError(t, err)

	svc, cleanup := data.createAgnhostServiceAndBackendPods(t, dstServiceName, data.testNamespace, node1, v1.ServiceTypeClusterIP)
	defer cleanup()
	t.Logf("%s Service is ready", dstServiceName)
	dstServiceIP = svc.Spec.ClusterIP

	podIPs := waitForPodIPs(t, data, []PodInfo{
		{tcpServerPodName, getOSString(), "", data.testNamespace},
		{pcToolboxPodName, getOSString(), "", data.testNamespace},
	})

	// Give a little time for Windows containerd Nodes to setup OVS.
	// Containerd configures port asynchronously, which could cause execution time of installing flow longer than docker.
	time.Sleep(time.Second * 1)

	testcases := []pcTestCase{
		{
			name:      "to-ipv4-ip",
			ipVersion: 4,
			srcPod:    pcToolboxPodName,
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", data.testNamespace, pcToolboxPodName, data.testNamespace, tcpServerPodName)),
				},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Namespace: data.testNamespace,
						Pod:       pcToolboxPodName,
					},
					Destination: crdv1alpha1.Destination{
						IP: podIPs[tcpServerPodName].IPv4.String(),
					},
					Type: crdv1alpha1.PacketCaptureFirstN,
					FirstNCaptureConfig: &crdv1alpha1.PacketCaptureFirstNConfig{
						Number: 5,
					},
					FileServer: crdv1alpha1.BundleFileServer{
						URL: fmt.Sprintf("sftp://%s:30010/upload", controlPlaneNodeIPv4()),
					},
					Packet: crdv1alpha1.Packet{
						IPHeader: crdv1alpha1.IPHeader{
							Protocol: protocolTCP,
						},
						TransportHeader: crdv1alpha1.TransportHeader{
							TCP: &crdv1alpha1.TCPHeader{
								DstPort: serverPodPort,
							},
						},
					},
				},
			},

			expectedPhase: crdv1alpha1.PacketCaptureSucceeded,
			expectedNum:   5,
		},
		{
			name:      "to-svc",
			ipVersion: 4,
			srcPod:    pcToolboxPodName,
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", data.testNamespace, pcToolboxPodName, data.testNamespace, tcpServerPodName)),
				},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Namespace: data.testNamespace,
						Pod:       pcToolboxPodName,
					},
					Destination: crdv1alpha1.Destination{
						Service:   dstServiceName,
						Namespace: data.testNamespace,
					},
					Type: crdv1alpha1.PacketCaptureFirstN,
					FirstNCaptureConfig: &crdv1alpha1.PacketCaptureFirstNConfig{
						Number: 5,
					},
					FileServer: crdv1alpha1.BundleFileServer{
						URL: fmt.Sprintf("sftp://%s:30010/upload", controlPlaneNodeIPv4()),
					},
					Packet: crdv1alpha1.Packet{
						IPHeader: crdv1alpha1.IPHeader{
							Protocol: protocolTCP,
						},
						TransportHeader: crdv1alpha1.TransportHeader{
							TCP: &crdv1alpha1.TCPHeader{
								DstPort: serverPodPort,
							},
						},
					},
				},
			},

			expectedPhase: crdv1alpha1.PacketCaptureSucceeded,
			expectedNum:   5,
		},
	}
	t.Run("testPacketCapture", func(t *testing.T) {
		for _, tc := range testcases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				runPacketCaptureTest(t, data, tc)
			})
		}
	})

}

// testPacketCaptureTCP verifies if PacketCapture can capture tcp packets. this function only contains basic
// cases with pod-to-pod.
func testPacketCaptureBasic(t *testing.T, data *TestData) {
	nodeIdx := 0
	if len(clusterInfo.windowsNodes) != 0 {
		nodeIdx = clusterInfo.windowsNodes[0]
	}
	node1 := nodeName(nodeIdx)

	node1Pods, _, _ := createTestAgnhostPods(t, data, 3, data.testNamespace, node1)
	err := createUDPServerPod(udpServerPodName, data.testNamespace, serverPodPort, node1)
	defer data.DeletePodAndWait(defaultTimeout, udpServerPodName, data.testNamespace)
	require.NoError(t, err)
	// test tcp server pod
	err = data.createServerPodWithLabels(tcpServerPodName, data.testNamespace, serverPodPort, nil)
	defer data.DeletePodAndWait(defaultTimeout, tcpServerPodName, data.testNamespace)
	require.NoError(t, err)
	err = data.createToolboxPodOnNode(pcToolboxPodName, data.testNamespace, node1, false)
	defer data.DeletePodAndWait(defaultTimeout, pcToolboxPodName, data.testNamespace)
	require.NoError(t, err)

	// Give a little time for Windows containerd Nodes to setup OVS.
	// Containerd configures port asynchronously, which could cause execution time of installing flow longer than docker.
	time.Sleep(time.Second * 1)

	testcases := []pcTestCase{
		{
			name:      "ipv4-tcp",
			ipVersion: 4,
			srcPod:    pcToolboxPodName,
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", data.testNamespace, pcToolboxPodName, data.testNamespace, tcpServerPodName)),
				},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Namespace: data.testNamespace,
						Pod:       pcToolboxPodName,
					},
					Destination: crdv1alpha1.Destination{
						Namespace: data.testNamespace,
						Pod:       tcpServerPodName,
					},
					Type: crdv1alpha1.PacketCaptureFirstN,
					FirstNCaptureConfig: &crdv1alpha1.PacketCaptureFirstNConfig{
						Number: 5,
					},
					FileServer: crdv1alpha1.BundleFileServer{
						URL: fmt.Sprintf("sftp://%s:30010/upload", controlPlaneNodeIPv4()),
					},
					Packet: crdv1alpha1.Packet{
						IPHeader: crdv1alpha1.IPHeader{
							Protocol: protocolTCP,
						},
						TransportHeader: crdv1alpha1.TransportHeader{
							TCP: &crdv1alpha1.TCPHeader{
								DstPort: serverPodPort,
							},
						},
					},
				},
			},
			expectedPhase: crdv1alpha1.PacketCaptureSucceeded,
			expectedNum:   5,
		},
		{
			name:      "ipv4-udp",
			ipVersion: 4,
			srcPod:    pcToolboxPodName,
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", data.testNamespace, pcToolboxPodName, data.testNamespace, udpServerPodName)),
				},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Namespace: data.testNamespace,
						Pod:       pcToolboxPodName,
					},
					Destination: crdv1alpha1.Destination{
						Namespace: data.testNamespace,
						Pod:       udpServerPodName,
					},

					Type:    crdv1alpha1.PacketCaptureFirstN,
					Timeout: 300,
					FirstNCaptureConfig: &crdv1alpha1.PacketCaptureFirstNConfig{
						Number: 5,
					},
					FileServer: crdv1alpha1.BundleFileServer{
						URL: fmt.Sprintf("sftp://%s:30010/upload", controlPlaneNodeIPv4()),
					},
					Packet: crdv1alpha1.Packet{
						IPHeader: crdv1alpha1.IPHeader{
							Protocol: protocolUDP,
						},
						TransportHeader: crdv1alpha1.TransportHeader{
							UDP: &crdv1alpha1.UDPHeader{
								DstPort: serverPodPort,
							},
						},
					},
				},
			},
			expectedPhase: crdv1alpha1.PacketCaptureSucceeded,
			expectedNum:   5,
		},
		{
			name:      "ipv4-icmp",
			ipVersion: 4,
			srcPod:    node1Pods[0],
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", data.testNamespace, node1Pods[0], data.testNamespace, node1Pods[1])),
				},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Namespace: data.testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: crdv1alpha1.Destination{
						Namespace: data.testNamespace,
						Pod:       node1Pods[1],
					},

					Type: crdv1alpha1.PacketCaptureFirstN,
					FirstNCaptureConfig: &crdv1alpha1.PacketCaptureFirstNConfig{
						Number: 5,
					},
					FileServer: crdv1alpha1.BundleFileServer{
						URL: fmt.Sprintf("sftp://%s:30010/upload", controlPlaneNodeIPv4()),
					},
					Packet: crdv1alpha1.Packet{
						IPHeader: crdv1alpha1.IPHeader{
							Protocol: protocolICMP,
						},
					},
				},
			},
			expectedPhase: crdv1alpha1.PacketCaptureSucceeded,
			expectedNum:   5,
		},
		{
			name:      "ipv6-icmp",
			ipVersion: 6,
			srcPod:    node1Pods[0],
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-ipv6", data.testNamespace, node1Pods[0], data.testNamespace, node1Pods[1])),
				},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Namespace: data.testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: crdv1alpha1.Destination{
						Namespace: data.testNamespace,
						Pod:       node1Pods[1],
					},

					Type: crdv1alpha1.PacketCaptureFirstN,
					FirstNCaptureConfig: &crdv1alpha1.PacketCaptureFirstNConfig{
						Number: 5,
					},
					FileServer: crdv1alpha1.BundleFileServer{
						URL: fmt.Sprintf("sftp://%s:30010/upload", controlPlaneNodeIPv4()),
					},
					Packet: crdv1alpha1.Packet{
						IPv6Header: &crdv1alpha1.IPv6Header{
							NextHeader: &protocolICMPv6,
						},
					},
				},
			},
			expectedPhase: crdv1alpha1.PacketCaptureSucceeded,
			expectedNum:   5,
		},
		{

			name:      "non-exist-pod",
			ipVersion: 4,
			srcPod:    node1Pods[0],
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", data.testNamespace, node1Pods[0], data.testNamespace, nonExistPodName)),
				},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Namespace: data.testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: crdv1alpha1.Destination{
						Namespace: data.testNamespace,
						Pod:       nonExistPodName,
					},
					Type: crdv1alpha1.PacketCaptureFirstN,
					FirstNCaptureConfig: &crdv1alpha1.PacketCaptureFirstNConfig{
						Number: 5,
					},
					FileServer: crdv1alpha1.BundleFileServer{
						URL: fmt.Sprintf("sftp://%s:30010/upload", controlPlaneNodeIPv4()),
					},
				},
			},
			expectedPhase:  crdv1alpha1.PacketCaptureFailed,
			expectedReason: fmt.Sprintf("Node: %s, Error: failed to get the destination pod %s/%s: pods \"%s\" not found", node1, data.testNamespace, nonExistPodName, nonExistPodName),
		},
	}
	t.Run("testPacketCaptureBasic", func(t *testing.T) {
		for _, tc := range testcases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				runPacketCaptureTest(t, data, tc)
			})
		}
	})
}

func getOSString() string {
	if len(clusterInfo.windowsNodes) != 0 {
		return "windows"
	} else {
		return "linux"
	}
}

func runPacketCaptureTest(t *testing.T, data *TestData, tc pcTestCase) {
	switch tc.ipVersion {
	case 4:
		skipIfNotIPv4Cluster(t)
	case 6:
		skipIfNotIPv6Cluster(t)
	}
	// wait for toolbox
	waitForPodIPs(t, data, []PodInfo{{pcToolboxPodName, getOSString(), "", data.testNamespace}})

	dstPodName := tc.pc.Spec.Destination.Pod
	var dstPodIPs *PodIPs
	if dstPodName != nonExistPodName && dstPodName != "" {
		// wait for pods to be ready first , or the pc will skip install flow
		podIPs := waitForPodIPs(t, data, []PodInfo{{dstPodName, getOSString(), "", data.testNamespace}})
		dstPodIPs = podIPs[dstPodName]
	}

	if _, err := data.crdClient.CrdV1alpha1().PacketCaptures().Create(context.TODO(), tc.pc, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Error when creating PacketCapture: %v", err)
	}
	defer func() {
		if err := data.crdClient.CrdV1alpha1().PacketCaptures().Delete(context.TODO(), tc.pc.Name, metav1.DeleteOptions{}); err != nil {
			t.Errorf("Error when deleting PacketCapture: %v", err)
		}
	}()

	if tc.pc.Spec.Destination.Pod != nonExistPodName {
		srcPod := tc.srcPod
		if dstIP := tc.pc.Spec.Destination.IP; dstIP != "" {
			ip := net.ParseIP(dstIP)
			if ip.To4() != nil {
				dstPodIPs = &PodIPs{IPv4: &ip}
			} else {
				dstPodIPs = &PodIPs{IPv6: &ip}
			}
		} else if tc.pc.Spec.Destination.Service != "" {
			ip := net.ParseIP(dstServiceIP)
			if ip.To4() != nil {
				dstPodIPs = &PodIPs{IPv4: &ip}
			} else {
				dstPodIPs = &PodIPs{IPv6: &ip}
			}
		}
		// Give a little time for Nodes to install OVS flows.
		time.Sleep(time.Second * 2)
		protocol := tc.pc.Spec.Packet.IPHeader.Protocol
		if tc.pc.Spec.Packet.IPv6Header != nil {
			protocol = *tc.pc.Spec.Packet.IPv6Header.NextHeader
		}
		server := dstPodIPs.IPv4.String()
		if tc.ipVersion == 6 {
			server = dstPodIPs.IPv6.String()
		}
		// Send an ICMP echo packet from the source Pod to the destination.
		if protocol == protocolICMP || protocol == protocolICMPv6 {
			if err := data.RunPingCommandFromTestPod(PodInfo{srcPod, getOSString(), "", data.testNamespace},
				data.testNamespace, dstPodIPs, agnhostContainerName, 10, 0, false); err != nil {
				t.Logf("Ping(%d) '%s' -> '%v' failed: ERROR (%v)", protocol, srcPod, *dstPodIPs, err)
			}
		} else if protocol == protocolTCP {
			for i := 1; i <= 5; i++ {
				if err := data.runNetcatCommandFromTestPodWithProtocol(tc.srcPod, data.testNamespace, toolboxContainerName, server, serverPodPort, "tcp"); err != nil {
					t.Logf("Netcat(TCP) '%s' -> '%v' failed: ERROR (%v)", srcPod, server, err)
				}
			}
		} else if protocol == protocolUDP {
			for i := 1; i <= 5; i++ {
				if err := data.runNetcatCommandFromTestPodWithProtocol(tc.srcPod, data.testNamespace, toolboxContainerName, server, serverPodPort, "udp"); err != nil {
					t.Logf("Netcat(UDP) '%s' -> '%v' failed: ERROR (%v)", srcPod, server, err)
				}
			}
		}
	}

	pc, err := data.waitForPacketCapture(t, tc.pc.Name, tc.expectedPhase)
	if err != nil {
		t.Fatalf("Error: Get PacketCapture failed: %v", err)
	}
	if tc.expectedPhase == crdv1alpha1.PacketCaptureFailed {
		if pc.Status.Reason != tc.expectedReason {
			t.Fatalf("Error: PacketCapture Error Reason should be %v, but got %s", tc.expectedReason, pc.Status.Reason)
		}
	}
	if pc.Status.NumCapturedPackets != tc.expectedNum {
		t.Fatalf("Error: PacketCapture captured packets count should be %v, but got %v", tc.expectedNum, pc.Status.NumCapturedPackets)
	}

}

func (data *TestData) waitForPacketCapture(t *testing.T, name string, phase crdv1alpha1.PacketCapturePhase) (*crdv1alpha1.PacketCapture, error) {
	var pc *crdv1alpha1.PacketCapture
	var err error
	timeout := 15 * time.Second
	if err = wait.PollUntilContextTimeout(context.Background(), defaultInterval, timeout, true, func(ctx context.Context) (bool, error) {
		pc, err = data.crdClient.CrdV1alpha1().PacketCaptures().Get(ctx, name, metav1.GetOptions{})
		if err != nil || pc.Status.Phase != phase {
			return false, nil
		}
		return true, nil
	}); err != nil {
		if pc != nil {
			t.Errorf("Latest PacketCapture status: %s %v", pc.Name, pc.Status)
		}
		return nil, err
	}
	return pc, nil
}
