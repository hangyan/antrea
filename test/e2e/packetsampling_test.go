package e2e

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/features"
)

var (
	psNamespace                 = "default"
	psSecretName                = "ps-secret"
	psNginxPodName              = "test-nginx"
	psBusyboxPodName            = "busybox"
	mixProtoServerPodName       = "mix-proto-server"
	serverPort            int32 = 8080
)

type psTestCase struct {
	name            string
	ps              *crdv1alpha1.PacketSampling
	expectedPhase   crdv1alpha1.PacketSamplingPhase
	expectedReasons []string
	expectedNum     int32
	// required IP version, skip if not match, default is 0 (no restrict)
	ipVersion int
	// Source Pod to run ping for live-traffic PacketSampling.
	srcPod       string
	skipIfNeeded func(t *testing.T)
}

// TestPacketSampling is the top-level test which contains all subtests for
// PacketSampling related test cases so they can share setup, teardown.
func TestPacketSampling(t *testing.T) {
	skipIfPacketSamplingDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	// setup sftp server for test.
	sftpServiceYAML := "sftp-deployment.yml"
	secretUserName := "foo"
	secretPassword := "pass"
	//uploadFolder := "upload"
	//uploadPath := path.Join("/home", secretUserName, uploadFolder)

	applySFTPYamlCommand := fmt.Sprintf("kubectl apply -f %s -n %s", sftpServiceYAML, data.testNamespace)
	code, stdout, stderr, err := data.RunCommandOnNode(controlPlaneNodeName(), applySFTPYamlCommand)
	require.NoError(t, err)
	defer func() {
		deleteSFTPYamlCommand := fmt.Sprintf("kubectl delete -f %s -n %s", sftpServiceYAML, data.testNamespace)
		data.RunCommandOnNode(controlPlaneNodeName(), deleteSFTPYamlCommand)
	}()
	t.Logf("Stdout of the command '%s': %s", applySFTPYamlCommand, stdout)
	if code != 0 {
		t.Errorf("Error when applying %s: %v", sftpServiceYAML, stderr)
	}
	failOnError(data.waitForDeploymentReady(t, data.testNamespace, "sftp", defaultTimeout), t)

	sec := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: psSecretName,
		},
		Data: map[string][]byte{
			"username": []byte(secretUserName),
			"password": []byte(secretPassword),
		},
	}
	_, err = data.clientset.CoreV1().Secrets(psNamespace).Create(context.TODO(), sec, metav1.CreateOptions{})
	require.NoError(t, err)
	defer data.clientset.CoreV1().Secrets(psNamespace).Delete(context.TODO(), psSecretName, metav1.DeleteOptions{})

	t.Run("testPacketSamplingIntraNode", func(t *testing.T) {
		testPacketSamplingIntraNode(t, data)
	})

}

func skipIfPacketSamplingDisabled(t *testing.T) {
	skipIfFeatureDisabled(t, features.PacketSampling, false, false)
}

// testPacketSamplingTCP verifies if PacketSampling can capture tcp packets.
func testPacketSamplingIntraNode(t *testing.T, data *TestData) {
	nodeIdx := 0
	if len(clusterInfo.windowsNodes) != 0 {
		nodeIdx = clusterInfo.windowsNodes[0]
	}
	node1 := nodeName(nodeIdx)

	node1Pods, _, node1CleanupFn := createTestAgnhostPods(t, data, 2, data.testNamespace, node1)
	defer node1CleanupFn()
	err := data.createNginxPodOnNode(psNginxPodName, data.testNamespace, node1, false)
	require.NoError(t, err)
	defer deletePodWrapper(t, data, data.testNamespace, psNginxPodName)

	err = data.createUDPAndTCPServerPod(mixProtoServerPodName, data.testNamespace, serverPodPort, node1)
	require.NoError(t, err)
	defer deletePodWrapper(t, data, data.testNamespace, mixProtoServerPodName)

	err = data.createBusyboxPodOnNode(psBusyboxPodName, data.testNamespace, node1, false)
	require.NoError(t, err)
	defer deletePodWrapper(t, data, data.testNamespace, psNginxPodName)

	// Give a little time for Windows containerd Nodes to setup OVS.
	// Containerd configures port asynchronously, which could cause execution time of installing flow longer than docker.
	time.Sleep(time.Second * 1)

	testcases := []psTestCase{
		{
			name:      "intraNodePacketSamplingIPv4",
			ipVersion: 4,
			srcPod:    psBusyboxPodName,
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", data.testNamespace, node1Pods[0], data.testNamespace, node1Pods[1])),
				},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: data.testNamespace,
						Pod:       psBusyboxPodName,
					},
					Destination: crdv1alpha1.Destination{
						Namespace: data.testNamespace,
						Pod:       psNginxPodName,
					},
					Type: crdv1alpha1.FirstNSampling,
					FirstNSamplingConfig: &crdv1alpha1.FirstNSamplingConfig{
						Number: 5,
					},
					FileServer: crdv1alpha1.BundleFileServer{
						URL: fmt.Sprintf("%s:30010/upload", controlPlaneNodeIPv4()),
					},
					Authentication: crdv1alpha1.BundleServerAuthConfiguration{
						AuthType: "BasicAuthentication",
						AuthSecret: &v1.SecretReference{
							Name:      psSecretName,
							Namespace: psNamespace,
						},
					},
					Packet: crdv1alpha1.Packet{
						IPHeader: crdv1alpha1.IPHeader{
							Protocol: protocolTCP,
						},
						TransportHeader: crdv1alpha1.TransportHeader{
							TCP: &crdv1alpha1.TCPHeader{
								DstPort: 80,
							},
						},
					},
				},
			},
			expectedPhase: crdv1alpha1.PacketSamplingSucceeded,
			expectedNum:   5,
		},
		{
			name:      "intraNodeUDPPacketSamplingIPv4",
			ipVersion: 4,
			srcPod:    psBusyboxPodName,
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", data.testNamespace, node1Pods[0], data.testNamespace, node1Pods[1])),
				},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: data.testNamespace,
						Pod:       psBusyboxPodName,
					},
					Destination: crdv1alpha1.Destination{
						Namespace: data.testNamespace,
						Pod:       mixProtoServerPodName,
					},

					Type: crdv1alpha1.FirstNSampling,
					FirstNSamplingConfig: &crdv1alpha1.FirstNSamplingConfig{
						Number: 5,
					},
					FileServer: crdv1alpha1.BundleFileServer{
						URL: fmt.Sprintf("%s:30010/upload", controlPlaneNodeIPv4()),
					},
					Authentication: crdv1alpha1.BundleServerAuthConfiguration{
						AuthType: "BasicAuthentication",
						AuthSecret: &v1.SecretReference{
							Name:      psSecretName,
							Namespace: psNamespace,
						},
					},
					Packet: crdv1alpha1.Packet{
						IPHeader: crdv1alpha1.IPHeader{
							Protocol: protocolUDP,
						},
						TransportHeader: crdv1alpha1.TransportHeader{
							UDP: &crdv1alpha1.UDPHeader{
								DstPort: serverPort,
							},
						},
					},
				},
			},
			expectedPhase: crdv1alpha1.PacketSamplingSucceeded,
			expectedNum:   5,
		},
	}
	t.Run("testPacketSamplingIntraNode", func(t *testing.T) {
		for _, tc := range testcases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				runPacketSamplingTest(t, data, tc)
			})
		}
	})
}

func runPacketSamplingTest(t *testing.T, data *TestData, tc psTestCase) {
	switch tc.ipVersion {
	case 4:
		skipIfNotIPv4Cluster(t)
	case 6:
		skipIfNotIPv6Cluster(t)
	}
	if tc.skipIfNeeded != nil {
		tc.skipIfNeeded(t)
	}
	if _, err := data.crdClient.CrdV1alpha1().PacketSamplings().Create(context.TODO(), tc.ps, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Error when creating PacketSampling: %v", err)
	}
	defer func() {
		if err := data.crdClient.CrdV1alpha1().PacketSamplings().Delete(context.TODO(), tc.ps.Name, metav1.DeleteOptions{}); err != nil {
			t.Errorf("Error when deleting PacketSampling: %v", err)
		}
	}()

	// LiveTraffic PacketSampling test supports only ICMP traffic from
	// the source Pod to an IP or another Pod.
	osString := "linux"
	if len(clusterInfo.windowsNodes) != 0 {
		osString = "windows"
	}
	var dstPodIPs *PodIPs
	srcPod := tc.srcPod
	if dstIP := tc.ps.Spec.Destination.IP; dstIP != "" {
		ip := net.ParseIP(dstIP)
		if ip.To4() != nil {
			dstPodIPs = &PodIPs{IPv4: &ip}
		} else {
			dstPodIPs = &PodIPs{IPv6: &ip}
		}
	} else {
		dstPod := tc.ps.Spec.Destination.Pod
		podIPs := waitForPodIPs(t, data, []PodInfo{{dstPod, osString, "", ""}})
		dstPodIPs = podIPs[dstPod]
	}
	// Give a little time for Nodes to install OVS flows.
	time.Sleep(time.Second * 2)
	protocol := tc.ps.Spec.Packet.IPHeader.Protocol
	server := dstPodIPs.IPv4.String()
	if tc.ipVersion == 6 {
		server = dstPodIPs.IPv6.String()
	}
	// Send an ICMP echo packet from the source Pod to the destination.
	if protocol == protocolICMP {
		if err := data.RunPingCommandFromTestPod(PodInfo{srcPod, osString, "", ""},
			data.testNamespace, dstPodIPs, agnhostContainerName, 10, 0, false); err != nil {
			t.Logf("Ping '%s' -> '%v' failed: ERROR (%v)", srcPod, *dstPodIPs, err)
		}
	} else if protocol == protocolTCP {
		url := fmt.Sprintf("%s:%v", server, tc.ps.Spec.Packet.TransportHeader.TCP.DstPort)
		if _, _, err := data.runWgetCommandOnBusyboxWithRetry(tc.srcPod, data.testNamespace, url, 3); err != nil {
			t.Logf("wget '%s' -> '%v' failed: ERROR (%v)", srcPod, url, err)
		}
	} else if protocol == protocolUDP {
		for i := 1; i <= 5; i++ {
			if err := data.runNetcatCommandFromTestPodWithProtocol(tc.srcPod, data.testNamespace, busyboxContainerName, server, serverPort, "udp"); err != nil {
				t.Logf("Netcat(UDP) '%s' -> '%v' failed: ERROR (%v)", srcPod, server, err)
			}
		}
	}

	ps, err := data.waitForPacketSampling(t, tc.ps.Name, tc.expectedPhase)
	if err != nil {
		t.Fatalf("Error: Get PacketSampling failed: %v", err)
	}
	if tc.expectedPhase == crdv1alpha1.PacketSamplingFailed {
		isReasonMatch := false
		for _, expectedReason := range tc.expectedReasons {
			if ps.Status.Reason == expectedReason {
				isReasonMatch = true
			}
		}
		if !isReasonMatch {
			t.Fatalf("Error: PacketSampling Error Reason should be %v, but got %s", tc.expectedReasons, ps.Status.Reason)
		}
	}
	if ps.Status.NumCapturedPackets != tc.expectedNum {
		t.Fatalf("Error: PacketSampling captured packets count should be %v, but got %v", tc.expectedNum, ps.Status.NumCapturedPackets)
	}

}

func (data *TestData) waitForPacketSampling(t *testing.T, name string, phase crdv1alpha1.PacketSamplingPhase) (*crdv1alpha1.PacketSampling, error) {
	var ps *crdv1alpha1.PacketSampling
	var err error
	timeout := 15 * time.Second
	if err = wait.PollImmediate(defaultInterval, timeout, func() (bool, error) {
		ps, err = data.crdClient.CrdV1alpha1().PacketSamplings().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil || ps.Status.Phase != phase {
			return false, nil
		}
		return true, nil
	}); err != nil {
		if ps != nil {
			t.Errorf("Latest PacketSampling status: %s %v", ps.Name, ps.Status)
		}
		return nil, err
	}
	return ps, nil
}
