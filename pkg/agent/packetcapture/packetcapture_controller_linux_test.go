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

package packetcapture

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/ssh"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/util"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/util/k8s"
)

var (
	pod1IPv4 = "192.168.10.10"
	pod2IPv4 = "192.168.11.10"

	ipv6         = "2001:db8::68"
	service1IPv4 = "10.96.0.10"
	pod1MAC, _   = net.ParseMAC("aa:bb:cc:dd:ee:0f")
	pod2MAC, _   = net.ParseMAC("aa:bb:cc:dd:ee:00")
	ofPortPod1   = uint32(1)
	ofPortPod2   = uint32(2)

	icmpProto = intstr.FromString("ICMP")

	pod1 = v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-1",
			Namespace: "default",
		},
		Status: v1.PodStatus{
			PodIP: pod1IPv4,
		},
	}
	pod2 = v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-2",
			Namespace: "default",
		},
		Status: v1.PodStatus{
			PodIP: pod2IPv4,
		},
	}
	pod3 = v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-3",
			Namespace: "default",
		},
	}

	secret1 = v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fileServerAuthSecretName,
			Namespace: "kube-system",
		},
		Data: map[string][]byte{
			"username": []byte("username"),
			"password": []byte("password"),
		},
	}
)

func generateTestSecret() *v1.Secret {
	return &v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "AAA",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"username": []byte("AAA"),
			"password": []byte("BBBCCC"),
		},
	}
}

type testUploader struct {
	url      string
	fileName string
}

func (uploader *testUploader) Upload(url string, fileName string, config *ssh.ClientConfig, outputFile afero.File) error {
	if url != uploader.url {
		return fmt.Errorf("expected url: %s for uploader, got: %s", uploader.url, url)
	}
	if fileName != uploader.fileName {
		return fmt.Errorf("expected filename: %s for uploader, got: %s", uploader.fileName, fileName)
	}
	return nil
}

type testCapture struct {
}

func (p *testCapture) Capture(ctx context.Context, device string, srcIP, dstIP net.IP, packet *crdv1alpha1.Packet) (chan gopacket.Packet, error) {
	// create test os
	defaultFS = afero.NewMemMapFs()
	// create test pcap file
	f, _, err := getPacketFileAndWriter("test-pcap-data")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// simulate packet file
	data := []byte{0xab, 0xcd, 0xef, 0x01, 0x02, 0x03, 0x04}
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Unix(12345667, 1234567000),
		Length:        700,
		CaptureLength: len(data),
	}
	err = func() error {
		w := pcapgo.NewWriter(f)
		if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
			return err
		}

		if err := w.WritePacket(ci, data); err != nil {
			return err
		}
		return nil
	}()
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("failed to upload to file server while setting offset: %v", err)
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	fileReader := bytes.NewReader(buf)
	r, err := pcapgo.NewReader(fileReader)
	if err != nil {
		return nil, err
	}

	source := gopacket.NewPacketSource(r, layers.LayerTypeEthernet)
	return source.Packets(), nil
}

type fakePacketCaptureController struct {
	*Controller
	kubeClient         kubernetes.Interface
	mockController     *gomock.Controller
	crdClient          *fakeversioned.Clientset
	crdInformerFactory crdinformers.SharedInformerFactory
	informerFactory    informers.SharedInformerFactory
}

func newFakePacketCaptureController(t *testing.T, runtimeObjects []runtime.Object, initObjects []runtime.Object) *fakePacketCaptureController {
	controller := gomock.NewController(t)
	objs := []runtime.Object{
		&pod1,
		&pod2,
		&pod3,
		&secret1,
	}
	objs = append(objs, generateTestSecret())
	if runtimeObjects != nil {
		objs = append(objs, runtimeObjects...)
	}
	kubeClient := fake.NewSimpleClientset(objs...)
	crdClient := fakeversioned.NewSimpleClientset(initObjects...)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	packetCaptureInformer := crdInformerFactory.Crd().V1alpha1().PacketCaptures()
	informerFactory := informers.NewSharedInformerFactory(kubeClient, 0)

	ifaceStore := interfacestore.NewInterfaceStore()
	addPodInterface(ifaceStore, pod1.Namespace, pod1.Name, []string{pod1IPv4, ipv6}, pod1MAC.String(), int32(ofPortPod1))
	addPodInterface(ifaceStore, pod2.Namespace, pod2.Name, []string{pod2IPv4}, pod2MAC.String(), int32(ofPortPod2))

	pcController := NewPacketCaptureController(
		kubeClient,
		crdClient,
		packetCaptureInformer,
		ifaceStore,
	)
	pcController.sftpUploader = &testUploader{}
	pcController.newPacketCapturerFn = func(pc *crdv1alpha1.PacketCapture) (PacketCapturer, error) {
		return &testCapture{}, nil
	}

	os.Setenv("POD_NAME", "antrea-agent")

	return &fakePacketCaptureController{
		Controller:         pcController,
		kubeClient:         kubeClient,
		mockController:     controller,
		crdClient:          crdClient,
		crdInformerFactory: crdInformerFactory,
		informerFactory:    informerFactory,
	}
}

func addPodInterface(ifaceStore interfacestore.InterfaceStore, podNamespace, podName string, podIPs []string, podMac string, ofPort int32) {
	containerName := k8s.NamespacedName(podNamespace, podName)
	var ifIPs []net.IP
	for _, ip := range podIPs {
		ifIPs = append(ifIPs, net.ParseIP(ip))
	}
	mac, _ := net.ParseMAC(podMac)
	ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		IPs:                      ifIPs,
		MAC:                      mac,
		InterfaceName:            util.GenerateContainerInterfaceName(podName, podNamespace, containerName),
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: podName, PodNamespace: podNamespace, ContainerID: containerName},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: ofPort},
	})
}

// TestPacketCaptureControllerRun was used to validate the whole run process is working. It doesn't wait for
// the testing pc to finish. on sandbox env, no good solution to open raw socket.
func TestStartPacketCapture(t *testing.T) {
	// create test os
	defaultFS = afero.NewMemMapFs()
	defaultFS.MkdirAll("/tmp/antrea/packetcapture/packets", 0755)
	pc := struct {
		name string
		pc   *crdv1alpha1.PacketCapture
	}{
		name: "start packetcapture",
		pc: &crdv1alpha1.PacketCapture{
			ObjectMeta: metav1.ObjectMeta{Name: "pc1", UID: "uid1"},
			Spec: crdv1alpha1.PacketCaptureSpec{
				Source: crdv1alpha1.Source{
					Pod: &crdv1alpha1.PodReference{
						Namespace: pod1.Namespace,
						Name:      pod1.Name,
					},
				},
				Destination: crdv1alpha1.Destination{
					Pod: &crdv1alpha1.PodReference{
						Namespace: pod2.Namespace,
						Name:      pod2.Name,
					},
				},
				CaptureConfig: crdv1alpha1.CaptureConfig{
					FirstN: &crdv1alpha1.PacketCaptureFirstNConfig{
						Number: 1,
					},
				},
				Packet: &crdv1alpha1.Packet{
					Protocol: &icmpProto,
				},
				FileServer: &crdv1alpha1.PacketCaptureFileServer{
					URL: "sftp://127.0.0.1:22/aaa",
				},
			},
		},
	}

	pcc := newFakePacketCaptureController(t, nil, []runtime.Object{pc.pc})
	pcc.sftpUploader = &testUploader{fileName: "pc1.pcapng"}
	stopCh := make(chan struct{})
	defer close(stopCh)
	pcc.crdInformerFactory.Start(stopCh)
	pcc.crdInformerFactory.WaitForCacheSync(stopCh)
	pcc.informerFactory.Start(stopCh)
	pcc.informerFactory.WaitForCacheSync(stopCh)
	pcc.startPacketCapture(pc.pc.Name)
	time.Sleep(300 * time.Millisecond)

	result, nil := pcc.crdClient.CrdV1alpha1().PacketCaptures().Get(context.Background(), pc.pc.Name, metav1.GetOptions{})
	assert.Nil(t, nil)

	// expected to capture 1 packet
	for _, cond := range result.Status.Conditions {
		if cond.Type == crdv1alpha1.PacketCaptureCompleted {
			assert.Equal(t, cond.Status, metav1.ConditionTrue)
		}
		if cond.Type == crdv1alpha1.PacketCaptureFileUploaded {
			assert.Equal(t, cond.Status, metav1.ConditionTrue)
		}
	}
	assert.Equal(t, int32(1), result.Status.NumberCaptured)
	assert.Equal(t, "sftp://127.0.0.1:22/aaa/pc1.pcapng", result.Status.FilePath)
}

func TestPacketCaptureUploadPackets(t *testing.T) {
	defaultFS = afero.NewMemMapFs()
	pcs := []struct {
		name        string
		pc          *crdv1alpha1.PacketCapture
		expectedErr string
		uploader    *testUploader
	}{
		{
			name: "sftp",
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{Name: "pc1", UID: "uid1"},
				Spec: crdv1alpha1.PacketCaptureSpec{
					FileServer: &crdv1alpha1.PacketCaptureFileServer{},
				},
			},
			uploader: &testUploader{fileName: "pc1.pcapng"},
		},
	}
	for _, pc := range pcs {
		t.Run(pc.name, func(t *testing.T) {
			pcc := newFakePacketCaptureController(t, nil, []runtime.Object{pc.pc})
			pcc.sftpUploader = pc.uploader
			stopCh := make(chan struct{})
			defer close(stopCh)
			pcc.crdInformerFactory.Start(stopCh)
			pcc.crdInformerFactory.WaitForCacheSync(stopCh)

			file, _ := defaultFS.Create(pc.name)
			err := pcc.uploadPackets(pc.pc, file)
			if pc.expectedErr != "" {
				assert.Equal(t, err.Error(), pc.expectedErr)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestMergeConditions(t *testing.T) {
	tt := []struct {
		name     string
		new      []crdv1alpha1.PacketCaptureCondition
		old      []crdv1alpha1.PacketCaptureCondition
		expected []crdv1alpha1.PacketCaptureCondition
	}{

		{
			name: "use-old",
			new: []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.PacketCaptureCompleted,
					LastTransitionTime: metav1.Now(),
				},
				{
					Type:               crdv1alpha1.PacketCaptureFileUploaded,
					LastTransitionTime: metav1.Now(),
				},
			},
			old: []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.PacketCaptureCompleted,
					LastTransitionTime: metav1.Now(),
				},
			},
			expected: []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.PacketCaptureCompleted,
					LastTransitionTime: metav1.Now(),
				},
				{
					Type:               crdv1alpha1.PacketCaptureFileUploaded,
					LastTransitionTime: metav1.Now(),
				},
			},
		},
		{
			name: "use-new",
			new: []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.PacketCaptureCompleted,
					LastTransitionTime: metav1.Now(),
					Status:             metav1.ConditionTrue,
				},
				{
					Type:               crdv1alpha1.PacketCaptureFileUploaded,
					LastTransitionTime: metav1.Now(),
				},
			},
			old: []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.PacketCaptureCompleted,
					LastTransitionTime: metav1.Now(),
					Status:             metav1.ConditionFalse,
				},
			},
			expected: []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.PacketCaptureCompleted,
					LastTransitionTime: metav1.Now(),
					Status:             metav1.ConditionTrue,
				},
				{
					Type:               crdv1alpha1.PacketCaptureFileUploaded,
					LastTransitionTime: metav1.Now(),
				},
			},
		},
	}

	for _, item := range tt {
		t.Run(item.name, func(t *testing.T) {
			result := mergeConditions(item.old, item.new)
			assert.True(t, conditionSliceEqualsIgnoreLastTransitionTime(item.expected, result))
		})
	}
}
