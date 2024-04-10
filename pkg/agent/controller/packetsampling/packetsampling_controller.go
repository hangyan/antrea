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

package packetsampling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"antrea.io/libOpenflow/protocol"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/afero"
	"golang.org/x/time/rate"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/util"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	clientsetversioned "antrea.io/antrea/pkg/client/clientset/versioned"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/util/ftp"
)

type StorageProtocolType string

const (
	sftpProtocol StorageProtocolType = "sftp"
)

const (
	controllerName               = "AntreaAgentPacketSamplingController"
	resyncPeriod   time.Duration = 0

	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second

	defaultWorkers = 4

	// 4bits in ovs reg4
	minTagNum uint8 = 1
	maxTagNum uint8 = 15

	// reason for timeout
	samplingTimeoutReason  = "PacketSampling timeout"
	defaultTimeoutDuration = time.Second * time.Duration(crdv1alpha1.DefaultPacketSamplingTimeout)

	samplingStatusUpdatePeriod = 10 * time.Second
)

var (
	timeoutCheckInterval = 10 * time.Second

	packetDirectory = getPacketDirectory()
	defaultFS       = afero.NewOsFs()
)

func getPacketDirectory() string {
	return filepath.Join(os.TempDir(), "antrea", "packetsampling", "packets")
}

type packetSamplingState struct {
	// name is the PacketSampling name
	name string
	// tag is a node scope unique id for the PacketSampling. It will be write into ovs reg and parsed in packetIn handler
	// to match with existing PacketSampling.
	tag uint8
	// shouldSyncPackets means this node will be responsible for doing the actual packet capture job.
	shouldSyncPackets bool
	// numCapturedPackets record how many packets has been captured. Due to the RateLimiter,
	// this maybe not be realtime data.
	numCapturedPackets int32
	// maxNumCapturedPackets is target number limit for our capture. If numCapturedPackets=maxNumCapturedPackets, means
	// the PacketSampling is succeeded.
	maxNumCapturedPackets int32
	// updateRateLimiter controls the frequency of the updates to PacketSampling status.
	updateRateLimiter *rate.Limiter
	// pcapngFile is the file object for the packet file.
	pcapngFile afero.File
	// pcapngWriter is the writer for the packet file.
	pcapngWriter *pcapgo.NgWriter
}

type Controller struct {
	kubeClient                  clientset.Interface
	crdClient                   clientsetversioned.Interface
	serviceLister               corelisters.ServiceLister
	serviceListerSynced         cache.InformerSynced
	endpointLister              corelisters.EndpointsLister
	endpointSynced              cache.InformerSynced
	packetSamplingInformer      crdinformers.PacketSamplingInformer
	packetSamplingLister        crdlisters.PacketSamplingLister
	packetSamplingSynced        cache.InformerSynced
	ofClient                    openflow.Client
	interfaceStore              interfacestore.InterfaceStore
	nodeConfig                  *config.NodeConfig
	queue                       workqueue.RateLimitingInterface
	runningPacketSamplingsMutex sync.RWMutex
	runningPacketSamplings      map[uint8]*packetSamplingState
	sftpUploader                ftp.UpLoader
}

func NewPacketSamplingController(
	kubeClient clientset.Interface,
	crdClient clientsetversioned.Interface,
	serviceInformer coreinformers.ServiceInformer,
	endpointInformer coreinformers.EndpointsInformer,
	packetSamplingInformer crdinformers.PacketSamplingInformer,
	client openflow.Client,
	interfaceStore interfacestore.InterfaceStore,
	nodeConfig *config.NodeConfig,
) *Controller {
	c := &Controller{
		kubeClient:             kubeClient,
		crdClient:              crdClient,
		packetSamplingInformer: packetSamplingInformer,
		packetSamplingLister:   packetSamplingInformer.Lister(),
		packetSamplingSynced:   packetSamplingInformer.Informer().HasSynced,
		ofClient:               client,
		interfaceStore:         interfaceStore,
		nodeConfig:             nodeConfig,
		queue: workqueue.NewRateLimitingQueueWithConfig(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay),
			workqueue.RateLimitingQueueConfig{Name: "packetsampling"}),
		runningPacketSamplings: make(map[uint8]*packetSamplingState),
		sftpUploader:           &ftp.SftpUploader{},
	}

	packetSamplingInformer.Informer().AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addPacketSampling,
		UpdateFunc: c.updatePacketSampling,
		DeleteFunc: c.deletePacketSampling,
	}, resyncPeriod)

	c.ofClient.RegisterPacketInHandler(uint8(openflow.PacketInCategoryPS), c)

	c.serviceLister = serviceInformer.Lister()
	c.serviceListerSynced = serviceInformer.Informer().HasSynced
	c.endpointLister = endpointInformer.Lister()
	c.endpointSynced = endpointInformer.Informer().HasSynced
	return c
}

func (c *Controller) enqueuePacketSampling(ps *crdv1alpha1.PacketSampling) {
	c.queue.Add(ps.Name)
}

// Run will create defaultWorkers workers (go routines) which will process the PacketSampling events from the
// workqueue.
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting packetsampling controller", "name", controllerName)
	defer klog.InfoS("Shutting down packetsampling controller", "name", controllerName)

	cacheSynced := []cache.InformerSynced{c.packetSamplingSynced, c.serviceListerSynced, c.endpointSynced}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSynced...) {
		return
	}

	err := defaultFS.MkdirAll(packetDirectory, 0755)
	if err != nil {
		klog.ErrorS(err, "Couldn't create directory for storing sampling packets", "directory", packetDirectory)
		return
	}

	go func() {
		wait.Until(c.checkPacketSamplingTimeout, timeoutCheckInterval, stopCh)
	}()

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (c *Controller) checkPacketSamplingTimeout() {
	c.runningPacketSamplingsMutex.RLock()
	ss := make([]string, 0, len(c.runningPacketSamplings))
	for _, psState := range c.runningPacketSamplings {
		ss = append(ss, psState.name)
	}
	c.runningPacketSamplingsMutex.RUnlock()
	for _, psName := range ss {
		// Re-post all running PacketSampling requests to the work queue to
		// be processed and checked for timeout.
		c.queue.Add(psName)
	}
}

func (c *Controller) addPacketSampling(obj interface{}) {
	ps := obj.(*crdv1alpha1.PacketSampling)
	klog.InfoS("Processing PacketSampling ADD event", "name", ps.Name)
	c.enqueuePacketSampling(ps)
}

func (c *Controller) updatePacketSampling(_, obj interface{}) {
	ps := obj.(*crdv1alpha1.PacketSampling)
	klog.InfoS("Processing PacketSampling UPDATE EVENT", "name", ps.Name)
	c.enqueuePacketSampling(ps)
}

func (c *Controller) deletePacketSampling(obj interface{}) {
	ps := obj.(*crdv1alpha1.PacketSampling)
	klog.InfoS("Processing PacketSampling DELETE event", "name", ps.Name)
	err := deletePcapngFile(string(ps.UID))
	if err != nil {
		klog.ErrorS(err, "Couldn't delete pcapng file")
	}
	c.enqueuePacketSampling(ps)
}

func deletePcapngFile(uid string) error {
	return defaultFS.Remove(uidToPath(uid))
}

func uidToPath(uid string) string {
	return filepath.Join(packetDirectory, uid+".pcapng")
}

func (c *Controller) worker() {
	for c.processPacketSamplingItem() {
	}
}

func (c *Controller) processPacketSamplingItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}

	defer c.queue.Done(obj)
	if key, ok := obj.(string); !ok {
		c.queue.Forget(obj)
		klog.ErrorS(nil, "Expected string in work queue but got", "obj", obj)
		return true
	} else if err := c.syncPacketSampling(key); err == nil {
		c.queue.Forget(key)
	} else {
		klog.ErrorS(err, "Error syncing PacketSampling, exiting", "key", key)
	}
	return true
}

func (c *Controller) cleanupPacketSampling(psName string) {
	psState := c.deletePacketSamplingState(psName)
	if psState != nil {
		err := c.ofClient.UninstallPacketSamplingFlows(psState.tag)
		if err != nil {
			klog.ErrorS(err, "Error cleaning up flows for PacketSampling", "name", psName)
		}
		if err := psState.pcapngFile.Close(); err != nil {
			klog.ErrorS(err, "Error closing pcap file", "name", psName)
		}
	}
}

func (c *Controller) deletePacketSamplingState(psName string) *packetSamplingState {
	c.runningPacketSamplingsMutex.Lock()
	defer c.runningPacketSamplingsMutex.Unlock()

	for tag, state := range c.runningPacketSamplings {
		if state.name == psName {
			delete(c.runningPacketSamplings, tag)
			return state
		}
	}
	return nil
}

func (c *Controller) startPacketSampling(ps *crdv1alpha1.PacketSampling, psState *packetSamplingState) error {
	var err error
	defer func() {
		if err != nil {
			c.cleanupPacketSampling(ps.Name)
			c.updatePacketSamplingStatus(ps, crdv1alpha1.PacketSamplingFailed, fmt.Sprintf("Node: %s, error:%+v", c.nodeConfig.Name, err), 0)

		}
	}()
	receiverOnly := false
	senderOnly := false
	var pod, ns string

	if ps.Spec.Source.Pod != "" {
		pod = ps.Spec.Source.Pod
		ns = ps.Spec.Source.Namespace
		if ps.Spec.Destination.Pod == "" {
			senderOnly = true
		}
	} else {
		pod = ps.Spec.Destination.Pod
		ns = ps.Spec.Destination.Namespace
		receiverOnly = true
	}

	podInterfaces := c.interfaceStore.GetContainerInterfacesByPod(pod, ns)
	psState.shouldSyncPackets = len(podInterfaces) > 0
	if !psState.shouldSyncPackets {
		return nil
	}
	var packet, senderPacket *binding.Packet
	var endpointPackets []binding.Packet
	var ofPort uint32
	packet, err = c.preparePacket(ps, podInterfaces[0], receiverOnly)
	if err != nil {
		return err
	}
	ofPort = uint32(podInterfaces[0].OFPort)
	senderPacket = packet
	klog.V(2).InfoS("PacketSampling sender packet", "packet", *packet)
	if senderOnly && ps.Spec.Destination.Service != "" {
		endpointPackets, err = c.genEndpointMatchPackets(ps)
		if err != nil {
			return fmt.Errorf("couldn't generate endpoint match packets: %w", err)
		}
	}

	c.runningPacketSamplingsMutex.Lock()
	psState.maxNumCapturedPackets = ps.Spec.FirstNSamplingConfig.Number
	var file afero.File
	filePath := uidToPath(string(ps.UID))
	if _, err := os.Stat(filePath); err == nil {
		return fmt.Errorf("packet file already exists. this may be due to an unexpected termination")
	} else if os.IsNotExist(err) {
		file, err = defaultFS.Create(filePath)
		if err != nil {
			return fmt.Errorf("failed to create pcapng file: %w", err)
		}
	} else {
		return fmt.Errorf("couldn't check if the file exists: %w", err)
	}
	writer, err := pcapgo.NewNgWriter(file, layers.LinkTypeEthernet)
	if err != nil {
		return fmt.Errorf("couldn't init pcap writer: %w", err)
	}
	psState.shouldSyncPackets = len(podInterfaces) > 0
	psState.pcapngFile = file
	psState.pcapngWriter = writer
	psState.updateRateLimiter = rate.NewLimiter(rate.Every(samplingStatusUpdatePeriod), 1)
	c.runningPacketSamplings[psState.tag] = psState
	c.runningPacketSamplingsMutex.Unlock()

	timeout := ps.Spec.Timeout
	if timeout == 0 {
		timeout = crdv1alpha1.DefaultPacketSamplingTimeout
	}
	klog.V(2).InfoS("Installing flow entries for PacketSampling", "name", ps.Name)
	err = c.ofClient.InstallPacketSamplingFlows(psState.tag, senderOnly, receiverOnly, senderPacket, endpointPackets, ofPort, timeout)
	if err != nil {
		klog.ErrorS(err, "Install flow entries failed", "name", ps.Name)
	}
	return err
}

// genEndpointMatchPackets generates match packets (with destination Endpoint's IP/port info) besides the normal match packet.
// these match packets will help the pipeline to capture the pod -> svc traffic.
// TODO: 1. support name based port name 2. dual-stack support
func (c *Controller) genEndpointMatchPackets(ps *crdv1alpha1.PacketSampling) ([]binding.Packet, error) {
	var port int32
	if ps.Spec.Packet.TransportHeader.TCP != nil {
		port = ps.Spec.Packet.TransportHeader.TCP.DstPort
	} else if ps.Spec.Packet.TransportHeader.UDP != nil {
		port = ps.Spec.Packet.TransportHeader.UDP.DstPort
	}
	var packets []binding.Packet
	dstSvc, err := c.serviceLister.Services(ps.Spec.Destination.Namespace).Get(ps.Spec.Destination.Service)
	if err != nil {
		return nil, err
	}
	for _, item := range dstSvc.Spec.Ports {
		if item.Port == port {
			if item.TargetPort.Type == intstr.Int {
				port = item.TargetPort.IntVal
			}
		}
	}
	dstEndpoint, err := c.endpointLister.Endpoints(ps.Spec.Destination.Namespace).Get(ps.Spec.Destination.Service)
	if err != nil {
		return nil, err
	}
	for _, item := range dstEndpoint.Subsets[0].Addresses {
		packet := binding.Packet{}
		packet.DestinationIP = net.ParseIP(item.IP)
		if port != 0 {
			packet.DestinationPort = uint16(port)
		}
		packet.IPProto, _ = parseTargetProto(&ps.Spec.Packet)
		packets = append(packets, packet)
	}
	return packets, nil
}

func (c *Controller) preparePacket(ps *crdv1alpha1.PacketSampling, intf *interfacestore.InterfaceConfig, receiverOnly bool) (*binding.Packet, error) {
	packet := new(binding.Packet)
	packet.IsIPv6 = ps.Spec.Packet.IPv6Header != nil

	if receiverOnly {
		if ps.Spec.Source.IP != "" {
			packet.SourceIP = net.ParseIP(ps.Spec.Source.IP)
		}
		packet.DestinationMAC = intf.MAC
	} else if ps.Spec.Destination.IP != "" {
		packet.DestinationIP = net.ParseIP(ps.Spec.Destination.IP)
	} else if ps.Spec.Destination.Pod != "" {
		dstPodInterfaces := c.interfaceStore.GetContainerInterfacesByPod(ps.Spec.Destination.Pod, ps.Spec.Destination.Namespace)
		if len(dstPodInterfaces) > 0 {
			if packet.IsIPv6 {
				packet.DestinationIP = dstPodInterfaces[0].GetIPv6Addr()
			} else {
				packet.DestinationIP = dstPodInterfaces[0].GetIPv4Addr()
			}
		} else {
			dstPod, err := c.kubeClient.CoreV1().Pods(ps.Spec.Destination.Namespace).Get(context.TODO(), ps.Spec.Destination.Pod, metav1.GetOptions{})
			if err != nil {
				return nil, fmt.Errorf("failed to get the destination pod %s/%s: %v", ps.Spec.Destination.Namespace, ps.Spec.Destination.Pod, err)
			}
			podIPs := make([]net.IP, len(dstPod.Status.PodIPs))
			for i, ip := range dstPod.Status.PodIPs {
				podIPs[i] = net.ParseIP(ip.IP)
			}
			if packet.IsIPv6 {
				packet.DestinationIP, _ = util.GetIPWithFamily(podIPs, util.FamilyIPv6)
			} else {
				packet.DestinationIP = util.GetIPv4Addr(podIPs)
			}
		}
		if packet.DestinationIP == nil {
			if packet.IsIPv6 {
				return nil, errors.New("destination Pod does not have an IPv6 address")
			}
			return nil, errors.New("destination Pod does not have an IPv4 address")
		}
	} else if ps.Spec.Destination.Service != "" {
		dstSvc, err := c.serviceLister.Services(ps.Spec.Destination.Namespace).Get(ps.Spec.Destination.Service)
		if err != nil {
			return nil, fmt.Errorf("failed to get the destination service %s/%s: %v", ps.Spec.Destination.Namespace, ps.Spec.Destination.Service, err)
		}
		if dstSvc.Spec.ClusterIP == "" {
			return nil, errors.New("destination Service does not have a ClusterIP")
		}

		packet.DestinationIP = net.ParseIP(dstSvc.Spec.ClusterIP)
		if !packet.IsIPv6 {
			packet.DestinationIP = packet.DestinationIP.To4()
			if packet.DestinationIP == nil {
				return nil, errors.New("destination Service does not have an IPv4 address")
			}
		} else if packet.DestinationIP.To4() != nil {
			return nil, errors.New("destination Service does not have an IPv6 address")
		}
	} else {
		return nil, errors.New("destination is not specified")
	}

	if ps.Spec.Packet.TransportHeader.TCP != nil {
		packet.SourcePort = uint16(ps.Spec.Packet.TransportHeader.TCP.SrcPort)
		packet.DestinationPort = uint16(ps.Spec.Packet.TransportHeader.TCP.DstPort)
		if ps.Spec.Packet.TransportHeader.TCP.Flags != 0 {
			packet.TCPFlags = uint8(ps.Spec.Packet.TransportHeader.TCP.Flags)
		}
	} else if ps.Spec.Packet.TransportHeader.UDP != nil {
		packet.SourcePort = uint16(ps.Spec.Packet.TransportHeader.UDP.SrcPort)
		packet.DestinationPort = uint16(ps.Spec.Packet.TransportHeader.UDP.DstPort)
	}

	proto, err := parseTargetProto(&ps.Spec.Packet)
	if err != nil {
		return nil, err
	}
	packet.IPProto = proto
	return packet, nil
}

func parseTargetProto(packet *crdv1alpha1.Packet) (uint8, error) {
	var ipProto uint8
	var isIPv6 bool
	if packet.IPv6Header != nil {
		isIPv6 = true
		if packet.IPv6Header.NextHeader != nil {
			ipProto = uint8(*packet.IPv6Header.NextHeader)
		}
	} else if packet.IPHeader.Protocol != 0 {
		ipProto = uint8(packet.IPHeader.Protocol)
	}

	proto2 := ipProto
	if packet.TransportHeader.TCP != nil {
		proto2 = protocol.Type_TCP
	} else if packet.TransportHeader.UDP != nil {
		proto2 = protocol.Type_UDP
	} else if packet.TransportHeader.ICMP != nil || ipProto == 0 {
		proto2 = protocol.Type_ICMP
		if isIPv6 {
			proto2 = protocol.Type_IPv6ICMP
		}
	}

	if ipProto != 0 && proto2 != ipProto {
		return 0, errors.New("conflicting protocol settings in ipHeader and transportHeader")
	}
	return proto2, nil
}

func (c *Controller) syncPacketSampling(psName string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).InfoS("Finished syncing PacketSampling", "name", psName, "startTime", time.Since(startTime))
	}()

	ps, err := c.packetSamplingLister.Get(psName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			c.cleanupPacketSampling(psName)
			return nil
		}
		return err
	}

	switch ps.Status.Phase {
	case "":
		err = c.initPacketSampling(ps)
	case crdv1alpha1.PacketSamplingRunning:
		err = c.checkPacketSamplingStatus(ps)
	default:
		c.cleanupPacketSampling(psName)
	}
	return err

}

// Allocates a tag. If the PacketSampling request has been allocated with a tag
// already, 0 is returned. If number of existing PacketSampling requests reaches
// the upper limit, an error is returned.
func (c *Controller) allocateTag(name string) (uint8, error) {
	c.runningPacketSamplingsMutex.Lock()
	defer c.runningPacketSamplingsMutex.Unlock()

	for _, state := range c.runningPacketSamplings {
		if state != nil && state.name == name {
			// The packetsampling request has been processed already.
			return 0, nil
		}
	}
	for i := minTagNum; i <= maxTagNum; i += 1 {
		if _, ok := c.runningPacketSamplings[i]; !ok {
			c.runningPacketSamplings[i] = &packetSamplingState{
				name: name,
				tag:  i,
			}
			return i, nil
		}
	}
	return 0, fmt.Errorf("number of on-going PacketSampling operations already reached the upper limit: %d", maxTagNum)
}

func (c *Controller) getUploaderByProtocol(protocol StorageProtocolType) (ftp.UpLoader, error) {
	if protocol == sftpProtocol {
		return c.sftpUploader, nil
	}
	return nil, fmt.Errorf("unsupported protocol %s", protocol)
}

func (c *Controller) generatePacketsPathForServer(name string) string {
	return name + ".pcapng"
}

func (c *Controller) uploadPackets(ps *crdv1alpha1.PacketSampling, outputFile afero.File) error {
	klog.V(2).InfoS("Uploading captured packets for PacketSampling", "name", ps.Name)
	uploader, err := c.getUploaderByProtocol(sftpProtocol)
	if err != nil {
		return fmt.Errorf("failed to upload support bundle while getting uploader: %v", err)
	}
	serverAuth, err := ftp.ParseBundleAuth(ps.Spec.Authentication, c.kubeClient)
	if err != nil {
		klog.ErrorS(err, "Failed to get authentication defined in the PacketSampling CR", "name", ps.Name, "authentication", ps.Spec.Authentication)
		return err
	}
	cfg := ftp.GenSSHClientConfig(serverAuth.BasicAuthentication.Username, serverAuth.BasicAuthentication.Password)
	return uploader.Upload(ps.Spec.FileServer.URL, c.generatePacketsPathForServer(string(ps.UID)), cfg, outputFile)

}

// initPacketSampling mark the packetsampling as running and allocate tag for it, then start the sampling. the tag will
// serve as a unique id for concurrent processing.
func (c *Controller) initPacketSampling(ps *crdv1alpha1.PacketSampling) error {
	tag, err := c.allocateTag(ps.Name)
	if err != nil {
		return err
	}
	if tag == 0 {
		return nil
	}
	err = c.updatePacketSamplingStatus(ps, crdv1alpha1.PacketSamplingRunning, "", 0)
	if err != nil {
		c.deallocateTag(ps.Name, tag)
		return err
	}
	return c.startPacketSampling(ps, c.runningPacketSamplings[tag])
}

func (c *Controller) updatePacketSamplingStatus(ps *crdv1alpha1.PacketSampling, phase crdv1alpha1.PacketSamplingPhase, reason string, numCapturedPackets int32) error {
	type PacketSampling struct {
		Status crdv1alpha1.PacketSamplingStatus `json:"status,omitempty"`
	}
	patchData := PacketSampling{Status: crdv1alpha1.PacketSamplingStatus{Phase: phase}}
	if phase == crdv1alpha1.PacketSamplingRunning && ps.Status.StartTime == nil {
		t := metav1.Now()
		patchData.Status.StartTime = &t
	}
	if reason != "" {
		patchData.Status.Reason = reason
	}
	if numCapturedPackets != 0 {
		patchData.Status.NumCapturedPackets = numCapturedPackets
	}
	if phase == crdv1alpha1.PacketSamplingSucceeded {
		patchData.Status.PacketsPath = c.generatePacketsPathForServer(string(ps.UID))
	}
	payloads, _ := json.Marshal(patchData)
	_, err := c.crdClient.CrdV1alpha1().PacketSamplings().Patch(context.TODO(), ps.Name, types.MergePatchType, payloads, metav1.PatchOptions{}, "status")
	return err
}

func (c *Controller) deallocateTag(name string, tag uint8) {
	c.runningPacketSamplingsMutex.Lock()
	defer c.runningPacketSamplingsMutex.Unlock()
	if state, ok := c.runningPacketSamplings[tag]; ok {
		if state != nil && name == state.name {
			delete(c.runningPacketSamplings, tag)
		}
	}
}

func (c *Controller) getTagForPacketSampling(name string) uint8 {
	c.runningPacketSamplingsMutex.Lock()
	defer c.runningPacketSamplingsMutex.Unlock()
	for tag, state := range c.runningPacketSamplings {
		if state != nil && state.name == name {
			// The packetsampling request has been processed already.
			return tag
		}
	}
	return 0
}

// checkPacketSamplingStatus is only called for PacketSamplings in the Running phase
func (c *Controller) checkPacketSamplingStatus(ps *crdv1alpha1.PacketSampling) error {
	tag := c.getTagForPacketSampling(ps.Name)
	if tag == 0 {
		return nil
	}
	if checkPacketSamplingSucceeded(ps) {
		c.deallocateTag(ps.Name, tag)
		return c.updatePacketSamplingStatus(ps, crdv1alpha1.PacketSamplingSucceeded, "", 0)
	}

	if isPacketSamplingTimeout(ps) {
		c.deallocateTag(ps.Name, tag)
		return c.updatePacketSamplingStatus(ps, crdv1alpha1.PacketSamplingFailed, samplingTimeoutReason, 0)
	}
	return nil
}

func checkPacketSamplingSucceeded(ps *crdv1alpha1.PacketSampling) bool {
	succeeded := false
	if ps.Spec.Type == crdv1alpha1.FirstNSampling && ps.Status.NumCapturedPackets == ps.Spec.FirstNSamplingConfig.Number {
		succeeded = true
	}
	return succeeded
}

func isPacketSamplingTimeout(ps *crdv1alpha1.PacketSampling) bool {
	var timeout time.Duration
	if ps.Spec.Timeout != 0 {
		timeout = time.Duration(ps.Spec.Timeout) * time.Second
	} else {
		timeout = defaultTimeoutDuration
	}
	var startTime time.Time
	if ps.Status.StartTime != nil {
		startTime = ps.Status.StartTime.Time
	} else {
		klog.V(2).InfoS("StartTime field in PacketSampling Status should not be empty", "PacketSampling", klog.KObj(ps))
		startTime = ps.CreationTimestamp.Time
	}
	return startTime.Add(timeout).Before(time.Now())
}
