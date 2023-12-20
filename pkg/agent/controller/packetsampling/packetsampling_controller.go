package packetsampling

import (
	"antrea.io/antrea/pkg/agent/util"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/libOpenflow/protocol"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/gopacket/layers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"net"
	"os"
	"path"
	"runtime"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/google/gopacket/pcapgo"
	"golang.org/x/time/rate"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	clientsetversioned "antrea.io/antrea/pkg/client/clientset/versioned"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/querier"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const (
	controllerName               = "AntreaAgentPacketSamplingController"
	resyncPeriod   time.Duration = 0

	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second

	defaultWorkers = 4
)

const (
	samplingStatusUpdatePeriod = 10 * time.Second
	packetDirectoryUnix        = "/tmp/packetsampling/packets"
	packetDirectoryWindows     = "C:\\packetsampling\\packets"
)

var packetDirectory = getPacketDirectory()

// TODO: refactor this part.
func getPacketDirectory() string {
	if runtime.GOOS == "windows" {
		return packetDirectoryWindows
	} else {
		return getPacketDirectory()
	}
}

type packetSamplingState struct {
	shouldSyncPackets     bool
	numCapturedPackets    int32
	maxNumCapturedPackets int32
	updateRateLimiter     *rate.Limiter

	uid          string
	pcapngFile   *os.File
	pcapngWriter *pcapgo.NgWriter

	name string
	tag  uint8

	receiverOnly bool
	isSender     bool
}

type Controller struct {
	kubeClient             clientset.Interface
	serviceLister          corelisters.ServiceLister
	serviceListerSynced    cache.InformerSynced
	packetSamplingClient   clientsetversioned.Interface
	packetSamplingInformer crdinformers.PacketSamplingInformer
	packetSamplingLister   crdlisters.PacketSamplingLister

	packetSamplingSynced cache.InformerSynced
	ovsBridgeClient      ovsconfig.OVSBridgeClient
	ofClient             openflow.Client

	networkPolicyQuerier querier.AgentNetworkPolicyInfoQuerier
	egressQuerier        querier.EgressQuerier

	interfaceStore interfacestore.InterfaceStore
	networkConfig  *config.NetworkConfig
	nodeConfig     *config.NodeConfig
	serviceCIDR    *net.IPNet

	queue                       workqueue.RateLimitingInterface
	runningPacketSamplingsMutex sync.RWMutex

	runningPacketSamplings map[uint8]*packetSamplingState
}

func NewPacketSamplingController(
	kubeClient clientset.Interface,
	informerFactory informers.SharedInformerFactory,
	packetSamplingInformer crdinformers.PacketSamplingInformer) *Controller {
	c := &Controller{
		kubeClient: kubeClient,
	}

	packetSamplingInformer.Informer().AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addPacketSampling,
		UpdateFunc: c.updatePacketSampling,
		DeleteFunc: c.deletePacketSampling,
	}, resyncPeriod)

	c.ofClient.RegisterPacketInHandler(uint8(openflow.PacketInCategoryTF), c)

	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		c.serviceLister = informerFactory.Core().V1().Services().Lister()
		c.serviceListerSynced = informerFactory.Core().V1().Services().Informer().HasSynced
	}
	return c

}

func (c *Controller) enqueuePacketSampling(ps *crdv1alpha1.PacketSampling) {
	c.queue.Add(ps.Name)
}

func (c *Controller) addPacketSampling(obj interface{}) {
	ps := obj.(*crdv1alpha1.PacketSampling)
	klog.Infof("Processing PacketSampling %s ADD event", ps.Name)
	c.enqueuePacketSampling(ps)
}

func (c *Controller) updatePacketSampling(_, obj interface{}) {
	ps := obj.(*crdv1alpha1.PacketSampling)
	klog.Infof("Processing PacketSampling %s UPDATE EVENT", ps.Name)
	c.enqueuePacketSampling(ps)
}

func (c *Controller) deletePacketSampling(obj interface{}) {
	ps := obj.(*crdv1alpha1.PacketSampling)
	klog.Infof("Processing PacketSampling %s DELETE event", ps.Name)

	err := deletePcapngFile(ps.Status.UID)
	if err != nil {
		klog.ErrorS(err, "Couldn't delete pcapng file")

	}
	c.enqueuePacketSampling(ps)

}

func deletePcapngFile(uid string) error {
	return os.Remove(uidToPath(uid))
}

func uidToPath(uid string) string {
	return path.Join(packetDirectory, uid+".pcapng")
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
		klog.Errorf("Expected string in work queue but got %#v", obj)
		return true
	} else if err := c.syncPacketSampling(key); err == nil {
		c.queue.Forget(key)
	} else {
		klog.Errorf("Error syncing PacketSampling %s, existing. Error: %v", key, err)
	}
	return true
}

func (c *Controller) validatePacketSampling(ps *crdv1alpha1.PacketSampling) error {
	if ps.Spec.Destination.Service != "" && !features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		return errors.New("using Service destination requires AntreaPolicy feature gate")
	}

	if ps.Spec.Destination.IP != "" {
		destIP := net.ParseIP(ps.Spec.Destination.IP)
		if destIP == nil {
			return fmt.Errorf("destination IP %s is not valid", ps.Spec.Destination.IP)
		}
		if !features.DefaultFeatureGate.Enabled(features.AntreaPolicy) && !c.serviceCIDR.Contains(destIP) {
			return errors.New("using ClusterIP destination requires AntreaPolicy feature gate")
		}

	}
	return nil
}

func (c *Controller) errorPacketSamplingCRD(ps *crdv1alpha1.PacketSampling, reason string) (*crdv1alpha1.PacketSampling, error) {
	ps.Status.Phase = crdv1alpha1.PacketSamplingFailed

	type PacketSampling struct {
		Status crdv1alpha1.PacketSamplingStatus `json:"status,omitempty"`
	}

	patchData := PacketSampling{
		Status: crdv1alpha1.PacketSamplingStatus{Phase: ps.Status.Phase, Reason: reason},
	}
	payloads, _ := json.Marshal(patchData)
	return c.packetSamplingClient.CrdV1alpha1().PacketSamplings().Patch(context.TODO(), ps.Name, types.MergePatchType, payloads, metav1.PatchOptions{}, "status")

}

func (c *Controller) cleanupPacketSampling(psName string) *packetSamplingState {
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

func (c *Controller) startPacketSampling(ps *crdv1alpha1.PacketSampling) error {
	err := c.validatePacketSampling(ps)

	func() {
		if err != nil {
			c.cleanupPacketSampling(ps.Name)
			c.errorPacketSamplingCRD(ps, fmt.Sprintf("Node: %s, error:%+v", c.nodeConfig.Name, err))

		}
	}()

	if err != nil {
		return err
	}

	if ps.Spec.Source.Pod == "" && ps.Spec.Destination.Pod == "" {
		klog.Errorf("PacketSampling %s has neither source or destination pod specified.", ps.Name)
		return nil
	}

	receiverOnly := false
	var pod, ns string
	if ps.Spec.Source.Pod != "" {
		pod = ps.Spec.Source.Pod
		ns = ps.Spec.Source.Namespace
	} else {
		receiverOnly = true
		pod = ps.Spec.Destination.Pod
		ns = ps.Spec.Destination.Namespace
	}

	podInterfaces := c.interfaceStore.GetContainerInterfacesByPod(pod, ns)
	isSender := !receiverOnly && len(podInterfaces) > 0

	var matchPacket *binding.Packet
	var ofPort uint32

	if len(podInterfaces) > 0 {
		packet, err := c.preparePacket(ps, podInterfaces[0], receiverOnly)
		if err != nil {
			return err
		}
		ofPort = uint32(podInterfaces[0].OFPort)
		matchPacket = packet
		klog.V(2).Infof("PacketSampling packet: %v", *packet)
	}

	c.runningPacketSamplingsMutex.Lock()
	psState := packetSamplingState{
		name: ps.Name, tag: ps.Status.DataplaneTag,
		receiverOnly: receiverOnly, isSender: isSender,
	}

	exists, err := fileExists(ps.Status.UID)
	if err != nil {
		return fmt.Errorf("couldn't check if the file exists: %w", err)

	}
	if exists {
		return fmt.Errorf("packet file already exists. this may be due to an unexpected termination")
	}

	file, err := createPcapngFile(ps.Status.UID)
	if err != nil {
		return fmt.Errorf("couldn't craete pcapng file: %w", err)
	}

	writer, err := pcapgo.NewNgWriter(file, layers.LinkTypeEthernet)
	if err != nil {
		return fmt.Errorf("couldn't init pcap writer: %w", err)
	}

	if ps.Spec.Destination.Pod != "" {
		pod = ps.Spec.Destination.Pod
		ns = ps.Spec.Destination.Namespace
	} else {
		pod = ps.Spec.Source.Pod
		ns = ps.Spec.Source.Namespace
	}
	podInterfaces = c.interfaceStore.GetContainerInterfacesByPod(pod, ns)
	shouldSyncPackets := len(podInterfaces) > 0
	psState.shouldSyncPackets = shouldSyncPackets
	psState.uid = ps.Status.UID
	psState.pcapngFile = file
	psState.pcapngWriter = writer

	if psState.shouldSyncPackets {
		psState.updateRateLimiter = rate.NewLimiter(rate.Every(samplingStatusUpdatePeriod), 1)
	}

	c.runningPacketSamplings[psState.tag] = &psState
	c.runningPacketSamplingsMutex.Unlock()

	klog.V(2).Infof("installing flow entries to packetsampling %s", ps.Name)
	timeout := ps.Spec.Timeout

	if timeout == 0 {
		timeout = crdv1alpha1.DefaultPacketSamplingTimeout
	}
	err = c.ofClient.InstallPacketSamplingFlows(psState.tag, receiverOnly, matchPacket, ofPort, timeout)
	return err

}

func createPcapngFile(uid string) (*os.File, error) {
	return os.Create(uidToPath(uid))
}

func fileExists(uid string) (bool, error) {
	_, err := os.Stat(uidToPath(uid))
	if err == nil {
		return true, nil
	} else {
		if os.IsNotExist(err) {
			return false, nil
		} else {
			return false, err
		}
	}
}

func (c *Controller) preparePacket(ps *crdv1alpha1.PacketSampling, intf *interfacestore.InterfaceConfig, receiverOnly bool) (*binding.Packet, error) {
	isICMP := false
	packet := new(binding.Packet)
	packet.IsIPv6 = ps.Spec.Packet.IPv6Header != nil

	if receiverOnly {
		if ps.Spec.Source.IP != "" {
			packet.SourceIP = net.ParseIP(ps.Spec.Source.IP)
			isIPv6 := packet.SourceIP.To4() == nil
			if isIPv6 != packet.IsIPv6 {
				return nil, errors.New("source IP does not match the IP header family")
			}
		}
		packet.DestinationMAC = intf.MAC
	} else if ps.Spec.Destination.IP != "" {
		packet.DestinationIP = net.ParseIP(ps.Spec.Destination.IP)
		if packet.DestinationIP == nil {
			return nil, errors.New("destination IP is not valid")
		}
		isIPv6 := packet.DestinationIP.To4() == nil
		if isIPv6 != packet.IsIPv6 {
			return nil, errors.New("destination IP does not match the IP header family")
		}
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
			return nil, errors.New("destination Service does not have an ClusterIP")
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
	}

	if ps.Spec.Packet.IPv6Header != nil {
		if ps.Spec.Packet.IPv6Header.NextHeader != nil {
			packet.IPProto = uint8(*ps.Spec.Packet.IPv6Header.NextHeader)
		}
	} else {
		packet.IPProto = uint8(ps.Spec.Packet.IPHeader.Protocol)
	}

	if ps.Spec.Packet.TransportHeader.TCP != nil {
		packet.IPProto = protocol.Type_TCP
		packet.SourcePort = uint16(ps.Spec.Packet.TransportHeader.TCP.SrcPort)
		packet.DestinationPort = uint16(ps.Spec.Packet.TransportHeader.TCP.DstPort)
		if ps.Spec.Packet.TransportHeader.TCP.Flags != 0 {
			packet.TCPFlags = uint8(ps.Spec.Packet.TransportHeader.TCP.Flags)
		}
	} else if ps.Spec.Packet.TransportHeader.UDP != nil {
		packet.IPProto = protocol.Type_UDP
		packet.SourcePort = uint16(ps.Spec.Packet.TransportHeader.UDP.SrcPort)
		packet.DestinationPort = uint16(ps.Spec.Packet.TransportHeader.UDP.DstPort)
	} else if ps.Spec.Packet.TransportHeader.ICMP != nil {
		isICMP = true
	}

	if packet.IPProto == protocol.Type_ICMP || packet.IPProto == protocol.Type_IPv6ICMP {
		isICMP = true
	}

	if isICMP {
		if packet.IsIPv6 {
			packet.IPProto = protocol.Type_IPv6ICMP

		} else {
			packet.IPProto = protocol.Type_ICMP
		}
	}

	return packet, nil
}

func (c *Controller) syncPacketSampling(psName string) error {
	startTime := time.Now()

	defer func() {
		klog.V(4).Infof("Finished syncing PacketSampling for %s. (%v)", psName, time.Since(startTime))
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
	case crdv1alpha1.PacketSamplingRunning:
		if ps.Status.DataplaneTag != 0 {
			start := false
			c.runningPacketSamplingsMutex.Lock()
			if _, ok := c.runningPacketSamplings[ps.Status.DataplaneTag]; !ok {
				start = true
			}
			c.runningPacketSamplingsMutex.Unlock()
			if start {
				c.startPacketSampling(ps)
			}
		}
	}
	return nil

}
