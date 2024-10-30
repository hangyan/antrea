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
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/spf13/afero"
	"golang.org/x/time/rate"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	klog "k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/controller/packetcapture/bpf"
	"antrea.io/antrea/pkg/agent/interfacestore"
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
	controllerName               = "AntreaAgentPacketCaptureController"
	resyncPeriod   time.Duration = 0

	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second

	defaultWorkers = 4

	// reason for timeout
	captureTimeoutReason   = "PacketCapture timeout"
	defaultTimeoutDuration = time.Second * time.Duration(60)

	captureStatusUpdatePeriod = 10 * time.Second

	// PacketCapture uses a dedicated secret object to store auth info for file server.
	// #nosec G101
	fileServerAuthSecretName      = "antrea-packetcapture-fileserver-auth"
	fileServerAuthSecretNamespace = "kube-system"

	// max packet size for pcap capture.
	snapshotLen = 65536
)

var (
	packetDirectory = getPacketDirectory()
	defaultFS       = afero.NewOsFs()
)

func getPacketDirectory() string {
	return filepath.Join(os.TempDir(), "antrea", "packetcapture", "packets")
}

type packetCaptureState struct {
	// name is the PacketCapture name
	name string
	// numCapturedPackets record how many packets have been captured. Due to the RateLimiter,
	// this maybe not be realtime data.
	numCapturedPackets int32
	// maxNumCapturedPackets is target number limit for our capture. If numCapturedPackets=maxNumCapturedPackets, means
	// the PacketCapture is finished successfully.
	maxNumCapturedPackets int32
	// updateRateLimiter controls the frequency of the updates to PacketCapture status.
	updateRateLimiter *rate.Limiter
	// pcapngFile is the file object for the packet file.
	pcapngFile afero.File
	// pcapngWriter is the writer for the packet file.
	pcapngWriter *pcapgo.NgWriter
}

type Controller struct {
	kubeClient            clientset.Interface
	crdClient             clientsetversioned.Interface
	packetCaptureInformer crdinformers.PacketCaptureInformer
	packetCaptureLister   crdlisters.PacketCaptureLister
	packetCaptureSynced   cache.InformerSynced
	interfaceStore        interfacestore.InterfaceStore
	nodeConfig            *config.NodeConfig
	queue                 workqueue.TypedRateLimitingInterface[string]
	sftpUploader          ftp.Uploader

	newPacketSourceFn func(c *Controller, pc *crdv1alpha1.PacketCapture) (PacketSource, error)
}

func NewPacketCaptureController(
	kubeClient clientset.Interface,
	crdClient clientsetversioned.Interface,
	packetCaptureInformer crdinformers.PacketCaptureInformer,
	interfaceStore interfacestore.InterfaceStore,
	nodeConfig *config.NodeConfig,
) *Controller {
	c := &Controller{
		kubeClient:            kubeClient,
		crdClient:             crdClient,
		packetCaptureInformer: packetCaptureInformer,
		packetCaptureLister:   packetCaptureInformer.Lister(),
		packetCaptureSynced:   packetCaptureInformer.Informer().HasSynced,
		interfaceStore:        interfaceStore,
		nodeConfig:            nodeConfig,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "packetcapture"},
		),
		sftpUploader: &ftp.SftpUploader{},
	}

	packetCaptureInformer.Informer().AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addPacketCapture,
		UpdateFunc: c.updatePacketCapture,
		DeleteFunc: c.deletePacketCapture,
	}, resyncPeriod)

	c.newPacketSourceFn = func(c *Controller, pc *crdv1alpha1.PacketCapture) (PacketSource, error) {
		matchPacket, err := c.createMatchPacket(pc)
		if err != nil {
			return nil, err
		}
		filter := bpf.CompilePacketFilter(pc.Spec.Packet, matchPacket)
		device := c.getTargetCaptureDevice(pc)
		if device == nil {
			return nil, nil
		}
		klog.V(5).InfoS("PacketCapture trying to match packet", "name", pc.Name, "packet", *matchPacket)
		klog.V(5).InfoS("Generated bpf instructions for Packetcapture", "name", pc.Name, "inst", filter)
		return NewPcapSource(*device, filter)
	}

	return c
}

func (c *Controller) enqueuePacketCapture(pc *crdv1alpha1.PacketCapture) {
	c.queue.Add(pc.Name)
}

// Run will create defaultWorkers workers (go routines) which will process the PacketCapture events from the
// workqueue.
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting packetcapture controller", "name", controllerName)
	defer klog.InfoS("Shutting down packetcapture controller", "name", controllerName)

	cacheSynced := []cache.InformerSynced{c.packetCaptureSynced}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSynced...) {
		return
	}

	err := defaultFS.MkdirAll(packetDirectory, 0755)
	if err != nil {
		klog.ErrorS(err, "Couldn't create directory for storing captured packets", "directory", packetDirectory)
		return
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (c *Controller) addPacketCapture(obj interface{}) {
	pc := obj.(*crdv1alpha1.PacketCapture)
	klog.InfoS("Processing PacketCapture ADD event", "name", pc.Name)
	c.enqueuePacketCapture(pc)
}

func (c *Controller) updatePacketCapture(_, obj interface{}) {
	pc := obj.(*crdv1alpha1.PacketCapture)
	klog.InfoS("Processing PacketCapture UPDATE event", "name", pc.Name)
	c.enqueuePacketCapture(pc)
}

func (c *Controller) deletePacketCapture(obj interface{}) {
	pc := obj.(*crdv1alpha1.PacketCapture)
	klog.InfoS("Processing PacketCapture DELETE event", "name", pc.Name)
	c.enqueuePacketCapture(pc)
}

func nameToPath(name string) string {
	return filepath.Join(packetDirectory, name+".pcapng")
}

func (c *Controller) worker() {
	for c.processPacketCaptureItem() {
	}
}

func (c *Controller) processPacketCaptureItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)
	if err := c.syncPacketCapture(key); err == nil {
		c.queue.Forget(key)
	} else {
		klog.ErrorS(err, "Error syncing PacketCapture, exiting", "key", key)
	}
	return true
}

func (c *Controller) cleanupPacketCapture(pcName string) {
	path := nameToPath(pcName)
	exist, err := afero.Exists(defaultFS, path)
	if err != nil {
		klog.ErrorS(err, "Failed to check if path exists", "path", path)
	}
	if !exist {
		return
	}
	if err := defaultFS.Remove(path); err == nil {
		klog.V(2).InfoS("Deleted pcap file", "name", pcName, "path", path)
	} else {
		klog.ErrorS(err, "Failed to delete pcap file", "name", pcName, "path", path)
	}
}

func getPacketFileAndWriter(name string) (afero.File, *pcapgo.NgWriter, error) {
	filePath := nameToPath(name)
	var file afero.File
	if _, err := os.Stat(filePath); err == nil {
		return nil, nil, fmt.Errorf("packet file already exists. this may be due to an unexpected termination")
	} else if os.IsNotExist(err) {
		file, err = defaultFS.Create(filePath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create pcapng file: %w", err)
		}
	} else {
		return nil, nil, fmt.Errorf("couldn't check if the file exists: %w", err)
	}
	writer, err := pcapgo.NewNgWriter(file, layers.LinkTypeEthernet)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't initialize pcap writer: %w", err)
	}
	return file, writer, nil
}

// getTargetCaptureDevice trying to locate the target device for capture. If the target pod is not exist on the current node,
// means this node will not perform the capture.
func (c *Controller) getTargetCaptureDevice(pc *crdv1alpha1.PacketCapture) *string {
	var pod, ns string
	if pc.Spec.Source.Pod != nil {
		pod = pc.Spec.Source.Pod.Name
		ns = pc.Spec.Source.Pod.Namespace
	} else {
		pod = pc.Spec.Destination.Pod.Name
		ns = pc.Spec.Destination.Pod.Namespace
	}

	podInterfaces := c.interfaceStore.GetContainerInterfacesByPod(pod, ns)
	if len(podInterfaces) == 0 {
		return nil
	}

	return &podInterfaces[0].InterfaceName
}

func (c *Controller) startPacketCapture(pc *crdv1alpha1.PacketCapture) error {
	var err error
	pcState := &packetCaptureState{name: pc.Name}
	defer func() {
		if err != nil {
			c.cleanupPacketCapture(pc.Name)
			klog.ErrorS(err, "PackageCapture failed", "name", pc.Name)
			err := c.updatePacketCaptureStatus(pc.Name, pcState.numCapturedPackets, "", err)
			if err != nil {
				klog.ErrorS(err, "failed to update PacketCapture status")
			}
		}
	}()

	klog.V(4).InfoS("Started processing PacketCapture", "name", pc.Name)

	device := c.getTargetCaptureDevice(pc)
	if device == nil {
		return nil
	}

	klog.V(2).InfoS("Prepare capture on current node", "name", pc.Name, "device", *device)
	packetSource, err := c.newPacketSourceFn(c, pc)
	if err != nil {
		klog.ErrorS(err, "failed to create packet source")
		return err

	}

	pcState.maxNumCapturedPackets = pc.Spec.CaptureConfig.FirstN.Number
	file, writer, err := getPacketFileAndWriter(pc.Name)
	if err != nil {
		return err
	}

	pcState.pcapngFile = file
	pcState.pcapngWriter = writer
	pcState.updateRateLimiter = rate.NewLimiter(rate.Every(captureStatusUpdatePeriod), 1)
	timeout := defaultTimeoutDuration
	if pc.Spec.Timeout != nil {
		timeout = time.Duration(*pc.Spec.Timeout) * time.Second
	}

	err = c.performCapture(pcState, timeout, packetSource)

	return err
}

func (c *Controller) performCapture(captureState *packetCaptureState, timeout time.Duration, source PacketSource) error {
	options := CaptureOptions{
		MaxCaptureLength: snapshotLen,
		Promiscuous:      true,
	}
	packets, err := source.Capture(&options)
	if err != nil {
		klog.ErrorS(err, "failed to start capture")
		return err
	}

	timer := time.NewTicker(timeout)
	defer timer.Stop()

	for {
		select {
		case packet := <-packets:
			if captureState.numCapturedPackets == captureState.maxNumCapturedPackets {
				return nil
			}
			captureState.numCapturedPackets++
			ci := gopacket.CaptureInfo{
				Timestamp:     time.Now(),
				CaptureLength: len(packet.Data()),
				Length:        len(packet.Data()),
			}
			err = captureState.pcapngWriter.WritePacket(ci, packet.Data())
			if err != nil {
				return fmt.Errorf("couldn't write packet: %w", err)
			}
			klog.V(5).InfoS("capture packet", "name", captureState.name, "count",
				captureState.numCapturedPackets, "len", ci.Length)

			reachTarget := captureState.numCapturedPackets == captureState.maxNumCapturedPackets
			// use rate limiter to reduce the times we need to update status.
			if reachTarget || captureState.updateRateLimiter.Allow() {
				pc, err := c.packetCaptureLister.Get(captureState.name)
				if err != nil {
					return fmt.Errorf("get PacketCapture failed: %w", err)
				}
				// if reach the target. flush the file and upload it.
				if reachTarget {
					path := os.Getenv("POD_NAME") + ":" + nameToPath(pc.Name)
					if err := captureState.pcapngWriter.Flush(); err != nil {
						return err
					}
					if pc.Spec.FileServer != nil {
						err := c.uploadPackets(pc, captureState.pcapngFile)
						klog.V(4).InfoS("Upload captured packets", "name", pc.Name, "path", path)
						// update upload result.
						if updateErr := c.updatePacketCaptureStatus(pc.Name, captureState.numCapturedPackets, path, err); updateErr != nil {
							return updateErr
						}
						if err != nil {
							return err
						}
					} else {
						// update capture result.
						if updateErr := c.updatePacketCaptureStatus(pc.Name, captureState.numCapturedPackets, path, nil); updateErr != nil {
							return updateErr
						}
					}

					if err := captureState.pcapngFile.Close(); err != nil {
						return err
					}
				}

				err = c.updatePacketCaptureStatus(pc.Name, captureState.numCapturedPackets, "", nil)
				if err != nil {
					return fmt.Errorf("failed to update the PacketCapture: %w", err)
				}
				klog.InfoS("Updated PacketCapture", "PacketCapture", klog.KObj(pc), "numCapturedPackets", captureState.numCapturedPackets)
			}
		case <-timer.C:
			pc, err := c.packetCaptureLister.Get(captureState.name)
			if err != nil {
				return fmt.Errorf("get PacketCapture failed: %w", err)
			}
			klog.InfoS("PacketCapture timeout", "name", pc.Name)
			err = errors.New(captureTimeoutReason)
			if updateErr := c.updatePacketCaptureStatus(pc.Name, 0, "", err); updateErr != nil {
				klog.ErrorS(updateErr, "failed to update the PacketCapture", "name", pc.Name)
			}
			return err
		}
	}
}

func (c *Controller) getPodIP(podRef *crdv1alpha1.PodReference, isIPv6 bool) (net.IP, error) {
	podInterfaces := c.interfaceStore.GetContainerInterfacesByPod(podRef.Name, podRef.Namespace)
	var result net.IP
	if len(podInterfaces) > 0 {
		if isIPv6 {
			result = podInterfaces[0].GetIPv6Addr()
		} else {
			result = podInterfaces[0].GetIPv4Addr()
		}
	} else {
		pod, err := c.kubeClient.CoreV1().Pods(podRef.Namespace).Get(context.TODO(), podRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get Pod %s/%s: %v", podRef.Namespace, podRef.Name, err)
		}
		podIPs := make([]net.IP, len(pod.Status.PodIPs))
		for i, ip := range pod.Status.PodIPs {
			podIPs[i] = net.ParseIP(ip.IP)
		}
		if isIPv6 {
			ip, err := util.GetIPWithFamily(podIPs, util.FamilyIPv6)
			if err != nil {
				return nil, err
			} else {
				result = ip
			}
		} else {
			result = util.GetIPv4Addr(podIPs)
		}
	}
	if result == nil {
		family := "IPv4"
		if isIPv6 {
			family = "IPv6"
		}
		return nil, fmt.Errorf("cannot find IP with %s AddressFamily for Pod %s/%s", family, podRef.Namespace, podRef.Name)
	}
	return result, nil
}

func (c *Controller) createMatchPacket(pc *crdv1alpha1.PacketCapture) (*binding.Packet, error) {
	packet := new(binding.Packet)
	if pc.Spec.Packet == nil {
		pc.Spec.Packet = &crdv1alpha1.Packet{
			IPFamily: v1.IPv4Protocol,
		}
	}

	packet.IsIPv6 = pc.Spec.Packet.IPFamily == v1.IPv6Protocol
	if pc.Spec.Source.Pod != nil {
		ip, err := c.getPodIP(pc.Spec.Source.Pod, packet.IsIPv6)
		if err != nil {
			return nil, err
		} else {
			packet.SourceIP = ip
		}
	} else if pc.Spec.Source.IP != nil {
		packet.SourceIP = net.ParseIP(*pc.Spec.Source.IP)
		if packet.SourceIP == nil {
			return nil, errors.New("invalid ip address: " + *pc.Spec.Source.IP)
		}
	}

	if pc.Spec.Destination.Pod != nil {
		ip, err := c.getPodIP(pc.Spec.Destination.Pod, packet.IsIPv6)
		if err != nil {
			return nil, err
		} else {
			packet.DestinationIP = ip
		}
	} else if pc.Spec.Destination.IP != nil {
		packet.DestinationIP = net.ParseIP(*pc.Spec.Destination.IP)
		if packet.DestinationIP == nil {
			return nil, errors.New("invalid ip address: " + *pc.Spec.Destination.IP)
		}
	}

	if pc.Spec.Packet.TransportHeader.TCP != nil {
		if pc.Spec.Packet.TransportHeader.TCP.SrcPort != nil {
			packet.SourcePort = uint16(*pc.Spec.Packet.TransportHeader.TCP.SrcPort)
		}
		if pc.Spec.Packet.TransportHeader.TCP.DstPort != nil {
			packet.DestinationPort = uint16(*pc.Spec.Packet.TransportHeader.TCP.DstPort)
		}
	} else if pc.Spec.Packet.TransportHeader.UDP != nil {
		if pc.Spec.Packet.TransportHeader.UDP.SrcPort != nil {
			packet.SourcePort = uint16(*pc.Spec.Packet.TransportHeader.UDP.SrcPort)
		}
		if pc.Spec.Packet.TransportHeader.UDP.DstPort != nil {
			packet.DestinationPort = uint16(*pc.Spec.Packet.TransportHeader.UDP.DstPort)
		}
	}
	return packet, nil
}

func (c *Controller) syncPacketCapture(pcName string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).InfoS("Finished syncing PacketCapture", "name", pcName, "startTime", time.Since(startTime))
	}()

	pc, err := c.packetCaptureLister.Get(pcName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			c.cleanupPacketCapture(pcName)
			return nil
		}
		return err
	}

	if isCaptureCompleted(pc, pc.Status.NumCapturedPackets) {
		return nil
	}

	if isPacketCaptureFailed(pc) {
		c.cleanupPacketCapture(pcName)
		return nil
	}

	if len(pc.Status.Conditions) > 0 {
		if isPacketCaptureTimeout(pc) {
			return c.updatePacketCaptureStatus(pc.Name, 0, "", errors.New(captureTimeoutReason))
		}
	} else {
		return c.startPacketCapture(pc)
	}
	return nil

}

func (c *Controller) getUploaderByProtocol(protocol StorageProtocolType) (ftp.Uploader, error) {
	if protocol == sftpProtocol {
		return c.sftpUploader, nil
	}
	return nil, fmt.Errorf("unsupported protocol %s", protocol)
}

func (c *Controller) generatePacketsPathForServer(name string) string {
	return name + ".pcapng"
}

func getDefaultFileServerAuth() *crdv1alpha1.BundleServerAuthConfiguration {
	return &crdv1alpha1.BundleServerAuthConfiguration{
		AuthType: crdv1alpha1.BasicAuthentication,
		AuthSecret: &v1.SecretReference{
			Name:      fileServerAuthSecretName,
			Namespace: fileServerAuthSecretNamespace,
		},
	}
}

func (c *Controller) uploadPackets(pc *crdv1alpha1.PacketCapture, outputFile afero.File) error {
	klog.V(2).InfoS("Uploading captured packets for PacketCapture", "name", pc.Name)
	uploader, err := c.getUploaderByProtocol(sftpProtocol)
	if err != nil {
		return fmt.Errorf("failed to upload packets while getting uploader: %v", err)
	}
	authConfig := getDefaultFileServerAuth()
	serverAuth, err := ftp.ParseBundleAuth(*authConfig, c.kubeClient)
	if err != nil {
		klog.ErrorS(err, "Failed to get authentication for the fileServer", "name", pc.Name, "authentication", authConfig)
		return err
	}
	cfg := ftp.GenSSHClientConfig(serverAuth.BasicAuthentication.Username, serverAuth.BasicAuthentication.Password)
	return uploader.Upload(pc.Spec.FileServer.URL, c.generatePacketsPathForServer(pc.Name), cfg, outputFile)
}

func isPacketCaptureFailed(pc *crdv1alpha1.PacketCapture) bool {
	conditions := pc.Status.Conditions
	if len(conditions) == 0 {
		return false
	}
	for _, item := range conditions {
		if item.Status == metav1.ConditionFalse {
			return true
		}
	}
	return false
}

func isPacketCaptureTimeout(pc *crdv1alpha1.PacketCapture) bool {
	var timeout time.Duration
	if pc.Spec.Timeout != nil {
		timeout = time.Duration(*pc.Spec.Timeout) * time.Second
	} else {
		timeout = defaultTimeoutDuration
	}
	var startTime time.Time
	if pc.Status.StartTime != nil {
		startTime = pc.Status.StartTime.Time
	} else {
		klog.V(2).InfoS("StartTime field in PacketCapture Status should not be empty", "PacketCapture", klog.KObj(pc))
		startTime = pc.CreationTimestamp.Time
	}
	return startTime.Add(timeout).Before(time.Now())
}

func isCaptureCompleted(pc *crdv1alpha1.PacketCapture, num int32) bool {
	cfg := pc.Spec.CaptureConfig.FirstN
	if cfg != nil && num == cfg.Number {
		return true
	}
	return false
}

func (c *Controller) updatePacketCaptureStatus(name string, num int32, path string, err error) error {
	toUpdate, getErr := c.packetCaptureLister.Get(name)
	if getErr != nil {
		klog.InfoS("Didn't find the original PacketCapture, skip updating status", "name", name)
		return nil
	}

	t := metav1.Now()
	updatedStatus := crdv1alpha1.PacketCaptureStatus{
		NumCapturedPackets: num,
		PacketsFilePath:    path,
		StartTime:          &t,
	}

	if err != nil {
		if isCaptureCompleted(toUpdate, num) {
			updatedStatus.Conditions = []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.CaptureCompleted,
					Status:             metav1.ConditionStatus(v1.ConditionTrue),
					LastTransitionTime: t,
					Reason:             "Succeed",
				},
			}
		} else {
			updatedStatus.Conditions = []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.CaptureCompleted,
					Status:             metav1.ConditionStatus(v1.ConditionFalse),
					LastTransitionTime: t,
					Reason:             "CaptureFailed",
					Message:            err.Error(),
				},
			}
		}
		if toUpdate.Spec.FileServer != nil {
			updatedStatus.Conditions = append(updatedStatus.Conditions, crdv1alpha1.PacketCaptureCondition{
				Type:               crdv1alpha1.PacketsUploaded,
				Status:             metav1.ConditionStatus(v1.ConditionFalse),
				LastTransitionTime: t,
				Reason:             "UploadFailed",
				Message:            err.Error(),
			})
		}
	} else {
		if isCaptureCompleted(toUpdate, num) {
			updatedStatus.Conditions = []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.CaptureCompleted,
					Status:             metav1.ConditionStatus(v1.ConditionTrue),
					LastTransitionTime: t,
					Reason:             "Succeed",
				},
			}
			if toUpdate.Spec.FileServer != nil {
				updatedStatus.Conditions = append(updatedStatus.Conditions, crdv1alpha1.PacketCaptureCondition{
					Type:               crdv1alpha1.PacketsUploaded,
					Status:             metav1.ConditionStatus(v1.ConditionTrue),
					LastTransitionTime: t,
					Reason:             "Succeed",
				})
			}
		} else {
			updatedStatus.Conditions = []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.CaptureCompleted,
					Status:             metav1.ConditionStatus(v1.ConditionUnknown),
					LastTransitionTime: t,
				},
			}
			if toUpdate.Spec.FileServer != nil {
				updatedStatus.Conditions = append(updatedStatus.Conditions, crdv1alpha1.PacketCaptureCondition{
					Type:               crdv1alpha1.PacketsUploaded,
					Status:             metav1.ConditionStatus(v1.ConditionUnknown),
					LastTransitionTime: t,
				})
			}
		}

	}

	if retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if toUpdate.Status.StartTime != nil {
			updatedStatus.StartTime = toUpdate.Status.StartTime
		}
		if toUpdate.Status.PacketsFilePath != "" {
			updatedStatus.PacketsFilePath = toUpdate.Status.PacketsFilePath
		}
		if updatedStatus.NumCapturedPackets == 0 && toUpdate.Status.NumCapturedPackets > 0 {
			updatedStatus.NumCapturedPackets = toUpdate.Status.NumCapturedPackets
		}
		if packetCaptureStatusEqual(toUpdate.Status, updatedStatus) {
			return nil
		}
		toUpdate.Status = updatedStatus
		klog.V(2).InfoS("Updating PacketCapture", "name", name, "status", toUpdate.Status)
		_, updateErr := c.crdClient.CrdV1alpha1().PacketCaptures().UpdateStatus(context.TODO(), toUpdate, metav1.UpdateOptions{})
		if updateErr != nil && apierrors.IsConflict(updateErr) {
			var getErr error
			if toUpdate, getErr = c.crdClient.CrdV1alpha1().PacketCaptures().Get(context.TODO(), name, metav1.GetOptions{}); getErr != nil {
				return getErr
			}
		}
		// Return the error from UPDATE.
		return updateErr
	}); retryErr != nil {
		return retryErr
	}
	klog.V(2).InfoS("Updated PacketCapture", "name", name)
	return nil
}

func conditionEqualsIgnoreLastTransitionTime(a, b crdv1alpha1.PacketCaptureCondition) bool {
	a1 := a
	a1.LastTransitionTime = metav1.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	b1 := b
	b1.LastTransitionTime = metav1.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	return a1 == b1
}

var semanticIgnoreLastTransitionTime = conversion.EqualitiesOrDie(
	conditionSliceEqualsIgnoreLastTransitionTime,
)

func packetCaptureStatusEqual(oldStatus, newStatus crdv1alpha1.PacketCaptureStatus) bool {
	return semanticIgnoreLastTransitionTime.DeepEqual(oldStatus, newStatus)
}

func conditionSliceEqualsIgnoreLastTransitionTime(as, bs []crdv1alpha1.PacketCaptureCondition) bool {
	if len(as) != len(bs) {
		return false
	}
	for i := range as {
		a := as[i]
		b := bs[i]
		if !conditionEqualsIgnoreLastTransitionTime(a, b) {
			return false
		}
	}
	return true
}
