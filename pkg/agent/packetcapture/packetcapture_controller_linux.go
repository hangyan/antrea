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
	"sync"
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
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	klog "k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/util"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	clientsetversioned "antrea.io/antrea/pkg/client/clientset/versioned"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	"antrea.io/antrea/pkg/util/env"
	"antrea.io/antrea/pkg/util/ftp"
)

type storageProtocolType string

const (
	sftpProtocol storageProtocolType = "sftp"
)

const (
	controllerName               = "PacketCaptureController"
	resyncPeriod   time.Duration = 0

	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second

	defaultWorkers = 2

	// defines how many capture request we can handle concurrently.
	maxConcurrentCaptures = 4
	// waiting captures will be marked as Pending unitl they can be processed.
	maxWaitingCaptures = 32

	// reason for timeout
	captureTimeoutReason   = "PacketCapture timeout"
	defaultTimeoutDuration = time.Second * time.Duration(60)

	captureStatusUpdatePeriod = 10 * time.Second

	// PacketCapture uses a dedicated Secret object to store authentication information for a file server.
	// #nosec G101
	fileServerAuthSecretName = "antrea-packetcapture-fileserver-auth"
)

type packetCapturePhase string

const (
	packetCapturePhaseUnknown   packetCapturePhase = ""
	packetCapturePhasePending   packetCapturePhase = "Pending"
	packetCapturePhaseRunning   packetCapturePhase = "Running"
	packetCapturePhaseCompleted packetCapturePhase = "Completed"
)

var (
	packetDirectory = filepath.Join(os.TempDir(), "antrea", "packetcapture", "packets")
	defaultFS       = afero.NewOsFs()
)

type packetCaptureState struct {
	// name is the PacketCapture name.
	name string
	// capturedPacketsNum records how many packets have been captured. Due to the RateLimiter,
	// this may not be the real-time data.
	capturedPacketsNum int32
	// targetCapturedPacketsNum is the target number limit for a PacketCapture. When numCapturedPackets == targetCapturedPacketsNum, it means
	// the PacketCapture is done successfully.
	targetCapturedPacketsNum int32
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
	queue                 workqueue.TypedRateLimitingInterface[string]
	sftpUploader          ftp.Uploader
	newPacketCapturerFn   func(pc *crdv1alpha1.PacketCapture) (PacketCapturer, error)
	cond                  *sync.Cond
	// A name-phase mapping for all PacketCapture CRs.
	captures           map[string]packetCapturePhase
	numRunningCaptures int
	waitingCaptures    int
	waitingCapturesCh  chan string
}

func NewPacketCaptureController(
	kubeClient clientset.Interface,
	crdClient clientsetversioned.Interface,
	packetCaptureInformer crdinformers.PacketCaptureInformer,
	interfaceStore interfacestore.InterfaceStore,
) *Controller {
	c := &Controller{
		kubeClient:            kubeClient,
		crdClient:             crdClient,
		packetCaptureInformer: packetCaptureInformer,
		packetCaptureLister:   packetCaptureInformer.Lister(),
		packetCaptureSynced:   packetCaptureInformer.Informer().HasSynced,
		interfaceStore:        interfaceStore,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "packetcapture"},
		),
		sftpUploader:      &ftp.SftpUploader{},
		cond:              sync.NewCond(&sync.Mutex{}),
		captures:          make(map[string]packetCapturePhase),
		waitingCapturesCh: make(chan string, maxWaitingCaptures),
	}

	packetCaptureInformer.Informer().AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addPacketCapture,
		UpdateFunc: c.updatePacketCapture,
		DeleteFunc: c.deletePacketCapture,
	}, resyncPeriod)

	c.newPacketCapturerFn = func(pc *crdv1alpha1.PacketCapture) (PacketCapturer, error) {
		device := c.getTargetCaptureDevice(pc)
		if device == nil {
			return nil, nil
		}
		return NewPcapCapture(*device)
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
		klog.ErrorS(err, "Couldn't create the directory for storing captured packets", "directory", packetDirectory)
		return
	}

	// check the captures that are waiting in line.
	go c.processWaitingCaptures()
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

func (c *Controller) processWaitingCaptures() {
	for {
		capture := func() string {
			c.cond.L.Lock()
			defer c.cond.L.Unlock()
			for c.numRunningCaptures >= maxConcurrentCaptures || c.waitingCaptures == 0 {
				c.cond.Wait()
			}
			c.numRunningCaptures += 1
			c.waitingCaptures -= 1
			capture := <-c.waitingCapturesCh
			c.startPacketCapture(capture)
			c.captures[capture] = packetCapturePhaseRunning
			return capture
		}()
		c.queue.Add(capture)
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
		if !apierrors.IsNotFound(err) {
			c.queue.AddRateLimited(key)
			klog.ErrorS(err, "Error syncing PacketCapture, requeueing", "key", key)
		} else {
			c.queue.Forget(key)
		}
	}
	return true
}

func (c *Controller) syncPacketCapture(pcName string) error {
	pc, err := c.packetCaptureLister.Get(pcName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			delete(c.captures, pcName)
			c.cleanupPacketCapture(pcName)
		}
		return err
	}

	// capture will not happen on this node.
	device := c.getTargetCaptureDevice(pc)
	if device == nil {
		return nil
	}

	status, err := func() (packetCapturePhase, error) {
		c.cond.L.Lock()
		defer c.cond.L.Unlock()
		status := c.captures[pcName]
		klog.InfoS("Syncing PacketCapture", "packagecapture", pcName, "status", status)
		if status == packetCapturePhaseUnknown {
			klog.InfoS("New PackageCapture", "name", pcName)
			newStatus, err := func() (packetCapturePhase, error) {
				if c.numRunningCaptures < maxConcurrentCaptures && c.waitingCaptures == 0 {
					c.numRunningCaptures += 1
					// run capture asynchronously
					err = c.startPacketCapture(pcName)
					return packetCapturePhaseRunning, err
				}
				// non blocking channel write
				select {
				case c.waitingCapturesCh <- pcName:
					c.waitingCaptures += 1
					return packetCapturePhasePending, nil
				default:
					// should never happen with realistic usage, will be requeued
					return packetCapturePhaseUnknown, fmt.Errorf("too many captures in waiting channel")
				}
			}()
			if err != nil {
				return "", err
			}
			c.captures[pcName] = newStatus
			return newStatus, nil
		}
		return status, nil
	}()
	if err != nil {
		return err
	}
	if err := c.patchStatusIfNeeded(pcName, status); err != nil {
		return fmt.Errorf("error when patching status: %w", err)
	}
	return nil
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
		klog.V(2).InfoS("Deleted the captured pcap file successfully", "name", pcName, "path", path)
	} else {
		klog.ErrorS(err, "Failed to delete the captured pcap file", "name", pcName, "path", path)
	}
}

func getPacketFileAndWriter(name string) (afero.File, *pcapgo.NgWriter, error) {
	filePath := nameToPath(name)
	var file afero.File
	if _, err := os.Stat(filePath); err == nil {
		klog.Warningf("the packet file %s already exists. This may be caused by an unexpected termination, will delete it", filePath)
		if err := defaultFS.Remove(filePath); err != nil {
			return nil, nil, err
		}
	}
	file, err := defaultFS.Create(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create pcapng file: %w", err)
	}
	writer, err := pcapgo.NewNgWriter(file, layers.LinkTypeEthernet)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't initialize a pcap writer: %w", err)
	}
	return file, writer, nil
}

// getTargetCaptureDevice is trying to locate the target device for packet capture. If the target Pod does not exist on the current Node,
// the agent on this Node will not perform the capture. In the PacketCapture spec, at least one of `.Spec.Source.Pod` or `.Spec.Destination.Pod`
// should be set.
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

func (c *Controller) startPacketCapture(name string) error {
	klog.V(4).InfoS("Started processing PacketCapture", "name", name)
	var err error
	pcState := &packetCaptureState{name: name}
	cleanup := func() {
		if err != nil {
			klog.ErrorS(err, "PackageCapture failed", "name", name)
			err := c.updatePacketCaptureStatus(name, pcState.capturedPacketsNum, "", err)
			if err != nil {
				klog.ErrorS(err, "Failed to update PacketCapture status")
			}
		}
	}
	defer cleanup()
	pc, err := c.packetCaptureLister.Get(name)
	if err != nil {
		return err
	}
	srcIP, dstIp, err := c.parseIPs(pc)
	if err != nil {
		return err
	}
	// checked before, ensured it's not nil here.
	device := c.getTargetCaptureDevice(pc)
	klog.V(2).InfoS("Prepare capture on current node", "name", pc.Name, "device", *device)
	packetCapturer, err := c.newPacketCapturerFn(pc)
	if err != nil {
		klog.ErrorS(err, "Failed to create packet source")
		return err
	}
	pcState.targetCapturedPacketsNum = pc.Spec.CaptureConfig.FirstN.Number
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
	go func() error {
		err = c.performCapture(pc, pcState, *device, srcIP, dstIp, timeout, packetCapturer)
		func() {
			c.cond.L.Lock()
			defer c.cond.L.Unlock()
			c.captures[name] = packetCapturePhaseCompleted
			c.numRunningCaptures -= 1
			c.cond.Signal()
		}()

		updateErr := c.updatePacketCaptureStatus(name, pcState.capturedPacketsNum, "", err)
		if updateErr != nil {
			klog.ErrorS(updateErr, "Failed to update PacketCapture status")
		}
		return err
	}()
	return nil
}

func (c *Controller) performCapture(
	pc *crdv1alpha1.PacketCapture,
	captureState *packetCaptureState,
	device string,
	srcIP, dstIP net.IP,
	timeout time.Duration,
	capturer PacketCapturer) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	packets, err := capturer.Capture(ctx, device, srcIP, dstIP, pc.Spec.Packet)
	if err != nil {
		klog.ErrorS(err, "Failed to start capture")
		return err
	}

	for {
		select {
		case packet := <-packets:
			if captureState.capturedPacketsNum == captureState.targetCapturedPacketsNum {
				return nil
			}
			captureState.capturedPacketsNum++
			ci := gopacket.CaptureInfo{
				Timestamp:     time.Now(),
				CaptureLength: len(packet.Data()),
				Length:        len(packet.Data()),
			}
			err = captureState.pcapngWriter.WritePacket(ci, packet.Data())
			if err != nil {
				return fmt.Errorf("couldn't write packets: %w", err)
			}
			klog.V(5).InfoS("Capture packets", "name", captureState.name, "count",
				captureState.capturedPacketsNum, "len", ci.Length)

			reachTarget := captureState.capturedPacketsNum == captureState.targetCapturedPacketsNum
			// use rate limiter to reduce the times we need to update status.
			if reachTarget || captureState.updateRateLimiter.Allow() {
				pc, err := c.packetCaptureLister.Get(captureState.name)
				if err != nil {
					return fmt.Errorf("get PacketCapture failed: %w", err)
				}
				// if reach the target. flush the file and upload it.
				if reachTarget {
					path := os.Getenv("POD_NAME") + ":" + nameToPath(pc.Name)
					if err = captureState.pcapngWriter.Flush(); err != nil {
						return err
					}
					if pc.Spec.FileServer != nil {
						err = c.uploadPackets(pc, captureState.pcapngFile)
						klog.V(4).InfoS("Upload captured packets", "name", pc.Name, "path", path)

					}
					// update capture result.
					if updateErr := c.updatePacketCaptureStatus(pc.Name, captureState.capturedPacketsNum, path, err); updateErr != nil {
						klog.ErrorS(err, "Failed to update PacketCapture status")
					}
					if err != nil {
						return err
					}
					if err := captureState.pcapngFile.Close(); err != nil {
						klog.ErrorS(err, "Close pcapng file error", "name", pc.Name, "path", path)
					}
				}

				err = c.updatePacketCaptureStatus(pc.Name, captureState.capturedPacketsNum, "", nil)
				if err != nil {
					klog.ErrorS(err, "Failed to update PacketCapture status")
				} else {
					klog.InfoS("Updated PacketCapture", "PacketCapture", klog.KObj(pc), "capturedPacketsNum", captureState.capturedPacketsNum)
				}
			}
		case <-ctx.Done():
			pc, err := c.packetCaptureLister.Get(captureState.name)
			if err != nil {
				return fmt.Errorf("get PacketCapture failed: %w", err)
			}
			klog.InfoS("PacketCapture timeout", "name", pc.Name)
			err = errors.New(captureTimeoutReason)
			if updateErr := c.updatePacketCaptureStatus(pc.Name, captureState.capturedPacketsNum, "", err); updateErr != nil {
				klog.ErrorS(updateErr, "The PacketCapture timed out, but PacketCapture status update failed", "name", pc.Name)
			}
			return err
		}
	}
}

func (c *Controller) getPodIP(podRef *crdv1alpha1.PodReference) (net.IP, error) {
	podInterfaces := c.interfaceStore.GetContainerInterfacesByPod(podRef.Name, podRef.Namespace)
	var result net.IP
	if len(podInterfaces) > 0 {
		result = podInterfaces[0].GetIPv4Addr()
	} else {
		pod, err := c.kubeClient.CoreV1().Pods(podRef.Namespace).Get(context.TODO(), podRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get Pod %s/%s: %w", podRef.Namespace, podRef.Name, err)
		}
		podIPs := make([]net.IP, len(pod.Status.PodIPs))
		for i, ip := range pod.Status.PodIPs {
			podIPs[i] = net.ParseIP(ip.IP)
		}
		result = util.GetIPv4Addr(podIPs)
	}
	if result == nil {
		return nil, fmt.Errorf("cannot find IP with IPV4 AddressFamily for Pod %s/%s", podRef.Namespace, podRef.Name)
	}
	return result, nil
}

func (c *Controller) parseIPs(pc *crdv1alpha1.PacketCapture) (srcIP, dstIP net.IP, err error) {
	if pc.Spec.Source.Pod != nil {
		srcIP, err = c.getPodIP(pc.Spec.Source.Pod)
	} else if pc.Spec.Source.IP != nil {
		srcIP = net.ParseIP(*pc.Spec.Source.IP)
		if srcIP == nil {
			err = errors.New("invalid source IP address: " + *pc.Spec.Source.IP)
		}
	}

	if pc.Spec.Destination.Pod != nil {
		dstIP, err = c.getPodIP(pc.Spec.Destination.Pod)
	} else if pc.Spec.Destination.IP != nil {
		dstIP = net.ParseIP(*pc.Spec.Destination.IP)
		if dstIP == nil {
			err = errors.New("invalid destination IP address: " + *pc.Spec.Destination.IP)
		}
	}
	return
}

func (c *Controller) patchStatusIfNeeded(name string, status packetCapturePhase) error {
	klog.InfoS("Patching PacketCapture CR Status if needed", "name", name, "status", status)
	conditions := []crdv1alpha1.PacketCaptureCondition{}

	if status == packetCapturePhaseRunning {
		conditions = append(conditions, crdv1alpha1.PacketCaptureCondition{
			Type:               crdv1alpha1.PacketCaptureRunning,
			Status:             metav1.ConditionStatus(v1.ConditionTrue),
			LastTransitionTime: metav1.Now(),
		})
	} else if status == packetCapturePhasePending || status == packetCapturePhaseUnknown {
		conditions = append(conditions, crdv1alpha1.PacketCaptureCondition{
			Type:               crdv1alpha1.PacketCapturePending,
			Status:             metav1.ConditionStatus(v1.ConditionTrue),
			LastTransitionTime: metav1.Now(),
		})
	} else {
		return nil
	}

	toUpdate, getErr := c.packetCaptureLister.Get(name)
	if getErr != nil {
		return getErr
	}
	if retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		newCond := mergeConditions(toUpdate.Status.Conditions, conditions)
		if conditionSliceEqualsIgnoreLastTransitionTime(toUpdate.Status.Conditions, newCond) {
			return nil
		}
		toUpdate.Status.Conditions = newCond
		klog.V(2).InfoS("Updating PacketCapture", "name", name, "status", toUpdate.Status)
		_, updateErr := c.crdClient.CrdV1alpha1().PacketCaptures().UpdateStatus(context.TODO(), toUpdate, metav1.UpdateOptions{})
		if updateErr != nil && apierrors.IsConflict(updateErr) {
			var getErr error
			if toUpdate, getErr = c.crdClient.CrdV1alpha1().PacketCaptures().Get(context.TODO(), name, metav1.GetOptions{}); getErr != nil {
				return getErr
			}
		}
		return updateErr
	}); retryErr != nil {
		return retryErr
	}

	return nil
}

func (c *Controller) getUploaderByProtocol(protocol storageProtocolType) (ftp.Uploader, error) {
	if protocol == sftpProtocol {
		return c.sftpUploader, nil
	}
	return nil, fmt.Errorf("unsupported protocol %s", protocol)
}

func (c *Controller) generatePacketsPathForServer(name string) string {
	return name + ".pcapng"
}

func (c *Controller) uploadPackets(pc *crdv1alpha1.PacketCapture, outputFile afero.File) error {
	klog.V(2).InfoS("Uploading captured packets for PacketCapture", "name", pc.Name)
	uploader, err := c.getUploaderByProtocol(sftpProtocol)
	if err != nil {
		return fmt.Errorf("failed to upload packets while getting uploader: %w", err)
	}
	authSecret := v1.SecretReference{
		Name:      fileServerAuthSecretName,
		Namespace: env.GetAntreaNamespace(),
	}
	serverAuth, err := ftp.ParseFileServerAuth(ftp.BasicAuthentication, &authSecret, c.kubeClient)
	if err != nil {
		klog.ErrorS(err, "Failed to get authentication for the fileServer", "name", pc.Name, "authSecret", authSecret)
		return err
	}
	cfg := ftp.GenSSHClientConfig(serverAuth.BasicAuthentication.Username, serverAuth.BasicAuthentication.Password)
	return uploader.Upload(pc.Spec.FileServer.URL, c.generatePacketsPathForServer(pc.Name), cfg, outputFile)
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
		NumberCaptured: num,
		FilePath:       path,
	}

	if err != nil {
		if isCaptureCompleted(toUpdate, num) {
			updatedStatus.Conditions = []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.PacketCaptureCompleted,
					Status:             metav1.ConditionStatus(v1.ConditionTrue),
					LastTransitionTime: t,
					Reason:             "Succeed",
				},
			}
		} else {
			updatedStatus.Conditions = []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.PacketCaptureCompleted,
					Status:             metav1.ConditionStatus(v1.ConditionFalse),
					LastTransitionTime: t,
					Reason:             "CaptureFailed",
					Message:            err.Error(),
				},
			}
		}
		if toUpdate.Spec.FileServer != nil {
			updatedStatus.Conditions = append(updatedStatus.Conditions, crdv1alpha1.PacketCaptureCondition{
				Type:               crdv1alpha1.PacketCaptureFileUploaded,
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
					Type:               crdv1alpha1.PacketCaptureCompleted,
					Status:             metav1.ConditionStatus(v1.ConditionTrue),
					LastTransitionTime: t,
					Reason:             "Succeed",
				},
			}
			if toUpdate.Spec.FileServer != nil {
				updatedStatus.Conditions = append(updatedStatus.Conditions, crdv1alpha1.PacketCaptureCondition{
					Type:               crdv1alpha1.PacketCaptureFileUploaded,
					Status:             metav1.ConditionStatus(v1.ConditionTrue),
					LastTransitionTime: t,
					Reason:             "Succeed",
				})
			}
		} else {
			updatedStatus.Conditions = []crdv1alpha1.PacketCaptureCondition{
				{
					Type:               crdv1alpha1.PacketCaptureCompleted,
					Status:             metav1.ConditionStatus(v1.ConditionUnknown),
					LastTransitionTime: t,
				},
			}
			if toUpdate.Spec.FileServer != nil {
				updatedStatus.Conditions = append(updatedStatus.Conditions, crdv1alpha1.PacketCaptureCondition{
					Type:               crdv1alpha1.PacketCaptureFileUploaded,
					Status:             metav1.ConditionStatus(v1.ConditionUnknown),
					LastTransitionTime: t,
				})
			}
		}

	}

	if retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if toUpdate.Status.FilePath != "" {
			updatedStatus.FilePath = toUpdate.Status.FilePath
		}
		if updatedStatus.NumberCaptured == 0 && toUpdate.Status.NumberCaptured > 0 {
			updatedStatus.NumberCaptured = toUpdate.Status.NumberCaptured
		}

		updatedStatus.Conditions = mergeConditions(toUpdate.Status.Conditions, updatedStatus.Conditions)
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

func mergeConditions(oldConditions, newConditions []crdv1alpha1.PacketCaptureCondition) []crdv1alpha1.PacketCaptureCondition {
	finalConditions := make([]crdv1alpha1.PacketCaptureCondition, 0)
	newConditionMap := make(map[crdv1alpha1.PacketCaptureConditionType]crdv1alpha1.PacketCaptureCondition)
	addedConditions := sets.New[string]()
	for _, condition := range newConditions {
		newConditionMap[condition.Type] = condition
	}
	for _, oldCondition := range oldConditions {
		newCondition, exists := newConditionMap[oldCondition.Type]
		if !exists {
			finalConditions = append(finalConditions, oldCondition)
			continue
		}
		// Use the original Condition if the only change is about lastTransition time
		if conditionEqualsIgnoreLastTransitionTime(newCondition, oldCondition) {
			finalConditions = append(finalConditions, oldCondition)
		} else {
			// Use the latest Condition.
			finalConditions = append(finalConditions, newCondition)
		}
		addedConditions.Insert(string(newCondition.Type))
	}
	for key, newCondition := range newConditionMap {
		if !addedConditions.Has(string(key)) {
			finalConditions = append(finalConditions, newCondition)
		}
	}
	return finalConditions
}