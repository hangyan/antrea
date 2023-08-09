// Copyright 2020 Antrea Authors
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

package samplingpacket

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/spf13/afero"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/klog/v2"
	clockutils "k8s.io/utils/clock"
	"k8s.io/utils/exec"

	systemv1beta1 "antrea.io/antrea/pkg/apis/system/v1beta1"
	"antrea.io/antrea/pkg/support"
	"antrea.io/antrea/pkg/util/compress"
)

const (
	bundleExpireDuration = time.Hour
	modeController       = "controller"
	modeAgent            = "agent"
)

var (
	// Declared as variables for testing.
	defaultFS       = afero.NewOsFs()
	defaultExecutor = exec.New()
	newAgentDumper  = support.NewAgentDumper

	clock clockutils.Clock = clockutils.RealClock{}
)

// NewControllerStorage creates a sampling storage for working on antrea controller.
func NewControllerStorage() Storage {
	bundle := &supportBundleREST{
		mode: modeController,
		cache: &systemv1beta1.SupportBundle{
			ObjectMeta: metav1.ObjectMeta{Name: modeController},
			Status:     systemv1beta1.SupportBundleStatusNone,
		},
	}
	return Storage{
		Mode:          modeController,
		SupportBundle: bundle,
		Download:      &downloadREST{supportBundle: bundle},
	}
}

// NewAgentStorage creates a sampling packet storage for working on antrea agent.
func NewAgentStorage() Storage {
	bundle := &samplingPacketsREST{
		mode: modeAgent,
		cache: &systemv1beta1.CapturedPacket{
			ObjectMeta: metav1.ObjectMeta{Name: modeAgent},
		},
	}
	return Storage{
		Mode:          modeAgent,
		SupportBundle: bundle,
		Download:      &downloadREST{supportBundle: bundle},
	}
}

// Storage contains REST resources for sampling packet, including status query and download.
type Storage struct {
	SamplingPacket *samplingPacketsREST
	Download       *downloadREST
	Mode           string
}

var (
	_ rest.Scoper          = &samplingPacketsREST{}
	_ rest.Getter          = &samplingPacketsREST{}
	_ rest.Creater         = &samplingPacketsREST{}
	_ rest.GracefulDeleter = &samplingPacketsREST{}
)

// supportBundleREST implements REST interfaces for bundle status querying.
type samplingPacketsREST struct {
	mode         string
	statusLocker sync.RWMutex
	cancelFunc   context.CancelFunc
	cache        *systemv1beta1.CapturedPacket
}

// Create triggers a bundle generation. It only allows resource creation when
// the name matches the mode. It returns metav1.Status if there is any error,
// otherwise it returns the SupportBundle.
func (r *samplingPacketsREST) Create(ctx context.Context, obj runtime.Object, _ rest.ValidateObjectFunc, _ *metav1.CreateOptions) (runtime.Object, error) {
	requestBundle := obj.(*systemv1beta1.CapturedPacket)
	if requestBundle.Name != r.mode {
		return nil, errors.NewForbidden(systemv1beta1.ControllerInfoVersionResource.GroupResource(), requestBundle.Name, fmt.Errorf("only resource name \"%s\" is allowed", r.mode))
	}
	r.statusLocker.Lock()
	defer r.statusLocker.Unlock()

	if r.cancelFunc != nil {
		r.cancelFunc()
	}
	ctx, cancelFunc := context.WithCancel(context.Background())
	r.cache = &systemv1beta1.CapturedPacket{
		ObjectMeta: metav1.ObjectMeta{Name: r.mode},
	}
	r.cancelFunc = cancelFunc
	go func() {
		var err error
		var b *systemv1beta1.SupportBundle
		if r.mode == modeAgent {
			b, err = r.collectAgent(ctx, since)
		} else if r.mode == modeController {
			b, err = r.collectController(ctx, since)
		}
		func() {
			r.statusLocker.Lock()
			defer r.statusLocker.Unlock()
			if err != nil {
				klog.Errorf("Error when collecting supportBundle: %v", err)
				r.cache.Status = systemv1beta1.SamplingPacketStatusNone
				return
			}
			select {
			case <-ctx.Done():
			default:
				r.cache = b
			}
		}()

		if err == nil {
			r.clean(ctx, b.Filepath, bundleExpireDuration)
		}
	}()

	return r.cache, nil
}

func (r *samplingPacketsREST) New() runtime.Object {
	return &systemv1beta1.SupportBundle{}
}

func (r *samplingPacketsREST) Destroy() {
}

// Get returns current status of the bundle. It only allows querying the resource
// whose name is equal to the mode.
func (r *samplingPacketsREST) Get(_ context.Context, name string, _ *metav1.GetOptions) (runtime.Object, error) {
	r.statusLocker.RLock()
	defer r.statusLocker.RUnlock()
	if r.cache.Name != name {
		return nil, errors.NewNotFound(systemv1beta1.Resource("supportBundle"), name)
	}
	return r.cache, nil
}

// Delete can remove the current finished bundle or cancel a running bundle
// collecting. It only allows querying the resource whose name is equal to the mode.
func (r *samplingPacketsREST) Delete(_ context.Context, name string, _ rest.ValidateObjectFunc, _ *metav1.DeleteOptions) (runtime.Object, bool, error) {
	if name != r.mode {
		return nil, false, errors.NewNotFound(systemv1beta1.Resource("supportBundle"), name)
	}
	r.statusLocker.Lock()
	defer r.statusLocker.Unlock()
	if r.cancelFunc != nil {
		r.cancelFunc()
	}
	r.cache = &systemv1beta1.SupportBundle{
		ObjectMeta: metav1.ObjectMeta{Name: r.mode},
		Status:     systemv1beta1.SupportBundleStatusNone,
	}
	return nil, true, nil
}

func (r *samplingPacketsREST) NamespaceScoped() bool {
	return false
}

func (r *samplingPacketsREST) collect(ctx context.Context, dumpers ...func(string) error) (*systemv1beta1.SupportBundle, error) {
	basedir, err := afero.TempDir(defaultFS, "", "bundle_tmp_")
	if err != nil {
		return nil, fmt.Errorf("error when creating tempdir: %w", err)
	}
	defer defaultFS.RemoveAll(basedir)
	for _, dumper := range dumpers {
		if err := dumper(basedir); err != nil {
			return nil, err
		}
	}
	outputFile, err := afero.TempFile(defaultFS, "", "bundle_*.tar.gz")
	if err != nil {
		return nil, fmt.Errorf("error when creating output tarfile: %w", err)
	}
	defer outputFile.Close()
	hashSum, err := compress.PackDir(defaultFS, basedir, outputFile)
	if err != nil {
		return nil, fmt.Errorf("error when packaging supportBundle: %w", err)
	}

	select {
	case <-ctx.Done():
		_ = defaultFS.Remove(outputFile.Name())
		return nil, fmt.Errorf("collecting is canceled")
	default:
	}
	stat, err := outputFile.Stat()
	var fileSize int64
	if err == nil {
		fileSize = stat.Size()
	}
	creationTime := metav1.Now()
	deletionTime := metav1.NewTime(creationTime.Add(bundleExpireDuration))
	return &systemv1beta1.SupportBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name:              r.mode,
			CreationTimestamp: creationTime,
			DeletionTimestamp: &deletionTime,
		},
		Status:   systemv1beta1.SupportBundleStatusCollected,
		Sum:      fmt.Sprintf("%x", hashSum),
		Size:     uint32(fileSize),
		Filepath: outputFile.Name(),
	}, nil
}

func (r *samplingPacketsREST) collectAgent(ctx context.Context, name string) (*systemv1beta1.SupportBundle, error) {
	dumper := newAgentDumper(defaultFS, defaultExecutor, r.ovsCtlClient, r.aq, r.npq, since, r.v4Enabled, r.v6Enabled)
	return r.collect(
		ctx,
		dumper.DumpLog,
		dumper.DumpHostNetworkInfo,
		dumper.DumpFlows,
		dumper.DumpNetworkPolicyResources,
		dumper.DumpAgentInfo,
		dumper.DumpHeapPprof,
		dumper.DumpOVSPorts,
		dumper.DumpMemberlist,
	)
}

func (r *samplingPacketsREST) collectController(ctx context.Context, since string) (*systemv1beta1.SupportBundle, error) {
	dumper := support.NewControllerDumper(defaultFS, defaultExecutor, since)
	return r.collect(
		ctx,
		dumper.DumpLog,
		dumper.DumpNetworkPolicyResources,
		dumper.DumpControllerInfo,
		dumper.DumpHeapPprof,
	)
}

func (r *samplingPacketsREST) clean(ctx context.Context, bundlePath string, duration time.Duration) {
	select {
	case <-ctx.Done():
	case <-clock.After(duration):
		func() {
			r.statusLocker.Lock()
			defer r.statusLocker.Unlock()
			select { // check the context again in case of cancellation when acquiring the lock.
			case <-ctx.Done():
			default:
				if r.cache.Status == systemv1beta1.SupportBundleStatusCollected {
					r.cache = &systemv1beta1.SupportBundle{
						ObjectMeta: metav1.ObjectMeta{Name: r.mode},
						Status:     systemv1beta1.SupportBundleStatusNone,
					}
				}
			}
		}()
	}
	defaultFS.Remove(bundlePath)
}

var (
	_ rest.Storage         = new(downloadREST)
	_ rest.Getter          = new(downloadREST)
	_ rest.StorageMetadata = new(downloadREST)
)

// downloadREST implements the REST for downloading the bundle.
type downloadREST struct {
	supportBundle *samplingPacketsREST
}

func (d *downloadREST) New() runtime.Object {
	return &systemv1beta1.SupportBundle{}
}

func (d *downloadREST) Destroy() {
}

func (d *downloadREST) Get(_ context.Context, _ string, _ *metav1.GetOptions) (runtime.Object, error) {
	return &bundleStream{d.supportBundle.cache}, nil
}

func (d *downloadREST) ProducesMIMETypes(_ string) []string {
	return []string{"application/tar+gz"}
}

func (d *downloadREST) ProducesObject(_ string) interface{} {
	return ""
}

var (
	_ rest.ResourceStreamer = new(bundleStream)
	_ runtime.Object        = new(bundleStream)
)

type bundleStream struct {
	cache *systemv1beta1.SupportBundle
}

func (b *bundleStream) GetObjectKind() schema.ObjectKind {
	return schema.EmptyObjectKind
}

func (b *bundleStream) DeepCopyObject() runtime.Object {
	panic("bundleStream does not have DeepCopyObject")
}

func (b *bundleStream) InputStream(_ context.Context, _, _ string) (stream io.ReadCloser, flush bool, mimeType string, err error) {
	// f will be closed by invoker, no need to close in this function.
	f, err := defaultFS.Open(b.cache.Filepath)
	if err != nil {
		return nil, false, "", err
	}
	return f, true, "application/tar+gz", nil
}
