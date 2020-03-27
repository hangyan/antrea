// +build !race

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

package networkpolicy

import (
	"context"
	"fmt"
	goruntime "runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
)

/*
TestComputeNetworkPolicyXLargeScale tests the execution time and the memory usage of computing a scale
of 25k Namespaces, 75k NetworkPolicies, 100k Pods. The reference value is:

NAMESPACES   PODS    NETWORK-POLICIES    TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
25000        100000  75000               6.10       1626         519853        208503 166707 208503
25000        100000  75000               5.84       1522         585696        225480 182641 225480
25000        100000  75000               6.42       1708         507003        206149 163293 206149

The metrics are not accurate under the race detector, and will be skipped when testing with "-race".
*/
func TestComputeNetworkPolicyXLargeScale(t *testing.T) {
	getObjects := func() ([]*v1.Namespace, []*networkingv1.NetworkPolicy, []*v1.Pod) {
		namespace := rand.String(8)
		namespaces := []*v1.Namespace{
			{
				ObjectMeta: metav1.ObjectMeta{Name: namespace, Labels: map[string]string{"app": namespace}},
			},
		}
		networkPolicies := []*networkingv1.NetworkPolicy{
			{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "default-deny-all", UID: types.UID(uuid.New().String())},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "np-1", UID: types.UID(uuid.New().String())},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app-1": "scale-1"}},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
					Ingress: []networkingv1.NetworkPolicyIngressRule{
						{
							From: []networkingv1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"app-1": "scale-1"},
									},
								},
							},
						},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "np-2", UID: types.UID(uuid.New().String())},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app-2": "scale-2"}},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
					Ingress: []networkingv1.NetworkPolicyIngressRule{
						{
							From: []networkingv1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"app-2": "scale-2"},
									},
								},
							},
						},
					},
				},
			},
		}
		pods := []*v1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "pod1", UID: types.UID(uuid.New().String()), Labels: map[string]string{"app-1": "scale-1"}},
				Spec:       v1.PodSpec{NodeName: getRandomNodeName()},
				Status:     v1.PodStatus{PodIP: getRandomIP()},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "pod2", UID: types.UID(uuid.New().String()), Labels: map[string]string{"app-1": "scale-1"}},
				Spec:       v1.PodSpec{NodeName: getRandomNodeName()},
				Status:     v1.PodStatus{PodIP: getRandomIP()},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "pod3", UID: types.UID(uuid.New().String()), Labels: map[string]string{"app-2": "scale-2"}},
				Spec:       v1.PodSpec{NodeName: getRandomNodeName()},
				Status:     v1.PodStatus{PodIP: getRandomIP()},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "pod4", UID: types.UID(uuid.New().String()), Labels: map[string]string{"app-2": "scale-2"}},
				Spec:       v1.PodSpec{NodeName: getRandomNodeName()},
				Status:     v1.PodStatus{PodIP: getRandomIP()},
			},
		}
		return namespaces, networkPolicies, pods
	}
	namespaces, networkPolicies, pods := getXObjects(25000, getObjects)
	testComputeNetworkPolicy(t, 10*time.Second, namespaces, networkPolicies, pods)
}

func testComputeNetworkPolicy(t *testing.T, maxExecutionTime time.Duration, namespaces []*v1.Namespace, networkPolicies []*networkingv1.NetworkPolicy, pods []*v1.Pod) {
	objs := make([]runtime.Object, 0, len(namespaces)+len(networkPolicies)+len(pods))
	for i := range namespaces {
		objs = append(objs, namespaces[i])
	}
	for i := range networkPolicies {
		objs = append(objs, networkPolicies[i])
	}
	for i := range pods {
		objs = append(objs, pods[i])
	}

	_, c := newController(objs...)
	c.heartbeatCh = make(chan heartbeat, 1000)

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	// executionMetric is used to count the executions of each routine and to record the last execution time.
	type executionMetric struct {
		executions    int
		lastExecution time.Time
	}
	executionMetrics := map[string]*executionMetric{}

	// If we don't receive any heartbeat from NetworkPolicyController for 3 seconds, it should have finished
	// all computation 3 seconds ago.
	idleTimeout := 3 * time.Second
	timer := time.NewTimer(idleTimeout)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			timer.Reset(idleTimeout)
			select {
			case heartbeat := <-c.heartbeatCh:
				m, ok := executionMetrics[heartbeat.name]
				if !ok {
					m = &executionMetric{}
					executionMetrics[heartbeat.name] = m
				}
				m.executions++
				m.lastExecution = heartbeat.timestamp
			case <-timer.C:
				// Send the stop signal if we don't receive any heartbeat for 3 seconds.
				close(stopCh)
				return
			}
		}
	}()

	// maxAlloc is used to record the maximum heap allocation.
	var maxAlloc uint64
	var memStats goruntime.MemStats
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				goruntime.ReadMemStats(&memStats)
				if memStats.Alloc > atomic.LoadUint64(&maxAlloc) {
					atomic.StoreUint64(&maxAlloc, memStats.Alloc)
				}
			}
		}
	}()

	// The watchers are used to count how many events we will get during the computation.
	addressGroupWatcher, _ := c.addressGroupStore.Watch(context.Background(), "", labels.Everything(), fields.Everything())
	appliedToGroupWatcher, _ := c.appliedToGroupStore.Watch(context.Background(), "", labels.Everything(), fields.Everything())
	networkPolicyWatcher, _ := c.internalNetworkPolicyStore.Watch(context.Background(), "", labels.Everything(), fields.Everything())
	addressGroupEvents, appliedToGroupEvents, networkPolicyEvents := 0, 0, 0
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-addressGroupWatcher.ResultChan():
				addressGroupEvents++
			case <-appliedToGroupWatcher.ResultChan():
				appliedToGroupEvents++
			case <-networkPolicyWatcher.ResultChan():
				networkPolicyEvents++
			case <-stopCh:
				return
			}
		}
	}()

	// Everything is ready, now start timing.
	start := time.Now()
	c.informerFactory.Start(stopCh)
	go c.Run(stopCh)

	// Block until all computation is done.
	<-stopCh
	// Minus the idle time to get the actual finish time.
	executionTime := time.Since(start) - idleTimeout
	if executionTime > maxExecutionTime {
		t.Errorf("The actual execution time %v is greater than the maximum value %v", executionTime, maxExecutionTime)
	}

	// Block until all statistics are done.
	wg.Wait()

	totalExecution := 0
	for name, m := range executionMetrics {
		t.Logf("Execution metrics of %s, executions: %d, duration: %v", name, m.executions, m.lastExecution.Sub(start))
		totalExecution += m.executions
	}

	t.Logf(`Summary metrics:
NAMESPACES   PODS    NETWORK-POLICIES    TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
%-12d %-7d %-19d %-10.2f %-12d %-13d %d %d %d
`, len(namespaces), len(pods), len(networkPolicies), float64(executionTime)/float64(time.Second), atomic.LoadUint64(&maxAlloc)/1024/1024, totalExecution, networkPolicyEvents, appliedToGroupEvents, networkPolicyEvents)
}

func getRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
}

func getRandomNodeName() string {
	return fmt.Sprintf("Node-%d", rand.Intn(1000))
}

func getXObjects(x int, getObjectsFunc func() ([]*v1.Namespace, []*networkingv1.NetworkPolicy, []*v1.Pod)) ([]*v1.Namespace, []*networkingv1.NetworkPolicy, []*v1.Pod) {
	var namespaces []*v1.Namespace
	var networkPolicies []*networkingv1.NetworkPolicy
	var pods []*v1.Pod
	for i := 0; i < x; i++ {
		newNamespaces, newNetworkPolicies, newPods := getObjectsFunc()
		namespaces = append(namespaces, newNamespaces...)
		networkPolicies = append(networkPolicies, newNetworkPolicies...)
		pods = append(pods, newPods...)
	}
	return namespaces, networkPolicies, pods
}
