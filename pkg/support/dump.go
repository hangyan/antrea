// Copyright 2021 Antrea Authors
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

package support

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/afero"
	"k8s.io/utils/exec"

	agentquerier "antrea.io/antrea/pkg/agent/querier"
	clusterinformationv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	controllerquerier "antrea.io/antrea/pkg/controller/querier"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	"antrea.io/antrea/pkg/querier"
	"antrea.io/antrea/pkg/util/logdir"
	"github.com/metakeule/fmtdate"
	"github.com/xhit/go-str2duration/v2"
)

// AgentDumper is the interface for dumping runtime information of the agent. Its
// functions should only work in an agent Pod or a Windows Node which has an agent
// installed.
type AgentDumper interface {
	// DumpFlows should create files that contains flows under the basedir.
	DumpFlows(basedir string) error
	// DumpHostNetworkInfo should create files that contains host network
	// information under the basedir. Host network information should include
	// links, routes, addresses and etc.
	DumpHostNetworkInfo(basedir string) error
	// DumpLog should create files that contains container logs of the agent
	// Pod under the basedir.
	DumpLog(basedir string) error
	// DumpAgentInfo should create a file that contains AgentInfo of the agent Pod
	// under the basedir.
	DumpAgentInfo(basedir string) error
	// DumpNetworkPolicyResources should create files that contains networkpolicy
	// resources on the agent Pod under the base dir.
	DumpNetworkPolicyResources(basedir string) error
	// DumpHeapPprof should create a pprof file of heap usage of the agent.
	DumpHeapPprof(basedir string) error

	// DumpOVSPorts should create file that contains OF port descriptions under the basedir.
	DumpOVSPorts(basedir string) error
}

// ControllerDumper is the interface for dumping runtime information of the
// controller. Its functions should only work in the controller Pod.
type ControllerDumper interface {
	// DumpLog should create files that contains container logs of the controller
	// Pod under the basedir.
	DumpLog(basedir string) error
	// DumpControllerInfo should create a file that contains ControllerInfo of
	// the controller Pod under the basedir.
	DumpControllerInfo(basedir string) error
	// DumpNetworkPolicyResources should create files that contains networkpolicy
	// resources on the controller Pod under the base dir.
	DumpNetworkPolicyResources(basedir string) error
	// DumpHeapPprof should create a pprof file of the heap usage of the controller.
	DumpHeapPprof(basedir string) error
}

func DumpHeapPprof(fs afero.Fs, basedir string) error {
	f, err := fs.Create(filepath.Join(basedir, "memprofile"))
	if err != nil {
		return err
	}
	defer f.Close()
	return pprof.WriteHeapProfile(f)
}

func dumpAntctlGet(fs afero.Fs, executor exec.Interface, name, basedir string) error {
	output, err := executor.Command("antctl", "-oyaml", "get", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error when dumping %s: %w", name, err)
	}
	return writeFile(fs, filepath.Join(basedir, name), name, output)
}

func dumpNetworkPolicyResources(fs afero.Fs, executor exec.Interface, basedir string) error {
	if err := dumpAntctlGet(fs, executor, "networkpolicies", basedir); err != nil {
		return err
	}
	if err := dumpAntctlGet(fs, executor, "appliedtogroups", basedir); err != nil {
		return err
	}
	return dumpAntctlGet(fs, executor, "addressgroups", basedir)
}

func timestampFilter(since string) *time.Time {
	var timeFilter *time.Time
	if since != "" {
		duration, _ := str2duration.ParseDuration(since)
		start := time.Now().Add(-duration)
		timeFilter = &start
	}
	return timeFilter

}


// parseTimeFromFileName parse time from log file name.
// example log file format: <component>.<hostname>.<user>.log.<level>.<yyyymmdd>-<hhmmss>.1
func parseTimeFromFileName(name string) (time.Time, error) {
	ss := strings.Split(name, ".")
	ts := ss[len(ss)-1]
	return fmtdate.Parse("YYYYMMDD-hhmmss", ts)

}

func parseTimeFromLogLine(log string, year string) (time.Time, error) {
	ss := strings.Split(log, ".")
	if ss[0] == "" {
		return time.Time{}, fmt.Errorf("log line is empty")
	}
	dateStr := year + ss[0][1:]
	return fmtdate.Parse("YYYYMMDD hh:mm:ss", dateStr)

}

// directoryCopy copies files under the srcDir to the targetDir. Only files whose name matches
// the prefixFilter will be copied. If prefixFiler is "", no filter is performed. At the same time, if the timeFilter is set,
// only files whose modTime is later than the timeFilter will be copied. If a file contains both older logs and matched logs, only
// the matched logs will be copied. Copied files will be located under the same relative path.
func directoryCopy(fs afero.Fs, targetDir string, srcDir string, prefixFilter string, timeFilter *time.Time) error {
	err := fs.MkdirAll(targetDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("error when creating target dir: %w", err)
	}
	return afero.Walk(fs, srcDir, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if prefixFilter != "" && !strings.HasPrefix(info.Name(), prefixFilter) {
			return nil
		}

		if timeFilter != nil && info.ModTime().Before(*timeFilter) {
			return nil
		}

		targetPath := path.Join(targetDir, info.Name())
		targetFile, err := fs.Create(targetPath)
		if err != nil {
			return err
		}
		defer targetFile.Close()

		srcFile, err := fs.Open(filePath)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		// ignore error here, copy the whole file
		startTime, _ := parseTimeFromFileName(info.Name())

		// process first matched file
		if timeFilter != nil && startTime.Before(*timeFilter) {
			data := ""
			scanner := bufio.NewScanner(srcFile)
			for scanner.Scan() {
				// the size limit of single log line is 64k. marked it as known issue and fix it if
				// error occurs
				line := scanner.Text()
				if data != "" {
					data += line + "\n"
				} else {
					ts, err := parseTimeFromLogLine(line, strconv.Itoa(timeFilter.Year()))
					if err == nil {
						if !ts.Before(*timeFilter) {
							data += line + "\n"
						}
					}
				}
			}
			_, err = targetFile.WriteString(data)
			return err
		} else {
			_, err = io.Copy(targetFile, srcFile)
			return err
		}
	})
}

// writeFile writes the given data to the specified filePath. Param "resource" is used to identify the type of the given
// data in the error message.
func writeFile(fs afero.Fs, filePath string, resource string, data []byte) error {
	err := afero.WriteFile(fs, filePath, data, 0644)
	if err != nil {
		return fmt.Errorf("error when writing %s to file: %w", resource, err)
	}
	return nil
}

type controllerDumper struct {
	fs       afero.Fs
	executor exec.Interface
	cq       controllerquerier.ControllerQuerier
	since    string
}

func (d *controllerDumper) DumpControllerInfo(basedir string) error {
	return dumpAntctlGet(d.fs, d.executor, "controllerinfo", basedir)
}

func (d *controllerDumper) DumpNetworkPolicyResources(basedir string) error {
	return dumpNetworkPolicyResources(d.fs, d.executor, basedir)
}

func (d *controllerDumper) DumpLog(basedir string) error {
	logDir := logdir.GetLogDir()
	return directoryCopy(d.fs, path.Join(basedir, "logs", "controller"), logDir, "antrea-controller", timestampFilter(d.since))
}

func (d *controllerDumper) DumpHeapPprof(basedir string) error {
	return DumpHeapPprof(d.fs, basedir)
}

func NewControllerDumper(fs afero.Fs, executor exec.Interface, since string) ControllerDumper {
	return &controllerDumper{
		fs:       fs,
		executor: executor,
		since:    since,
	}
}

type agentDumper struct {
	fs           afero.Fs
	executor     exec.Interface
	ovsCtlClient ovsctl.OVSCtlClient
	aq           agentquerier.AgentQuerier
	npq          querier.AgentNetworkPolicyInfoQuerier
	// days is for log filter
	since string
}

func (d *agentDumper) DumpAgentInfo(basedir string) error {
	ci := new(clusterinformationv1beta1.AntreaAgentInfo)
	d.aq.GetAgentInfo(ci, false)
	f, err := d.fs.Create(filepath.Join(basedir, "agentinfo"))
	if err != nil {
		return err
	}
	defer f.Close()
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(ci)
}

func (d *agentDumper) DumpNetworkPolicyResources(basedir string) error {
	dump := func(o interface{}, name string) error {
		f, err := d.fs.Create(filepath.Join(basedir, "agentinfo"))
		if err != nil {
			return err
		}
		defer f.Close()
		encoder := json.NewEncoder(f)
		encoder.SetIndent("", "  ")
		return encoder.Encode(o)
	}
	if err := dump(d.npq.GetAddressGroups(), "addressgroups"); err != nil {
		return err
	}
	if err := dump(d.npq.GetNetworkPolicies(&querier.NetworkPolicyQueryFilter{}), "networkpolicies"); err != nil {
		return err
	}
	return dump(d.npq.GetAppliedToGroups(), "appliedtogroups")
}

func (d *agentDumper) DumpFlows(basedir string) error {
	flows, err := d.ovsCtlClient.DumpFlows()
	if err != nil {
		return fmt.Errorf("error when dumping flows: %w", err)
	}
	return writeFile(d.fs, filepath.Join(basedir, "flows"), "flows", []byte(strings.Join(flows, "\n")))
}

func (d *agentDumper) DumpHeapPprof(basedir string) error {
	return DumpHeapPprof(d.fs, basedir)
}

func (d *agentDumper) DumpOVSPorts(basedir string) error {
	portsDesc, err := d.ovsCtlClient.DumpPortsDesc()
	if err != nil {
		return fmt.Errorf("error when dumping ports desc: %w", err)
	}
	portData := make([]string, len(portsDesc))
	for idx := range portsDesc {
		portData[idx] = strings.Join(portsDesc[idx], "\n")
	}
	return writeFile(d.fs, filepath.Join(basedir, "ovsports"), "ports", []byte(strings.Join(portData, "\n")))
}

func NewAgentDumper(fs afero.Fs, executor exec.Interface, ovsCtlClient ovsctl.OVSCtlClient, aq agentquerier.AgentQuerier, npq querier.AgentNetworkPolicyInfoQuerier, since string) AgentDumper {
	return &agentDumper{
		fs:           fs,
		executor:     executor,
		ovsCtlClient: ovsCtlClient,
		aq:           aq,
		npq:          npq,
		since:        since,
	}
}
