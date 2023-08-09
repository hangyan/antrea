package samplingpacket

import (
	"antrea.io/antrea/pkg/util/logdir"
	"bufio"
	"fmt"
	"github.com/spf13/afero"
	"io"
	"k8s.io/utils/exec"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

type agentDumper struct {
	fs           afero.Fs
	executor     exec.Interface

}

func NewAgentDumper(fs afero.Fs, executor exec.Interface) *agentDumper {
	return &agentDumper{
		fs:           fs,
		executor:     executor,
	}
}

func (d *agentDumper) DumpLog(basedir string) error {
	logDir := logdir.GetLogDir()
	return directoryCopy(d.fs, path.Join(basedir, "logs", "controller"), logDir, "antrea-controller", timestampFilter(d.since))
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
			return fmt.Errorf("error when creating target file %s: %w", targetPath, err)
		}
		defer targetFile.Close()

		srcFile, err := fs.Open(filePath)
		if err != nil {
			return fmt.Errorf("error when opening source file %s: %w", filePath, err)
		}
		defer srcFile.Close()

		startTime, err := parseTimeFromFileName(info.Name())
		if timeFilter != nil {
			// if name contains timestamp, use it to find the first matched file. If not, such as ovs log file,
			// just parse the log file (usually there is only one log file for each component)
			if err == nil && startTime.Before(*timeFilter) || err != nil {
				data := ""
				scanner := bufio.NewScanner(srcFile)
				for scanner.Scan() {
					// the size limit of single log line is 64k. marked it as known issue and fix it if
					// error occurs
					line := scanner.Text()
					if data != "" {
						data += line + "\n"
					} else {
						ts, err := parseTimeFromLogLine(line, strconv.Itoa(timeFilter.Year()), prefixFilter)
						if err == nil {
							if !ts.Before(*timeFilter) {
								data += line + "\n"
							}
						}
					}
				}
				_, err = targetFile.WriteString(data)
				return err
			}
		}
		_, err = io.Copy(targetFile, srcFile)
		return err
	})
}