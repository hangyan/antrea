package packetcapture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/antctl/raw"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	antrea "antrea.io/antrea/pkg/client/clientset/versioned"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

const defaultTimeout time.Duration = time.Second * 60

var Command *cobra.Command

var option = &struct {
	source     string
	dest       string
	protocol   string
	sourcePort int32
	destPort   int32
	nowait     bool
	timeout    time.Duration
}{}

var packetCaptureExample = strings.TrimSpace(`
  Start capture packets from pod1 to pod2, both Pods are in Namespace default
  $ antctl packetcaputre -S pod1 -D pod2
  Start capture packets from pod1 in Namespace ns1 to a destination IP
  $ antctl packetcapture -S ns1/pod1 -D 192.168.123.123
`)

func init() {
	Command = &cobra.Command{
		Use:     "packetcapture",
		Short:   "Start capture packets",
		Long:    "Start capture packets on the target flow.",
		Example: packetCaptureExample,
		RunE:    packetCaptureRunE,
	}

	Command.Flags().StringVarP(&option.source, "source", "s", "", "source of the the PacketCapture: Namespace/Pod, Pod, or IP")
	Command.Flags().StringVarP(&option.dest, "dest", "d", "", "destination of the PacketCapture: Namespace/Pod, Pod, or IP")

}

func getClients(cmd *cobra.Command) (kubernetes.Interface, antrea.Interface, error) {
	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return nil, nil, err
	}
	k8sClientset, client, err := raw.SetupClients(kubeconfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create clientset: %w", err)
	}
	return k8sClientset, client, nil
}

func packetCaptureRunE(cmd *cobra.Command, args []string) error {
	option.timeout, _ = cmd.Flags().GetDuration("timeout")
	if option.timeout > time.Hour {
		fmt.Fprintf(cmd.OutOrStdout(), "Timeout cannot be longer than 1 hour")
		return nil
	}
	if option.timeout == 0 {
		option.timeout = defaultTimeout
	}
	k8sClient, client, err := getClients(cmd)
	if err != nil {
		return err
	}
	pc, err := newPacketCapture()
	if err != nil {
		return fmt.Errorf("error when filling up PacketCapture config: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.CrdV1alpha1().PacketCaptures().Create(ctx, pc, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("error when creating PacketCapture, is PacketCapture feature gate enabled? %w", err)
	}
	defer func() {
		if !option.nowait {
			if err = client.CrdV1alpha1().PacketCaptures().Delete(context.TODO(), pc.Name, metav1.DeleteOptions{}); err != nil {
				klog.Errorf("error when deleting PacketCapture: %w", err)
			}

		}
	}()

	if option.nowait {
		return nil
	}

	var res *v1alpha1.PacketCapture
	err = wait.PollUntilContextTimeout(context.TODO(), 1*time.Second, option.timeout, false, func(ctx context.Context) (bool, error) {
		res, err := client.CrdV1alpha1().PacketCaptures().Get(ctx, pc.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		for _, cond := range res.Status.Conditions {
			if cond.Type == v1alpha1.PacketCaptureComplete && cond.Status == metav1.ConditionTrue {
				return true, nil
			}
		}
		return false, nil

	})
	if wait.Interrupted(err) {
		err = errors.New("timeout waiting for PacketCapture done")
		if res == nil {
			return err
		}
	} else if err != nil {
		return fmt.Errorf("error when retrieving PacketCapture: %w", err)
	}

	return nil
}

func parseEndpoint(endpoint string) (pod *v1alpha1.PodReference, ip *string) {
	parsedIP := net.ParseIP(option.source)
	if parsedIP != nil && parsedIP.To4() != nil {
		ip = ptr.To(parsedIP.String())
	} else {
		split := strings.Split(option.source, "/")
		if len(split) == 1 {
			pod = &v1alpha1.PodReference{
				Namespace: "default",
				Name:      split[0],
			}
		} else if len(split) == 2 && len(split[0]) != 0 && len(split[1]) != 0 {
			pod = &v1alpha1.PodReference{
				Namespace: split[0],
				Name:      split[1],
			}
		}
	}
	return nil, nil
}

func getPCName(src, dest string) string {
	replace := func(s string) string {
		return strings.ReplaceAll(s, "/", "-")
	}
	prefix := fmt.Sprintf("%s-%s", replace(src), replace(dest))
	if option.nowait {
		return prefix
	}
	return fmt.Sprintf("%s-%s", prefix, rand.String(8))
}

func newPacketCapture() (*v1alpha1.PacketCapture, error) {
	var src v1alpha1.Source
	if option.source != "" {
		src.Pod, src.IP = parseEndpoint(option.source)
		if src.Pod == nil && src.IP == nil {
			return nil, fmt.Errorf("source should be in the format of Namespace/Pod, Pod, or IPv4")
		}
	}

	var dst v1alpha1.Destination
	if option.dest != "" {
		dst.Pod, dst.IP = parseEndpoint(option.dest)
		if dst.Pod == nil && dst.IP == nil {
			return nil, fmt.Errorf("destination should be in the format of Namespace/Pod, Pod, or IPv4")
		}
	}

	if src.Pod == nil && dst.Pod == nil {
		return nil, errors.New("one of source and destination must be a Pod")
	}

	name := getPCName(option.source, option.dest)
	pc := &v1alpha1.PacketCapture{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.PacketCaptureSpec{
			Source:      src,
			Destination: dst,
		},
	}
	return pc, nil
}
