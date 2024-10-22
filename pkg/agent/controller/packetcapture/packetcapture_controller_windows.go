package packetcapture

import (
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	clientsetversioned "antrea.io/antrea/pkg/client/clientset/versioned"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	clientset "k8s.io/client-go/kubernetes"
)

type Controller struct {
}

func NewPacketCaptureController(
	kubeClient clientset.Interface,
	crdClient clientsetversioned.Interface,
	packetCaptureInformer crdinformers.PacketCaptureInformer,
	interfaceStore interfacestore.InterfaceStore,
	nodeConfig *config.NodeConfig,
) *Controller {
	return &Controller{}
}

func (c *Controller) Run(stopCh <-chan struct{}) {
	return
}
