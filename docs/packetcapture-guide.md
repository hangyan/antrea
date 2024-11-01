# Packet Capture User Guide

Starting with Antrea v2.2, Antrea supports PacketCapture for network diagnosis.
It can capture specified number of packets from real traffic and upload them to a
supported storage location. Users can create a `PacketCapture` CR to trigger
packet capture on the target traffic flow.

## Prerequisites

PacketCapture is disabled by default. If you
want to enable this feature, you need to set feature gate `PacketCapture` to `true` in
the `antrea-config` ConfigMap for `antrea-agent`.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: antrea-config
  namespace: kube-system
data:
  antrea-agent.conf: |
    featureGates:
      PacketCapture: true
```

## Start a new PacketCapture

When starting a new packet capture, you can provide the following information to identify
the target traffic flow:

* Source Pod
* Destination Pod, Service or IP address
* Transport protocol (TCP/UDP/ICMP)
* Transport ports

You can start a new packet capture by creating a `PacketCapture` CR. An optional `fileServer` field can be specified to
store the generated packets file. Before that, a Secret named `antrea-packetcapture-fileserver-auth`
located in the same Namespace where Antrea is deployed must exist and carry the authentication information for the target file server.
You can also create the Secret using the following `kubectl` command:

```bash
kubectl create secret generic antrea-packetcapture-fileserver-auth -n kube-system --from-literal=username='<username>' --from-literal=password='<password>'
```

If no `fileServer` field is present in the CR, the captured packets file will be saved in the antrea-agent Pod (the one on the same node with source or destination pod in the CR).
The default file path will be `/tmp/antrea/packetcapture/packets/<PacketCapture_CR_Name>.pcapng`.

And here is an example of `PacketCapture` CR:

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: PacketCapture
metadata:
  name: pc-test
spec:
  fileServer:
    url: sftp://127.0.0.1:22/upload # Define your own sftp url here.
  timeout: 60
  captureConfig:
    firstN:
      number: 5
  source:
    pod:
      namespace: default
      name: frontend
  destination:
  # Available options for destination could be `pod` (a Pod), `ip` (an specific IP address), or `service` (a Service name). These 3 options are mutually exclusive.
    pod:
      namespace: default
      name: backend
  packet:
    ipFamily: IPv4
    protocol: TCP # Numerical format is also supported. eg. TCP (6), UDP (17), ICMP (1).
    transportHeader:
      tcp:
        dstPort: 8080 # Destination port needs to be set when the protocol is TCP/UDP.
```

The CR above starts a new packet capture of TCP flows from a Pod named `frontend`
to the port 8080 of a Pod named `backend` using TCP protocol. It will capture the first 5 packets
that meet this criterion and upload them to the specified sftp server. Users can download the
packet file from the sftp server (or from local antrea-agent Pod) and analyze its contents with network diagnose tools
like Wireshark or tcpdump.

Note: This feature is not supported on Windows for now.
