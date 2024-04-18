# PacketCapture User Guide

Starting with Antrea v2.0, Antrea supports using PacketCapture for network diagnosis.
It can capture specified number of packets from real traffic and upload them to a
supported storage location. Users can create a PacketCapture CRD to trigger
such actions on the target traffic flow.

<!-- toc -->
- [Prerequisites](#prerequisites)
- [Start a new PacketCapture](#start-a-new-packetcapture)
<!-- /toc -->

## Prerequisites

The PacketCapture feature is disabled by default. If you
want to enable this feature, you need to set PacketCapture feature gate to true in `antrea-config`
ConfigMap for antrea-agent.

```yaml
  antrea-agent.conf: |
    featureGates:
    # Enable packetcapture feature to capture real traffic packets.
      PacketCapture: true
```

## Start a new PacketCapture

When start a new packet capture, you can provide the following information to identify
the target flow:

* Source Pod
* Destination Pod, Service or IP address
* Transport protocol (TCP/UDP/ICMP)
* Transport ports

You can start a new packet capture by creating a PacketCapture CR via
`kubectl` and a yaml file which contains the essential configuration of
PacketCapture CRD. Following is an example of PacketCapture CR:

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: PacketCapture
metadata:
  name: ps-test
spec:
  fileServer:
    url: sftp://127.0.0.1:22/upload # define your own ftp url here.
  authentication:
    authType: "BasicAuthentication"
    authSecret:
      name: test-secret
      namespace: default
  timeout: 600
  type: FirstNCapture
  firstNCaptureConfig:
    number: 5
  source:
    namespace: default
    pod: frontend
  destination:
    namespace: default
    pod: backend
    # Destination can also be an IP address ('ip' field) or a Service name ('service' field); the 3 choices are mutually exclusive.
  packet:
    ipHeader: # If ipHeader/ipv6Header is not set, the default value is IPv4 + ICMP.
      protocol: 6 # Protocol here can be 6 (TCP), 17 (UDP) or 1 (ICMP), default value is 1 (ICMP)
    transportHeader:
      tcp:
        dstPort: 8080 # Destination port needs to be set when the protocol is TCP/UDP.
```

The CRD above starts a new packet capture from a Pod named `frontend`
to the port 8080 of a Pod named `backend` using TCP protocol. It will capture the first 5 packets
that meet this criterion and upload them to the file server specified in the PacketCapture's
specifications. Users can download the packet file from the ftp server and analysis its content
with common network diagnose tools like Wireshark or `tcpdump`.
