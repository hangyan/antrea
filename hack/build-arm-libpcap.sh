#!/usr/bin/env bash

# Copyright 2020 Antrea Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

PCAPV=1.10.5
echo "Building lipcap with ARCH=${ARCH}"
pushd .
apt-get update && apt-get install -y flex bison gcc-aarch64-linux-gnu gcc-arm-linux-gnueabi
mkdir -p /tmp/pcap
cd /tmp/pcap || exit

wget -c http://www.tcpdump.org/release/libpcap-${PCAPV}.tar.gz
export CC=aarch64-linux-gnu-gcc
if [ $(ARCH) == "arm" ]; then
  export CC=arm-linux-gnueabihf-gcc
fi
rm -rf libpcap*
tar -zxvf libpcap-${PCAPV}.tar.gz
mv libpcap-${PCAPV} libpcap || exit
./configure --host=aarch64-linux --with-pcap=linux
make
popd || exit
