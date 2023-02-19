+++
title = "QEMU 简易配置（CPU/内存/网络/...）"
date = 2023-02-19
[taxonomies]
tags = ["linux", "qemu"]
+++

从大学开始，我看过了一堆的 QEMU 配置的文章，这些文章要不就是从别的地方复制黏贴出来的，要不就是使用了已经停止维护的工具。所以我决定从网上找一手资料（QEMU Wiki，文档, man qemu，...）来写一篇文章来讲讲怎么简单的配置 QEMU 模拟虚拟机。在文章的最后放了最终运行的命令，大家复制了保存成脚本就可以使用，或者根据自己的要求来配置。（这个脚本已经经过 2 个人使用了，很好用 233）

## CPU 配置

下面的选项开启 KVM 全虚拟化支持，能提升虚拟机的速度。

```bash
--enable-kvm
```

下面的 CPU 设置选项，是让模拟出来的 CPU 支持主机支持的所有选项。

```bash
-cpu host
```

下面的选项是指定 SMP（可以简单理解为模拟 CPU 的核数）

```bash
-smp 4
```

## 内存

下面的选项是指定内存大小。这里我分配了 4G 内存给虚拟机。

```bash
-m 4096M
```

## 网络

QEMU 将网络支持分成了 2 个部分，一部分是给虚拟机（guest）提供的虚拟网络设备（virtual network device），一部分是与模拟 NIC 交互的网络后端（network backend）。QEMU 在默认配置下提供了 SLiRP 后端，在使用这个后端的情况下， ICMP 协议没法工作，也就是没法 ping,但是 TCP 和 UDP 是可以正常工作的。

在网络后端这一层，我们选择 [tap](https://docs.kernel.org/networking/tuntap.html)。因为 tap 是在 Linux 内核层面支持的，性能比较好，而且可以支持 ICMP/IP 层协议。需要注意的是 ifname 的参数 "tap6" 是我们创建 tap 设备名字。下面是相关参数。

```bash
-netdev tap,id=net0,ifname=tap6,script=no,downscript=no
```

QEMU 可以模拟很多的虚拟网络设备，这里我们选择模拟 e1000 网卡。需要注意的是 netdev 的参数需要和前面配置的 netdev 中的 id 对上，这里我们的 netdev 参数为 "net0"。在 mac 参数中，将 MAC 配置成 "52:55:00:d1:55:00"。下面是相关参数。

```bash
-device e1000,netdev=net0,mac=52:55:00:d1:55:00
```

### 如何创建 tap 设备

上面的参数需要手动创建 tap 设备才能使用。通过下面的命令既可以创建设备名叫 "tap6" 的设备，并且将 IP 设置在 "192.168.122.1"。下面命令的主要操作就是创建 tap 设备，设置 IP，并且启用设备。

```bash
IP=192.168.122.1/24
ip tuntap add tap6 mode tap
ip addr add $IP dev tap6
ip link set tap6 up
```

如果需要让虚拟机和外网相连接的话，还需要下面的命令，来创建网桥，使得虚拟机 tap 设备和宿主机网卡相连。

```bash
ip link add br0 type bridge
ip link set dev tap6 master br0
ip link set dev eth0 master br0
ip link set dev br0 up
```

### 使用 dnsmasq 配置 DHCP

如果需要让虚拟机走 DHCP 协议获取 IP 的话，最简单的方式就是在宿主机上使用 dnsmasq 来给虚拟机分配 IP。下面是 dnsmasq 的配置，配合上面的 IP 配置，可以让宿主机的 IP 设置为 192.168.122.1，虚拟机的 IP 在 192.168.122.2,192.168.122.200 这个范围内。

```plaintext
listen-address=192.168.122.1
dhcp-range=192.168.122.2,192.168.122.200
```

### 别的选项

下面的选项开启 GDB 远程调试。在 GDB 里使用 `target remote :5555` 即可连接。

```bash
-gdb tcp::5555
```

## 最后成果

network.sh 脚本，需要 root 权限运行，并且需要配置 dnsmasq 启用 DHCP 服务。

```bash
#!/usr/bin/env bash
set -x

IP=192.168.122.1/24
ip tuntap add tap6 mode tap
ip addr add $IP dev tap6
ip link set tap6 up  # Check again when VM boot finish
dnsmasq
```

boot.sh 脚本，通过 `boot.sh $虚拟机镜像名字` 来运行虚拟机。

```bash
#!/usr/bin/env bash
set -x

qemu-system-x86_64 \
  --enable-kvm \
  -m 4096M \
  -cpu host \
  -smp 4 \
  -netdev tap,id=net0,ifname=tap6,script=no,downscript=no \
  -device e1000,netdev=net0,mac=52:55:00:d1:55:00 \
  $1
```

## Refs

- `man qemu`
- <https://wiki.qemu.org/Documentation/Networking>
