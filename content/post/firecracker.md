+++
title = "使用 Firecracker 搭建 Agent 沙箱"
date = 2026-10-28
[taxonomies]
tags = ["linux"]
+++

最近在使用 LLM 进行编程，但是对 LLM 的安全性存在一定的担忧，所以就使用 Firecracker 搭建了一个沙箱，并写文记录。

## 技术选型

- 虚拟化：选择 Firecracker 的原因还是因为他比 QEMU 和 libvirt 轻量，并且性能和稳定性都不错，安全问题也没那么多。
- 防止破坏性操作：通过直接复制虚拟机磁盘即可实现简单的回退操作，在 Agent 破坏系统后可以马上恢复。或者可以使用 firecracker 的 snapshot 功能进行快照。
- 系统安全问题：虚拟机的操作系统选择的是 Arch Linux 这种滚动发行版，滚动发行版有较新的软件，之前看文章分析类似于 Debian 这种发行版，可能会遗漏一些安全补丁导致漏洞被利用，选择新的软件能尽量避免漏洞。
- 网络监控：网络会通过 socks5 + tap 设备经过宿主机，可以在 socks5 代理软件处对网络流量进行监控和管理。

> 由于这只是一个简易的沙箱，所以可能仍然存在一部分安全问题，这些问题在后续有空了进行修复

## 环境搭建

### 系统配置

本次使用的虚拟机系统为 Arch Linux，从网上下载 rootfs，然后创建文件系统，解压 rootfs 到文件系统，使用 systemd-nspawn 进系统对 rootfs 进行一些配置，即可完成系统的配置。

```bash
ROOTFS=arch-rootfs.img
MOUNTPOINT=/tmp/arch-container
# 下载 rootfs
curl -O https://mirrors.ustc.edu.cn/archlinux/iso/latest/archlinux-bootstrap-x86_64.tar.zst
# 创建文件系统
truncate -s 4G $ROOTFS
mkfs.ext4 $ROOTFS
# 解压 rootfs 到文件系统
mkdir -p $MOUNTPOINT
sudo mount -o loop $ROOTFS $MOUNTPOINT
sudo tar -xf archlinux-bootstrap-x86_64.tar.zst --strip-components=1 --numeric-owner -C $MOUNTPOINT
# 进行一些配置
sudo systemd-nspawn -D $MOUNTPOINT
pacman-key --init
pacman-key --populate archlinux
passwd
```

接下来进行的是内核的配置，将内核的 bzImage 文件转换为 ELF 文件即可。需要注意的是内核需要内置一些模块，才能让 Firecracker 启动，否则的话得准备 initramfs。Arch Linux 的内核已经内置了需要的模块，所以我们直接用就可以了。需要的模块请参考 [Firecracker kernel-policy 文档](https://github.com/firecracker-microvm/firecracker/blob/main/docs/kernel-policy.md)。

```bash
curl -L -o linux.pkg.tar.zst https://archlinux.org/packages/core/x86_64/linux/download/
tar -xf linux*.pkg.tar.zst --wildcards 'usr/lib/modules/*/vmlinuz'
curl -O https://raw.githubusercontent.com/torvalds/linux/refs/heads/master/scripts/extract-vmlinux
chmod +x extract-vmlinux
./extract-vmlinux usr/lib/modules/*/vmlinuz > vmlinux
```

> Arch Linux 的 linux 包里集成了很多内核模块，将这个包解压到 rootfs 里，然后执行 "depmod -a && modprobe virtio_net" 加载 virtio_net 内核模块，可以解决没有网络的问题。

### Firecracker 配置

使用 httpx python 库即可和 Firecracker 的 API 进行交互，当然用 curl 也可以。需要设置机器配置，内核参数，rootfs, 网络才能让虚拟机启动。这部分请直接参考代码。

```python
def create_vm(tap: bool = False):
    client.put(
        "http://localhost/machine-config",
        json={"vcpu_count": config.VCPU, "mem_size_mib": config.MEM, "smt": False},
    )
    boot_source = {
        "kernel_image_path": config.KERNEL,
        "boot_args": "console=ttyS0 reboot=k panic=1",
    }
    if config.INITRD:
        boot_source["initrd_path"] = config.INITRD
    client.put("http://localhost/boot-source", json=boot_source)
    client.put(
        "http://localhost/drives/rootfs",
        json={
            "drive_id": "rootfs",
            "path_on_host": config.ROOTFS,
            "is_root_device": True,
            "is_read_only": False,
        },
    )
    if tap:
        client.put(
            "http://localhost/network-interfaces/eth0",
            json={
                "iface_id": "eth0",
                "host_dev_name": "tap0",
                "guest_mac": "AA:FC:00:00:00:01",
            },
        )


def start_vm():
    client.put("http://localhost/actions", json={"action_type": "InstanceStart"})
```

### 网络配置

网络配置永远是最麻烦的。最标准的做法就是按照官方文档进行配置 tap + nftables 来实现虚拟机上网。但是作为懒狗，我不太想去折腾宿主机的网络，经过一番搜索，我发现可以通过 tun2socks 来让虚拟机走宿主机的代理这种邪门的方式上网，这种方式的优点就是宿主机只要配置 tap + socks5 代理就可以了。虚拟机里执行的命令如下:

```bash
TUN_IP=198.18.0.1
HOST_IP=172.16.0.1
DEV_IP=172.16.0.2
PROXY=socks5://172.16.0.1:8000
# 如果没有配置虚拟机网卡的 IP, 就配置一下
ip addr add $DEV_IP/30 dev enp0s2
ip link set enp0s2 up
# 添加 tun 设备
modprobe tun
ip tuntap add mode tun dev tun0
ip addr add $TUN_IP/15 dev tun0
ip link set dev tun0 up
# 配置网络
ip route del default
ip route add default via $TUN_IP dev tun0 metric 1
ip route add default via $HOST_IP dev enp0s2 metric 10
# 启动 tun2socks
./tun2socks-linux-amd64-v3 --device tun0 --proxy $PROXY --interface enp0s2 &
```

在宿主机上可以使用 [xray](https://github.com/xtls/xray-core) 来进行代理，xray 中可以配置白名单和黑名单，来对流量进行监控和过滤。最后在宿主机上的防火墙中放行代理端口，即可实现虚拟机联网。下面是最精简的 xray 配置，拦截了对内网的访问，对下面配置参照 xray 的文档进行扩展即可实现白名单和黑名单：

```json
{
  "inbounds": [
    {
      "listen": "172.16.0.1",
      "port": 8000,
      "protocol": "socks",
      "settings": {
        "udp": true
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct-out",
      "protocol": "freedom"
    },
    {
      "tag": "block",
      "protocol": "blackhole"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "ip": ["geoip:private"],
        "outboundTag": "block"
      }
    ]
  }
}
```

## 其他

由于 Firecracker 的设计，得在虚拟机里执行 "reboot" 才能关闭虚拟机。

在启动系统后，可以对系统加载的模块进行精简，启用 hardened 内核来做到更安全，因为今年年初发现的越权漏洞都用到了冷门却带有漏洞的内核模块，所以在内核处加强防护是必要的。

## 启动

下载在文末提到的代码，配合上上面创建的 rootfs 和内核，执行下面的命令即可启动虚拟机。

```bash
$ firecracker --api-sock /tmp/firecracker.socket --enable-pci
# 修改 config.toml 配置
# 执行 ./tap.sh 创建 tap 设备
$ uv run fc.py
```

## 结算画面

```bash
[agent@archlinux ~]$ fastfetch
                  -`                     agent@archlinux
                 .o+`                    ---------------
                `ooo/                    OS: Arch Linux x86_64
               `+oooo:                   Kernel: Linux 7.2.8-arch1-2
              `+oooooo:                  Uptime: 10 mins
              -+oooooo+:                 Packages: 158 (pacman)
            `/:-:++oooo+:                Shell: bash 5.3.20
           `/++++/+++++++:               Terminal: /dev/pts/0 10.5p1
          `/++++++++++++++:              CPU: AMD EPYC (2) @ 3.90 GHz
         `/+++ooooooooooooo/`            Memory: 276.82 MiB / 952.44 MiB (29%)
        ./ooosssso++osssssso+`           Swap: Disabled
       .oossssso-````/ossssss+`          Disk (/): 1.23 GiB / 3.86 GiB (32%) - ext4
      -osssssso.      :ssssssso.         Local IP (tun0): 198.18.0.1/15
     :osssssss/        osssso+++.        Locale: C.UTF-8
    /ossssssss/        +ssssooo/-        
  `/ossssso+/:-        -:/+osssso+-                              
 `+sso+:-`                 `.-/+oso:                             
`++:.                           `-/+/
.`                                 `/
[agent@archlinux ~]$ pi -p '你是什么agent, 在什么系统上运行？'
我是 **pi** 编码助手（Pi Coding Agent），一个运行在终端里的 AI 编程代理。

当前环境信息：

| 项目 | 值 |
|---|---|
| Agent | pi（`PI_CODING_AGENT=true`） |
| 模型 | `deepseek-flash`（provider: deepseek） |
| 推理等级 | low |
| 系统 | Arch Linux（rolling），内核 7.2.8-arch1-2，x86_64 |
| 用户 / 工作目录 | `agent` / `/home/agent` |
| 会话 ID | `01a181e4-6d8e-7001-bc7d-6cdfcd8f1e35` |

我能读写文件、执行 shell 命令、编辑代码等，可以直接帮你完成开发任务。
[agent@archlinux ~]$ 
```

## 总结

我将 Firecracker 启动封装成了 Python 代码，这样通过修改配置就可以启动不同的系统。并且通过简单的方法实现了回退操作，流量监控等行为。

代码在这：<https://github.com/chenx6/gadget/tree/master/firecracker>。
