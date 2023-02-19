+++
title = "斐讯 N1 折腾/避坑笔记"
date = 2020-02-01
description = "最近想搞一台小服务器来做 Git 服务器，下载 Bt 等事情，所以就在一堆便宜的 ARM 机顶盒/NAS 中间挑选。最后看上了 100 RMB 左右的斐讯 N1，因为 N1 不用拆机就可以刷机。"
[taxonomies]
tags = ["arm", "server"]
+++

最近想搞一台小服务器来做 Git 服务器，下载 Bt 等事情，所以就在一堆便宜的 ARM 机顶盒/NAS 中间挑选。最后看上了 100 RMB 左右的斐讯 N1，因为 N1 不用拆机就可以刷机。

## 准备工作

- 空 U 盘
- HDMI 线
- 一台斐讯 N1
- 键盘，鼠标

> 可以试试没有 HDMI 线和键鼠进行安装，好像进入 U 盘中的镜像时会自动开启 sshd 服务。

## 安装系统

基本分为三个步骤：

1. 将 N1 降级
2. 插入带有镜像的 U 盘，然后使用 `adb shell reboot update` 进入 U 盘镜像中的系统
3. 使用镜像中的脚本完成安装。

这部分可以看其他人的图文教程（忘了截图了...）例如 <https://www.cnblogs.com/HintLee/p/9866485.html> 和 <https://www.aptx.xin/phicomm-n1.html>

### N1 降级

将 N1 的 USB 调试打开，然后用 webpad 的降级工具降级，工具运行完成后重启盒子的系统，虽然看起来版本号没有变，但是底层的版本号确实降级了。

### 镜像安装

首先是去找镜像。恩山上的帖子感觉有点复古，所以我就去外网找到了这个帖子：<https://forum.armbian.com/topic/7930-armbian-for-amlogic-s9xxx-kernel-5x/>，但是这里面提供的镜像竟然是 rc 版本的，于是就又去 <https://forum.armbian.com/topic/12162-single-armbian-image-for-rk-aml-aw/> 找到了三种芯片合一镜像。虽然镜像解压出来有 5G 大小，但是这个 build 比较新，是 2 月 20 日左右编译的。我选择了 "Armbian_20.05.0-trunk_Arm-64_buster_current_5.5.1_20200227.img" 这个不带桌面的 Debian buster 系统的镜像。网盘地址：<https://yadi.sk/d/_rQgn_FosYuW0g>

其次是刻录 U 盘，这里推荐 rufus，绿色版文件不到 10 MB。操作也非常简单。

![0](/images/Annotation_2020-03-02_161540.png)

刻录完成后打开 "BOOT" 分区，修改 "uEnv.txt"。将 "# aml s9xxx" 下面几行行去除注释，将下一行改成 N1 的 dtb 文件路径。

最后是惊险刺激的安装环节。在 adb 连接上盒子后，执行 `adb shell reboot update` ，然后迅速插入 U 盘，可以看到 U 盘中的 Debian 开始启动。

> 这里有个坑点，如果是 USB 3.0 的 U 盘的话可能无法进入 U 盘中的系统，而是进入了 Recovery。导致前面情况的原因可能是盒子的供电不足，需要使用盒子上的另一个 USB 口对盒子进行供电。将 USB Type A 的双头线将电脑和盒子进行连接即可解决问题。

![1](/images/Annotation_2020-03-02_161912.png)

先输入用户名 "root" 和默认密码 "1234" 登录系统后进行修改 root 用户的密码，新建普通用户。最后执行 "./install-aml.sh" 进行安装。

## 系统配置

安装完成后重启，拔出 U 盘，即可使用之前创建的用户登录系统。

### 连接 WIFI

然后执行 `sudo nmtui`，使用 "nmtui" 进行配置网络。在 TUI 中使用键盘的方向键控制选项，使用回车进行确定，使用 Esc 进行返回。

选择 "Activate a connection" 就可以在 TUI 中连接 WIFI 了。选择网络，输入密码，连接网络一气呵成。

### 配置 apt 源

还得配置下 apt 源。我用的 `sudo sed "s/\/\/.*debian.org/\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list -i` 进行修改 apt 源。先去掉命令最后的 -i 选项，看看文件是否正确修改，然后加上 -i 选项进行修改。

### 启动 sshd

最后看一下 sshd 是否启动：`sudo systemctl status sshd`

如果没启动，那就 `sudo systemctl start sshd` 进行启动，然后在用电脑的 ssh 连接上盒子。当然，用 JuiceSSH 或者 Termux 连接也行。

![](/images/Annotation_2020-03-02_152424.png)

## 配置相应的软件（未完）

### aria2：HTTP/Bt 下载

先安装上 aria2 `sudo apt update && sudo apt install aria2`

然后在相应目录配置好 `$HOME/.aria2/aria2.conf` 还有 systemd 的 unit。我将通过 systemd 来实现开机启动 aria2。

![7](/images/Annotation_2020-03-02_151859.png)

由于在 aria2 的配置文件中设置了 `save-session`，所以得将 `save-session` 后面所指定的文件 `touch` 创建出来，要不然会报错。

> systemd 对于非 Linux 用户不太友好，但是对 Linux 用户来说还是方便啊。

最后使用 `systemd --user enable aria2.service && systemd --user start aria2.service` 启动 aria2。

![6](/images/Annotation_2020-03-02_151817.png)

这个 service 会随着用户的退出而退出，所以要将当前用户设置为驻留用户：`loginctl enable-linger $USER`，这样就能实现开机启动，用户登出时不退出服务了。
