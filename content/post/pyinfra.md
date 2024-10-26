+++
title = "成为运维带师 - 用 pyinfra 进行自动化运维"
date = 2024-10-26
[taxonomies]
tags = ["linux", "python"]
+++

每次购买新服务器都要手动配置一堆的基础服务，而且配置过程太无聊了。经过研究和试验之后发现：通过 shell 脚本去执行配置就要被 shell script 的很多坑爹细节坑到，而且 shell script 本身功能有有限，还是需要借助一些外部软件来实现更多功能；ansible 配置太复杂，而且我个人不喜欢 yaml 格式，觉得这格式过于奇葩；Nix 学习成本高，而且比较占磁盘空间。

有一天，我在 Hacker News 上刷到了 [pyinfra](https://pyinfra.com/) 这个软件，可以通过 Python 代码进行声明式的配置系统。不觉得很酷吗？作为一个懒狗，我觉得这太酷了，很符合我对自动化运维的想象。

## 基本概念

安装 pyinfra 很简单，使用 `pipx install pyinfra` 就完成安装了。

通过 pyinfra 进行批量运维也很简单，执行 `pyinfra $inventory $operations` 就可以批量运维系统了。这里主要涉及到了两个概念，inventory 和 operations。inventory 指的是要执行操作的主机，还有操作这些主机需要的数据，主机也可以是本地机器，通过 "@local" 这个名字来指定，或者 Docker 容器。名字以 "@docker/" 开头。operations 指的是需要执行的操作和状态，例如确保一个软件在主机上是否安装，pyinfra 会检查操作的状态，如果已经达到了状态的话 pyinfa 就不会再操作了，减少重复执行。

### inventory

inventory 定义很简单，新建一个 .py 文件，然后在代码里新建一个 list，list 变量的名字就是一个 group，list 里的内容就是 group 里的主机。group 可以配合 "--limit" 参数限制 operations 执行的主机范围。

```python
servers = ["@ssh/example.com"]
```

还可以往 inventory 里加入主机的相关数据来连接主机，例如下面的 inventory 让 pyinfra 在操作时候通过用户 "user" 和密码 "password" 连接主机。

```python
servers = [
    (
        "@ssh/example.com",
        {
            "ssh_user": "user",
            "ssh_password": "password"
        },
    ),
]
```

### operations

pyinfra 已经实现了很多的操作，可以查看官方文档来查看。需要注意的是文档的内容不一定及时更新，需要以实际的代码为准。下面的代码定义了一个操作，在主机上执行 echo 命令。

```python
from pyinfra.operations import server

server.shell(
    name="Hello pyinfra",
    commands=['echo "hello from $HOST $USER"'],
)
```

将上面文件保存到 "deploy/hello.py" 后，通过 `pyinfra @local deploy/hello.py` 执行后输出如下。可以看到命令被成功执行。

```bash
$ pyinfra @local deploy/hello.py           
--> Loading config...
--> Loading inventory...
--> Connecting to hosts...
    [@local] Connected

--> Preparing operations...
--> Preparing Operations...
    Loading: deploy/hello.py
    [@local] Ready: deploy/hello.py

--> Detected changes:
    Operation       Change       Conditional Change   
    Hello pyinfra   1 (@local)   -                    

    Detected changes may not include every change pyinfra will execute.
    Hidden side effects of operations may alter behaviour of future operations,
    this will be shown in the results. The remote state will always be updated
    to reflect the state defined by the input operations.

    Detected changes displayed above, skip this step with -y
                             
--> Beginning operation run...
--> Starting operation: Hello pyinfra 
    [@local] Success

--> Results:
    Operation       Hosts   Success   Error   No Change   
    Hello pyinfra   1       1         -       -           

--> Disconnecting from hosts...
```

配合上面 inventory 的内容，将上面 inventory 的内容保存在 inventory.py 文件中，即可通过 `pyinfra inventory.py deploy/hello.py` 在别的主机上执行 operations 操作了。

## 实战

### 更换 apt source

下面的代码表示了更换 apt source 的操作：通过全局设置设置当前文件下的 operation 都使用 sudo 命令操作，并设置 sudo 命令使用的密码，通过 `files.replace` operation 替换默认的 apt source 为 USTC 镜像站。

```python
from pyinfra.operations import files
from pyinfra.context import config, host

config.SUDO = True
config.SUDO_PASSWORD = host.data.get("ssh_password")

files.replace(
    path="/etc/apt/sources.list",
    text="deb.debian.org",
    replace="mirrors.ustc.edu.cn",
)
```

### 部署 aria2 服务

下面的代码表示了部署 aria2 服务的操作：部署 aria2 需要创建一份 aria2 的配置，然后创建一个单独的用户，最后配置 systemd 让 aria2 在前面创建的用户上运行。在这份 operations 里用到了 `files.template` 操作，可以使用 jinja2 模板从 inventory 里的 data 中生成 aria2 配置。在我之前的文章中应该用文字描述过如何配置 aria2 服务，现在用代码表示，可以更清晰的描述了执行的操作。

```python
from pyinfra.operations import apt, files, systemd, server
from pyinfra.context import config, host

config.SUDO = True
config.SUDO_PASSWORD = host.data.get("ssh_password")

aria2_config = host.data.get("aria2_config")

apt.packages(
    name="Install aria2 program",
    packages=["aria2"],
    update=True,
)
files.template(
    name="Add config",
    src="config/aria2/aria2.conf.j2",
    dest="/etc/aria2/aria2.conf",
    config=aria2_config,
)
server.group(
    name="Create group",
    group="aria2",
)
server.user(
    name="Create user",
    user="aria2",
    group="aria2",
)
files.directory(
    name="Create download dir",
    path=aria2_config["download_dir"],  # type: ignore
)
files.file(
    name="Create aria2 session",
    path=aria2_config["download_dir"] + "/aria2.session",  # type: ignore
    user="aria2",
    group="aria2",
    touch=True,
)
files.put(
    name="Add systemd config",
    src="config/aria2/aria2.service",
    dest="/etc/systemd/system/aria2.service",
)
systemd.daemon_reload()
systemd.service(
    name="Start service",
    service="aria2.service",
    running=True,
    enabled=True,
)
```

相应的 inventory.py 文件如下，和之前的 inventory 相比，加入了部署 aria2 所需的一些数据。

```python
servers = [
    (
        "@ssh/example.com",
        {
            "ssh_user": "user",
            "ssh_password": "password",
            "aria2_config": {"download_dir": "/home/aria2/Downloads"},
        },
    ),
]
```

## 总结

对比 Nix, shell script, ansible，我觉得 pyinfra 在他们之间找到了一个平衡点，学习成本相对较低，代码相对明确，可以借助 Python 生态去实现高级功能。未来还会继续研究和使用这套工具。

## Refs

[pyinfra Documentation](https://docs.pyinfra.com/en/3.x/)
