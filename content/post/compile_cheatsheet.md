+++
title = "关于 C 语言编译的那些破事"
date = 2022-05-21
description = "C 和 C++ 的编译是真的痛苦，会出现一堆离谱的问题。所以我特地写一篇文章讲一下这些破事，并且提供一些样例代码方便复制黏贴。"
[taxonomies]
tags = ["cpp", "c", "compile"]
+++

C 和 C++ 的编译是真的痛苦，会出现一堆离谱的问题。所以我特地写一篇文章讲一下这些破事，并且提供一些样例代码方便复制黏贴。

## 编译过程简述

在网上能找到一堆的编译流程相关的博客，而且肯定比我讲的正确，所以这里我就简单概括下。

现在很少有程序能只依赖与 C 标准库和系统 API 了，所以会有一堆的外部依赖库。要想编译成功，得让编译器和链接器都知道去哪找这些库，怎么链接上。于是就有了一堆的编译管理工具。像 CMake 和 Meson 是负责生成编译的脚本，make 和 ninja 则是负责执行编译任务，然后是 gcc 和 clang 将代码编译成目标文件，最后有 ld, gold, mold 将目标文件进行链接生成可执行文件。

```txt
CMake -> make  -> gcc   -> ld   -> 可执行文件
Meson    ninja    clang    gold
Bazel    ...      zig cc   lld
...               ...      mold
                           ...
```

## 编译系统

### Meson

样例代码

```meson
# 指定项目名称，使用语言，默认选项
project('project name', 'cpp'
        default_options : ['c_std=c11', 'cpp_std=c++11'])
# 指定头文件位置
incdir = include_directories('include')
#（可选）使用 math 库
cc = meson.get_compiler('c')
m_dep = cc.find_library('m')
#（可选）使用 `dependency` 寻找库依赖
zdep = dependency('zlib', version: '>=1.2.8')
#（可选）子目录
subdir('tests')
# 指定代码文件位置，头文件位置来生成可执行文件
utils = ['src/logger.cpp', 'src/utils.cpp']
# 可执行文件的相关设置
executable('client', 'src/main_client.cpp', 'src/client.cpp', utils, 
           include_directories : incdir,
           dependencies : m_dep
           cpp_args: [],
           c_args: [],
           link_args : '')
# 在 executable 函数中添加下面的设置可以编译 32 位，静态链接的程序
#    cpp_args: ['-m32', '-static'],
#    c_args: ['-m32', '-static'],
#    link_args : '-m32'
```

常用编译命令

```bash
# 生成编译所需文件
meson setup builddir --wipe
# Debug 编译
meson setup --buildtype debug --reconfigure
# 编译
meson compile -C builddir
```

更多的内容参考 [#refs](#refs)

### CMake

样例代码

```cmake
# 指定项目名字，CMake 版本要求，C++ 版本要求
project(project_name)
cmake_minimum_required(VERSION 3.0)
set(CXX_STANDARD 11)

# 使用 CMake 管理的库
find_package(OpenCV REQUIRED)
include_directories(${OpenCV_INCLUDE_DIRS})
link_directories(${OpenCV_LIBRARY_DIRS})

# 使用由 pkg-config 管理的库
find_package(PkgConfig)
pkg_search_module(LIBNOTIFY REQUIRED libnotify)
include_directories(${LIBNOTIFY_INCLUDE_DIRS})

# 指定头文件目录
include_directories(./include)
# 扫描目录，获得目录下源代码位置
aux_source_directory(./src SRC)
add_executable(name ${SRC})
# 链接上库
target_link_libraries(${PROJECT_NAME} ${OpenCV_LIBS} ${LIBNOTIFY_LIBRARIES})
```

常用命令

```bash
# 编译
cd build && cmake ..
# Debug 编译
cmake -DCMAKE_BUILD_TYPE=Debug ..
```

### Makefile

Makefile 的可读性真的是灾难级别的，下面这篇文章图文并茂，讲的很好，推荐阅读！！！

[Makefile由浅入深--教程、干货](https://zhuanlan.zhihu.com/p/47390641)

## 库管理工具

### pkg-config

|选项|作用|样例|
| - | - | - |
|`--cflags`|查询这个库的所需要的 CFLAGS|`pkg-config --cflags glib-2.0`|
|`--libs`|查询链接上这个库的所需要的选项|`pkg-config --libs zlib`|
|`–-list-all`|列出所有的，可以被查找到的库|`pkg-config –-list-all \| rg $库`|

设置 pkg-config 搜索路径

```bash
export PKG_CONFIG_PATH=/usr/lib/pkgconfig/:$PKG_CONFIG_PATH
```

官方文档参考 [#refs](#refs)

## 编译器

### GCC编译选项

#### 链接

|选项|作用|样例|
| - | - | - |
|`-l$library`|链接上某个库|`-lm`|
|`-static`|静态链接库||
|`-static-libstdc++`|静态链接libstdc++||
|`-Wl,$option`|将链接选项传递给 ld||

#### 目录搜索

|选项|作用|样例|
| - | - | - |
|`-I $dir`|（大写的i）头文件搜索路径|`-I ./include`|
|`-L$dir`|库文件搜索路径|`-L./lib`|
|`--sysroot=$dir`|头文件和库的搜索路径|`--sysroot=/usr`|

### 使用 zig cc 进行跨平台编译

zig cc 真是跨平台编译救星，下面演示下常见命令。

```bash
# 显示支持的 libc
zig targets | jq .libc
# 直接编译
zig cc $文件 -target $目标
zig cc hello.c -target i386-linux-musl -static
# 让 make 等工具使用
make CC="zig cc" CXX="zig c++"
```

参考文章 [#refs](#refs)

## 环境配置

### Docker/Podman

Ubuntu image，添加 32 位支持，安装编译工具链，库和 CMake

```dockerfile
FROM ubuntu:18.04

RUN dpkg --add-architecture i386 && \
    apt update && \
    apt install -y gcc-multilib g++-multilib build-essential cmake
```

CentOS image，从本地复制一份 ninja，安装编译工具，相关的库和 Meson

```dockerfile
FROM amd64/centos:7

COPY ./ninja /usr/local/bin

RUN yum install python3 glibc-devel.i686 glibc-devel.x86_64 libgcc.i686 libgcc.x86_64 libstdc++-devel.i686 libstdc++-devel -y && \
    yum group install "Development Tools" -y

RUN python3 -m pip install meson -i https://opentuna.cn/pypi/web/simple
```

使用容器进行编译。设置成运行完后删除，并将当前目录映射到 "/src" 目录下，启动名字为 `$容器名字` 的容器。

```bash
podman run --rm -v "$(pwd):/src" -it $容器名字
```

### Glibc symver

有时候在新系统上编译的可执行文件，在旧系统上运行时，会产生 "找不到函数" 错误。这时候可以通过指定 symver 来进行兼容旧版本。具体细节可以参考 [#Refs](#Refs) 中的 "All about symbol versioning"，或者使用 "wheybags/glibc_version_header" 这个项目。

```c
__asm__(".symver fopen,fopen@GLIBC_2.2.5");
```

## Refs

- <https://gcc.gnu.org/onlinedocs/gcc-11.3.0/gcc/>
- <https://www.freedesktop.org/wiki/Software/pkg-config>
- <https://mesonbuild.com/howtox.html>
- <https://mesonbuild.com/Meson-sample.html>
- <https://andrewkelley.me/post/zig-cc-powerful-drop-in-replacement-gcc-clang.html>
- [All about symbol versioning](https://zhuanlan.zhihu.com/p/314912277)
- <https://github.com/wheybags/glibc_version_header>
