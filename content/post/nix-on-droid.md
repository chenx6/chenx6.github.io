+++
title = "低成本体验 Nix 之 nix-on-droid"
date = 2024-03-23
[taxonomies]
tags = ["linux", "nix"]
+++

对 Linux 感兴趣的用户应该会接触过很多奇怪的 Linux 发行版，例如使用声明式配置文件配置系统的 NixOS，通过一套配置文件就可以搭建起来一个系统。但是 NixOS 的安装和学习曲线都算比较陡峭的，在互联网冲浪的时候，发现有个 [nix-on-droid](https://github.com/nix-community/nix-on-droid) 项目，可以在安卓系统上搭建起一个迷你版本的 Nix 环境，所以就下载体验了一波，并写文记录使用。

## 安装

通过 F-Droid 就可以下载项目的 APK 安装包，安装 APK 之后会进行初始化，该项目会自动从网上下载一个初始化的镜像并进行初始化，在下载和安装完之后就会进入系统了。

## Nix 语言简易教程

NixOS 有一个用于声明式配置的模块系统，这个系统会将多个模块组合起来，用来生成完整的系统配置。用于定义配置的语言则是 Nix 语言。可以通过 `nix repl` 命令进入交互式 shell 进行 Nix 语言的学习。

### 类型

Nix 语言使用的是动态类型系统。在 Nix 语言中，有几种基本类型，包括字符串，布尔类型，空指针，整数，浮点数，集合，列表，和其他函数式语言差不多。

```nix
"string"
''
multiple line
string
''
true
false
null
12345
1.2345
[ 1 2 3 ]
```

这里个人认为比较重要的是集合，集合是由一堆的 `name = value` 定义组成的。

```nix
{
  name = value;
}
```

### 函数

函数的形式为 `pattern: body`。`pattern` 决定了函数接收的参数，并且有 3 种形式。

- 如果 `pattern` 只有 1 个标志符，这个函数就可以接收任意参数。例如 `arg1: !arg1`，函数接收了 1 个名叫 `arg1` 的参数，并在函数体对其做了取反的操作。
- 如果 `pattern` 是一个类似于 `{ name1, name2, ... }` 这样的集合形式，这个函数会接收一个集合，集合中包含着 `pattern` 中定义的属性，并将值绑定到变量上供函数体使用。例如 `{ arg1, arg2 }: arg2 + arg1` 代表着这个函数接收含有 `arg1` 和 `arg2` 定义的集合作为参数。函数语句申明中可以出现类似 `?`，代表着默认参数。例如 `{ x ? "foo" }: x`。函数还可以使用 `{arg1, arg2, ...}` 接收有多于定义的集合。
- `pattern` 中还可以使用 `@` 符将集合里的值进行关联。例如 `{ pkgs, ... } @ attrs`，后面的 `@attrs` 意味着将集合中的定义打包关联起来，在函数体中可以通过类似 `attrs.pkgs` 语句来使用 `pkgs` 参数。

下面是 nix-on-droid 项目演示用的配置。`{ pkgs, ... }:` 是 nix 函数的参数申明，代表着函数需要一个带有 `pkgs` 定义的集合。`pkgs` 这个定义一般指向的是 nixpkgs。这个函数返回了一组定义，在下面的代码中，则是定义了 `environment.packages` 和 `system.stateVersion`。

```nix
{ pkgs, ... }:

{
  environment.packages = [ pkgs.vim ];
  system.stateVersion = "23.11";
}
```

### if else

条件判断语句和其他的函数式语言类似。例如 `if e1 then e2 else e3` 代表着如果 `e1` 条件满足了就返回 `e2`，否则返回 `e3`。

### let

let 语句则是可以声明局部变量，供后续使用。例如 `let x = "foo"; y = "bar"; in x + y` 声明了 `x`, `y` 变量，在 `in` 语句中就可以使用这两个变量。

### with

`with` 语句可以将集合里的函数和定义放到当前的语句中，类似于简写了内容。例如 `with builtins; head [ 1 2 3 ]`。`with builtins;` 语句将 `builtins` 集合里的内容引进到了后面的 `head [ 1 2 3 ]` 语句中。等同于 `builtins.head [ 1 2 3 ]`。

### import

有时候单个配置文件里存放了太多的定义，不好进行管理，这时候可以配置存放在不同的文件里，通过 `imports = [ ... ];` 语句进行导入。在 NixOS 的文档里演示了使用多个文件生成配置，将 KDE 的配置单独放到一个文件里。

```nix
{ config, pkgs, ... }:

{
  imports = [ ./kde.nix ];
  ...
}
```

### 其他

上面是一些常见的概念，NixOS 还可以做到修改包的默认配置，添加自定义的包等功能，这些功能请查询 [Refs](#refs) 中提到的官方文档。

## 实战

### 使用 nix-shell 来创建开发环境

我平时用 Python 来写一些脚本时，需要一个开发环境。这时候就可以通过 nix-shell 命令和相关配置来配置所需要的软件和包。

在下面的例子中，我通过调用 `python3.withPackages` 可以将 Python 解释器和对应的包打包在一起。通过调用 `pkgs.mkShell` 函数，可以安装上前面打包的 Python 环境和系统软件("black", "mypy")。

```nix
{ pkgs ? import <nixpkgs> {} }:
with pkgs;
let
  pythonEnv = python3.withPackages (ps: [
    ps.ipython
    ps.numpy
    ps.requests
    ps.beautifulsoup4
    ps.python-lsp-server
    ps.z3
  ]);
in mkShell {
  packages = [
    pythonEnv
    black
    mypy
  ];
}
```

将上面的内容保存到 "shell.nix" 文件后，即可通过 "nix-shell" 命令即可搭建一个全新的开发环境。

### 使用 Nix 构建和打包

下面的代码是打包 gnu hello 程序的代码，可以看到是通过调用 `stdenv.mkDerivation` 函数描述程序的构建流程，在传递给函数的集合中，调用了 `fetchzip` 函数下载代码。

```nix
{
  lib,
  stdenv,
  fetchzip,
}:

stdenv.mkDerivation {
  pname = "hello";
  version = "2.12.1";

  src = fetchzip {
    url = "https://ftp.gnu.org/gnu/hello/hello-2.12.1.tar.gz";
    sha256 = "0xw6cr5jgi1ir13q6apvrivwmmpr5j8vbymp0x6ll0kcv6366hnn";
  };
}
```

如果想要打包更复杂的软件，可以参考 [NixOS/nixpkgs](https://github.com/NixOS/nixpkgs/) repo 里的文件，还有 [nix.dev 里的打包教程](https://nix.dev/tutorials/packaging-existing-software)。

TODO: 补充几个现实中的例子。

### home-manager

home-manager 可以用来管理用户态的程序和配置。配置选项请参考 home-manager 的文档，可定义的内容很多。下面放一个我自己的 home-manager 配置，主要是安装了常用的软件，配置了 zsh, helix editor, ssh, git。

```nix
{ pkgs, ... }:
{
  home.packages = with pkgs; [
    xplr
    ripgrep
    fd
    nmap
    htop
    just
  ];
  programs.zsh = {
    enable = true;
    syntaxHighlighting.enable = true;
    sessionVariables = {
      PS1 = "%(?..%F{red}%? %f)%~ %F{cyan}>%f ";
    };
    shellAliases = {
      ll = "ls -la";
      ".j" = "just";
    };
    enableAutosuggestions = true;
    # autosuggestion.enable = true;
  };
  programs.helix = {
    enable = true;
    settings = {
      theme = "base16_terminal";
      keys.normal = {
        "^" = "goto_line_start";
        "$" = "goto_line_end";
      };
    };
  };
  programs.ssh = {
    enable = true;
    package = pkgs.openssh;
    matchBlocks = {
      lpi4 = {
        hostname = "1.1.1.1";
        user = "user";
      };
    };
  };
  programs.git = {
    enable = true;
    userName = "user";
    userEmail = "user@example.com";
  };
  home.stateVersion = "23.11";
}
```

## 其他

关于 NixOS 的相关包和配置可以到 <https://search.nixos.org/> 进行搜索。进阶的教程可以看 [Nix Pills](https://nixos.org/guides/nix-pills/) 和 [Welcome to nix.dev](https://nix.dev/) 还有 [NixOS Wiki](https://nixos.wiki/)。

## Refs

- [Nix Language](https://nixos.org/manual/nix/stable/language/index.html)
- [NixOS Manual](https://nixos.org/manual/nixos/stable/)
- [Development environment with nix-shell](https://nixos.wiki/wiki/Development_environment_with_nix-shell)
