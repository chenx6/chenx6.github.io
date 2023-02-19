+++
title = "CodeQL 体验"
date = 2020-04-20
description = "之前在 Twitter 上看到有大佬说 Github Learning Club 上搞了个免费的 CodeQL 课程，课程最终目标是使用 CodeQL 这个语言找出 uboot 中的 9 个漏洞。我在克服拖延症后，终于在 4 月底完成了这个课程，于是写文记录。"
[taxonomies]
tags = ["re", "codeql"]
+++

## 概要

之前在 Twitter 上看到有大佬说 Github Learning Club 上搞了个免费的 CodeQL 课程，课程最终目标是使用 CodeQL 这个语言找出 uboot 中的 9 个漏洞。我在克服拖延症后，终于在 4 月底完成了这个课程，于是写文记录。

[课程链接](https://lab.github.com/githubtraining/codeql-u-boot-challenge-(cc++))

[通过 CodeQL 找出来的漏洞分析](https://securitylab.github.com/research/uboot-rce-nfs-vulnerability)

## 提前准备

1. VSCode  // VSC 天下第一
2. 本机上的 Git 和 Github 帐号  // 废话
3. 在线翻译  // 文档和课程的英文文本量有点大
4. C/C++ 基础  // 不会 C 语言怎么挖洞啊

## 环境搭建

首先先在课程链接中选择 "Start free course"，然后 Github 机器人会在你的帐号下新建项目。先将这个项目 Clone 到本地。Github 机器人会通过 Issue 和 Pull request 和你进行沟通。

官方推荐使用 VSCode，那我们就使用 VSC。当然，其他 IDE 应该也是可以的。

然后安装[CodeQL 插件](https://marketplace.visualstudio.com/items?itemName=github.vscode-codeql)。

CodeQL 插件会自动从 Github 上下载大约 400M 的 codeql-cli，如果下载速度慢请使用加速器。

接下来[Clone 这个项目](https://github.com/github/vscode-codeql-starter/)到本地。这个项目里的 submodule 也须要 Clone。使用下面命令一步到位。

```bash
git clone --recursive https://github.com/github/vscode-codeql-starter/
```

在 VSCode 菜单中点击 `File > Open Workspace` 选择 `vscode-codeql-starter.code-workspace` 这个文件来打开这个工作区。

从[这个链接](https://downloads.lgtm.com/snapshots/cpp/uboot/u-boot_u-boot_cpp-srcVersion_d0d07ba86afc8074d79e436b1ba4478fa0f0c1b5-dist_odasa-2019-07-25-linux64.zip)下载已经分析好的 uboot CodeQL 数据库，然后解压到相应的文件夹。

使用 VSCode 快捷键 "ctrl + shift + p" 进入命令模式，输入 "codeql choose database" 看到相应的选项后，点击就可以添加上前面解压的 uboot codeql 数据库。

在前面打开工作区 VSCode 中使用 `File -> Add Folder to Workspace` 添加前面机器人新建的项目文件夹到当前工作区。

到此环境配置完成。

## 第一次查询和 Pull request

机器人创建的项目中有等着我们编辑的空文件和 `solution` 文件夹。接下来是教程中的第三步，编辑 `3_function_definitions.ql` 这个文件，借助补全填入下面内容，以查询 `strlen` 的声明和定义。

```ql
import cpp

from Function f
where f.getName() = "strlen"
select f, "a function named strlen"
```

可以看到 CodeQL 程序的基本架构，第一句 `import cpp` 导入了 CPP 模块，而后面的 `from ... where ... select` 就是 CodeQL 程序的基本结构。

`from Function f` 这句话声明了 f 是个 Function 类型的变量。Function 是个类，一个类代表了一种数据的集合，而 Function 这个类型代表了待分析代码中的函数集合。

后面的 `where ...` 中出现的谓词代表了我们想查询的逻辑，而变量 `f` 后面的 `getName` 是谓词，他表达了我们查询的逻辑。在上面的代码中我们找到了所有名字为 "strlen" 的函数。

然后在 VSCode 的命令面板里让命令跑起来，或者对着脚本右键，点击 "Run Query"，进行查询了。

![0](/images/codeql0.png)

写完代码后，就是发起 Pull request 了。

```bash
# 拉取 master
git checkout master
git pull
# 新建分支，并切换到该分支
git checkout -b step-4
# 进行 commit
git add .
git commit -a -m "Step 4 query"
# 推送分支，可以发起 pull request
git push -u origin step-4
```

执行完上面的命令后，在 Github 上打开 "codeql-uboot" 项目的 Pull request 标签，就可以看到我们创建了一个新分支，且可以发起 Pull request。在发起 PR 后，会触发 Github Actions，校验答案的时间在 1 到 3 分钟左右。检查完成后就会进行下一步操作了。

![1](/images/codeql1.png)

> 所以在这几分钟内可以看点泡面番，或者打开邦邦清下火（逃

## 导入不同的类完成查询

前面我们查询了函数，在第五步我们可以通过引入 "Macro" 类查询 `ntohl, ntohll, ntohs` 这三个转换字节序的宏。代码类似第一次查询，这里使用正则表达式可以缩短查询语句。

```ql
import cpp

from Macro m
where m.getName().regexpMatch("ntoh(s|l|ll)")
select m
```

## 使用两个变量来查询调用该函数的位置

在代码中的 `from` 语句处可以声明多个变量，然后在 `where` 中进行联系，以查询相关函数调用。如果无从下手的话可以看看[使用 CodeQL 查询 C++ 的样例](https://help.semmle.com/wiki/display/CBCPP/Call+to+function)

```ql
import cpp

from FunctionCall call, Function func
where
    call.getTarget() = func and
    func.getName() = "memcpy"
select call
```

## 查看宏的顶层表达

> 应该是展开宏吧...但是英文原文是 "Gets a top-level expression associated with this macro invocation"

通过 `MacroInvocation` 这个类来查询 "ntohs" 等宏的调用，并通过 `getExpr()` 这个方法进行宏的展开，得到相应的代码片段。

```ql
import cpp

from MacroInvocation mi
where mi.getMacro().getName().regexpMatch("ntoh(s|l|ll)")
select mi.getExpr()

```

## 自己实现一个类

前面[第一次查询](#)说了，一个类代表了一种数据的集合。通过实现一个自己的类，能自定义一个自己想要的数据集合。如果有点懵可以看看 CodeQL 关于类的[相关文档](https://help.semmle.com/QL/ql-handbook/types.html#classes)。查询语句中的类中，先通过 `exists` 量词创建一个临时变量 `mi` 来表示被调用的宏的名字，如果被调用的的宏展开后和当前代码片段相等，则这个表达式属于这个集合。

```ql
import cpp

class NetworkByteSwap extends Expr {
  NetworkByteSwap() {
    exists(MacroInvocation mi |
      mi.getMacroName().regexpMatch("ntoh(s|l|ll)") and
      this = mi.getExpr()
    )
  }
}

from NetworkByteSwap n
select n, "Network byte swap"
```

## 数据流和污点追踪

借助前面几步，我们基本了解了 CodeQL 的使用。最后一个测试是使用 CodeQL 进行污点追踪。这里使用了 CodeQL 的全局污点追踪(Global taint tracking)。可以先看看[使用 CodeQL 追踪数据流的文档](https://help.semmle.com/QL/learn-ql/cpp/dataflow.html)了解相关概念。新定义的 `Config` 类继承于 `TaintTracking::Configuration`。类中重载的 `isSource` 谓语定义为污点的源头，而 `isSink` 定义为污点的去处。

有时候，远程输入的数据可能经过 `ntoh` 函数处理，通过转换字节序得到相应的数字。而 `memcpy` 的第 2 个参数如果控制不当，可造成数据溢出。将上面两个结论结合起来，如果有一个远程输入的数据通过字节序变换得到的数字，在未经过校验的情况下，作为了 `memcpy` 的第二个参数，那么就有可能造成数据溢出。

照着 [Github 自家安全团队的文章](https://securitylab.github.com/research/cve-2018-4259-macos-nfs-vulnerability)，可以照猫画虎的补全数据查询语句。

在 `isSource` 中，我们通过判断 `source` 的 `Expr` 是否是 `NetworkByteSwap` 这个类，来判断污点的源头。

在 `isSink` 中，我们使用了辅助类 `FunctionCall` 判断函数调用是否为 `memcpy` 且 `sink` 的代码片段是否为 `memcpy` 的第二个参数；最后一句则是判断函数的第一个参数是否为常量，如果为常量的话基本不可能出现问题，所有忽略。

```ql
/**
 * @kind path-problem
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetworkByteSwap extends Expr {
  NetworkByteSwap() {
    exists(MacroInvocation mi |
      mi.getMacroName().regexpMatch("ntoh(s|l|ll)") and
      this = mi.getExpr()
    )
  }
}

class Config extends TaintTracking::Configuration {
  Config() { this = "NetworkToMemFuncLength" }

  override predicate isSource(DataFlow::Node source) { source.asExpr() instanceof NetworkByteSwap }

  override predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall call |
      call.getTarget().getName() = "memcpy" and
      sink.asExpr() = call.getArgument(2) and
      not call.getArgument(1).isConstant()
    )
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"

```

![2](/images/codeql2.png)

点击查询结果就可以跳转到代码位置，以进行详细分析。

![3](/images/codeql3.png)

这里就是 Github 展示的漏洞，对 nfs 请求的回复长度未经过校验，导致可以控制 nfs_path 的 2048 字节。

## refs

CodeQL 教程 <https://help.semmle.com/QL/learn-ql/>
