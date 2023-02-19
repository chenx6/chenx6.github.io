+++
title = "在 LLVM 代码树外编译 LLVM Pass (使用 OLLVM 示范)"
date = 2020-01-01
description = "在网络上流传的编译 LLVM Pass 都需要一份 LLVM 源码，从整个源代码编译，编译非常花时间 (i7 6700HQ 使用 `make -j8` 编译整个项目花了近 50 分钟)，所以在翻阅文档时发现 LLVM 支持在代码树外编译，在 1 分钟内编译一个 Pass，还是非常香的。"
tags = ["re", "llvm"]
+++

在网络上流传的编译 LLVM Pass 都需要一份 LLVM 源码，从整个源代码编译，编译非常花时间 (i7 6700HQ 使用 `make -j8` 编译整个项目花了近 50 分钟)，所以在翻阅文档时发现 LLVM 支持在代码树外编译，在 1 分钟内编译一个 Pass，还是非常香的。

## 项目配置

### 项目目录结构

本次作为示范的 OLLVM 是一个使用 LLVM Pass 进行代码混淆的项目。他的主要文件在于 `${LLVM 项目目录}/lib/Transforms/Obfuscation/` 和 `${LLVM 项目目录}/include/llvm/Transforms/Obfuscation/`。将这两个目录下的文件放入对应的目录就可以在代码树外编译 OLLVM 了。OLLVM 相关的文件可以在 [GitHub](https://github.com/obfuscator-llvm//obfuscator/tree/llvm-4.0) 找到。

在项目根目录放置主要的 `CMakeLists.txt` 和 代码目录，然后在代码目录中放代码和编译相关的 `CMakeLists.txt` 。项目结构类似下面。

```bash
$ tree ollvm
ollvm
├── CMakeLists.txt
└── Obfuscation
    ├── BogusControlFlow.cpp
    ├── CMakeLists.txt
    ├── CryptoUtils.cpp
    ├── Flattening.cpp
    ├── SplitBasicBlocks.cpp
    ├── Substitution.cpp
    ├── Utils.cpp
    └── include
        ├── BogusControlFlow.h
        ├── CryptoUtils.h
        ├── Flattening.h
        ├── Split.h
        ├── Substitution.h
        └── Utils.h

2 directories, 14 files
```

### 两个 CMakeLists.txt

第一个是项目目录下的 `CMakeLists.txt`，用来关联 LLVM 的文件，CMake 会按照一定的顺序寻找 LLVM 这个 Package，如果要手动指定的话使用 `-DLLVM_DIR=` 这个选项来指定。

```cmake
cmake_minimum_required(VERSION 3.10)

find_package(LLVM REQUIRED CONFIG)

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

add_subdirectory(Obfuscation)
```

下面是源代码目录下 `CMakeLists.txt`，用来编译出 Pass 的动态库文件。

```cmake
cmake_minimum_required(VERSION 3.10)

include_directories(./include)

add_library(LLVMObfuscation
  MODULE
  CryptoUtils.cpp
  Substitution.cpp
  BogusControlFlow.cpp
  Utils.cpp
  SplitBasicBlocks.cpp
  Flattening.cpp
)

add_dependencies(LLVMObfuscation intrinsics_gen)
```

### 代码魔改

由于 OLLVM 的代码是放在主代码树中的，所以在提取出代码树外后可能需要进行一点魔改才能让 Pass 正常工作。以 `BogusControlFlow.cpp` 为例，源代码的 `runOnFunction()` 函数中检测了 "bcf" 是否在全局声明中存在，但是将文件提取出来后，直接在 `opt` 加上相关参数就可以进行使用 Pass 了，所以将 `if (toObfuscate(flag, &F, "bcf"))` 语句直接去除，留下混淆部分就行。

```cpp
  virtual bool runOnFunction(Function &F) {
    // Check if the percentage is correct
    if (ObfTimes <= 0) {
      errs() << "BogusControlFlow application number -bcf_loop=x must be x > 0";
      return false;
    }

    // Check if the number of applications is correct
    if (!((ObfProbRate > 0) && (ObfProbRate <= 100))) {
      errs() << "BogusControlFlow application basic blocks percentage "
                "-bcf_prob=x must be 0 < x <= 100";
      return false;
    }
    // If fla annotations
    if (toObfuscate(flag, &F, "bcf")) {
      bogus(F);
      doF(*F.getParent());
      return true;
    }
```

修改后代码如下。

```cpp
  virtual bool runOnFunction(Function &F) {
    // Check if the percentage is correct
    if (ObfTimes <= 0) {
      errs() << "BogusControlFlow application number -bcf_loop=x must be x > 0";
      return false;
    }

    // Check if the number of applications is correct
    if (!((ObfProbRate > 0) && (ObfProbRate <= 100))) {
      errs() << "BogusControlFlow application basic blocks percentage "
                "-bcf_prob=x must be 0 < x <= 100";
      return false;
    }

    bogus(F);
    doF(*F.getParent());
    return true;
  } // end of runOnFunction()
```

## 开始编译

首先安装相关依赖，本文默认环境是 WSL Ubuntu 18.04

```bash
$ apt update
$ apt install cmake llvm-8 llvm-8-dev gcc # gcc/clang 都行
```

在项目目录新建个 `build` 文件夹，然后通过 CMake 的特性在 build 文件夹生成 `Makefiles`，然后进行编译。`-DLLVM_DIR` 的参数需要根据 `LLVMConfig.cmake` 的位置进行改变。

```bash
$ mkdir build && cd build
$ cmake .. -DLLVM_DIR=/usr/lib/llvm-8/lib/cmake/llvm/
$ cmake --build . -- -j$(nproc)
```

然后在 `build/Obfuscation` 下就会生成 `libLLVMObfuscation.so`

## Pass 使用

找了份 OJ 上题目的代码

```c
#include <stdio.h>

int main()
{
    int score, enterFlag = 0;
    while (scanf("%d", &score) != EOF)
    {
        if (enterFlag)
            printf("\n");
        else if (!enterFlag)
            enterFlag = 1;
        if (score >= 90 && score <= 100)
            printf("Excellent");
        else if (score >= 80 && score < 90)
        {
            printf("Good");
        }
        else if (score >= 70 && score < 80)
        {
            printf("Average");
        }
        else if (score >= 60 && score < 70)
        {
            printf("Pass");
        }
        else if (score >= 0 && score < 60)
        {
            printf("Failing");
        }
        else
        {
            printf("Error");
        }
    }
    return 0;
}
```

先将代码编译成 LLVM IR (Bitcode 形式)，然后使用 `opt` 调用 Pass 进行混淆，最后进行编译

```bash
$ clang-8 -emit-llvm -c F.c -o F.bc
$ opt-8 -load ./libLLVMObfuscation.so -boguscf F.bc -o F_bogus.bc
$ clang-8 F_bogus.bc -o F_bogus
```

一波操作后 IDA F5 的反汇编如下。可以看到出现了虚假的跳转，让代码可读性变差了，说明 Pass 确实执行了。

```c
/* This file has been generated by the Hex-Rays decompiler.
   Copyright (c) 2007-2017 Hex-Rays <info@hex-rays.com>

   Detected compiler: GNU C++
*/

#include <defs.h>


//-------------------------------------------------------------------------
// Function declarations

// int printf(const char *format, ...);
// __int64 __fastcall __isoc99_scanf(_QWORD, _QWORD); weak
int __cdecl main(int argc, const char **argv, const char **envp);

//-------------------------------------------------------------------------
// Data declarations

_UNKNOWN unk_400F24; // weak
int x; // weak
int y; // weak


//----- (0000000000400560) ----------------------------------------------------
int __cdecl main(int argc, const char **argv, const char **envp)
{
  bool v4; // [rsp+43h] [rbp-Dh]
  signed int v5; // [rsp+44h] [rbp-Ch]
  int v6; // [rsp+48h] [rbp-8h]
  int v7; // [rsp+4Ch] [rbp-4h]

  v7 = 0;
  v5 = 0;
  while ( 1 )
  {
    if ( y >= 10 && (((_BYTE)x - 1) * (_BYTE)x & 1) != 0 )
      goto LABEL_42;
    while ( 1 )
    {
      v4 = (unsigned int)__isoc99_scanf(&unk_400F24, &v6) != -1;
      if ( y < 10 || (((_BYTE)x - 1) * (_BYTE)x & 1) == 0 )
        break;
LABEL_42:
      __isoc99_scanf(&unk_400F24, &v6);
    }
    if ( !v4 )
      break;
    while ( y >= 10 && (((_BYTE)x - 1) * (_BYTE)x & 1) != 0 )
      ;
    if ( v5 != 0 )
    {
      printf("\n");
    }
    else
    {
      if ( !v5 )
      {
        do
          v5 = 1;
        while ( y >= 10 && (((_BYTE)x - 1) * (_BYTE)x & 1) != 0 );
      }
      while ( y >= 10 && (((_BYTE)x - 1) * (_BYTE)x & 1) != 0 )
        ;
    }
    while ( y >= 10 && (((_BYTE)x - 1) * (_BYTE)x & 1) != 0 )
      ;
    if ( v6 < 90 || v6 > 100 )
    {
      while ( y >= 10 && (((_BYTE)x - 1) * (_BYTE)x & 1) != 0 )
        ;
      if ( v6 >= 80 )
      {
        while ( y >= 10 && (((_BYTE)x - 1) * (_BYTE)x & 1) != 0 )
          ;
        if ( v6 < 90 )
        {
          if ( y >= 10 && (((_BYTE)x - 1) * (_BYTE)x & 1) != 0 )
            goto LABEL_49;
          while ( 1 )
          {
            printf("Good");
            if ( y < 10 || (((_BYTE)x - 1) * (_BYTE)x & 1) == 0 )
              goto LABEL_38;
LABEL_49:
            printf("Good");
          }
        }
      }
      if ( v6 < 70 || v6 >= 80 )
      {
        while ( y >= 10 && (((_BYTE)x - 1) * (_BYTE)x & 1) != 0 )
          ;
        if ( v6 < 60 || v6 >= 70 )
        {
          if ( v6 < 0 )
            goto LABEL_59;
          while ( y >= 10 && (((_BYTE)x - 1) * (_BYTE)x & 1) != 0 )
            ;
          if ( v6 >= 60 )
          {
LABEL_59:
            printf("Error");
          }
          else
          {
            if ( y >= 10 && (((_BYTE)x - 1) * (_BYTE)x & 1) != 0 )
              goto LABEL_52;
            while ( 1 )
            {
              printf("Failing");
              if ( y < 10 || (((_BYTE)x - 1) * (_BYTE)x & 1) == 0 )
                break;
LABEL_52:
              printf("Failing");
            }
          }
          while ( y >= 10 && (((_BYTE)x - 1) * (_BYTE)x & 1) != 0 )
            ;
          goto LABEL_37;
        }
        printf("Pass");
      }
      else
      {
        printf("Average");
      }
LABEL_37:
      while ( y >= 10 && (((_BYTE)x - 1) * (_BYTE)x & 1) != 0 )
        ;
LABEL_38:
      while ( y >= 10 && (((_BYTE)x - 1) * (_BYTE)x & 1) != 0 )
        ;
    }
    else
    {
      printf("Excellent");
    }
  }
  while ( y >= 10 && (((_BYTE)x - 1) * (_BYTE)x & 1) != 0 )
    ;
  return 0;
}
```

## refs

OLLVM (好久没更新了啊) <https://github.com/obfuscator-llvm//obfuscator/tree/llvm-4.0>

LLVM 官方关于 CMake 构建项目的文档：<http://releases.llvm.org/9.0.0/docs/CMake.html#developing-llvm-passes-out-of-source>

一个 LLVM Pass 骨架：<https://github.com/sampsyo/llvm-pass-skeleton>
