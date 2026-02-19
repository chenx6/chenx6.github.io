+++
title = "7z 路径处理导致的问题（CVE-2025-11001/CVE-2025-55188）"
date = 2026-02-19
[taxonomies]
tags = ["re"]
+++

去年在上网冲浪的时候发现 7z 连续在软链接处理上爆出来了 3 个漏洞，而且是可稳定利用的路径穿梭漏洞，所以就想自己看看为什么会出现这种情况，两者之间是否有共通点。

## 构建

在 Linux 下执行下面命令即可构建。

```bash
cd CPP/7zip/Bundles/Alone
make -f makefile.gcc
```

## 梦开始的地方

24.09 版本下，会使用下面函数对软链接进行检查，当 LowLevel (文件相对于解压路径的最小层级) 和 FinalLevel (文件相对于解压路径的层级) 不符合要求的时候，会拒绝解压。防止软链接指向了指定解压目录的外面。

```cpp
bool IsSafePath(const UString &path)
{
  CLinkLevelsInfo levelsInfo;
  levelsInfo.Parse(path);
  return !levelsInfo.IsAbsolute
      && levelsInfo.LowLevel >= 0
      && levelsInfo.FinalLevel > 0;
}
```

例如 "./dir/../file" 的 LowLevel 为 0，FinalLevel 为 1，可以通过校验。但是 "./dir/../../file" 的 LowLevel 为 -1, FinalLevel 为 0，不能通过校验。

## 软链接处理流程

下面是精简版本的解压文件函数调用图，在后面两个 CVE 的分析中都可以参考。

```cpp
GetExtractStream()
    if (_fi.IsLinuxSymLink())
        _is_SymLink_in_Data_Linux = true;
CloseReparseAndFile()
    needSetReparse = linkInfo.Parse(_outMemBuf, reparseSize, _is_SymLink_in_Data_Linux);
        isRelative = true;
        return true;
    if (needSetReparse)
        SetFromLinkPath(_diskFilePath, linkInfo, linkWasSet)
            // 检查软链接路径
            if (linkInfo.isRelative)
                relatPath = GetDirPrefixOf(_item.Path);
            relatPath += linkInfo.linkPath;
            IsSafePath(relatPath)
            // 解压软链接
            if (!linkInfo.isRelative)
                NName::GetFullPath(_dirPathPrefix_Full, us2fs(relatPath), existPath)
            else
                existPath = us2fs(linkInfo.linkPath)
            FillLinkData(data, fs2us(existPath), !linkInfo.isJunction, linkInfo.isWSL)
            NFile::NIO::SetReparseData(fullProcessedPath, _item.IsDir, data, (DWORD)data.Size())
```

## CVE-2025-11001

这个漏洞是在 25.00 进行修复的。当软链接指向 "C:\" 开头的路径的时候，完全满足 `IsSafePath` 的检查。导致创建一个穿梭出解压路径的软链接。压缩包后续的文件只要在这个软链接指向的文件夹内，就会被直接解压到这个软链接指向的文件夹。

例如存在下面压缩包，在解压软链接会使用 `IsSafePath("link/C:\")` 通过检查，创建软链接，并且在解压投毒文件的时候，会将文件放到 "C:\file" 处，造成路径穿梭。由于路径中有 "C:\"，所以只能在 Windows 下利用。

```txt
link/ -> C:\  // 软链接
link/file     // 投毒文件
```

## CVE-2025-55188

这个漏洞是在 25.01 进行修复的。利用的是 7z 会将压缩包中指向绝对路径的软链接改为当前目录下，再加上 7z 解压文件的时候，是按照一定顺序进行解压的，导致可以通过嵌套软链接绕过检查，实现路径穿梭。

例如我在 "/tmp/test" 目录下解压下面的压缩包。压缩包里的这些软链接都可以通过 `IsSafePath()` 的检查。但是在解压 "a/b/link" 的时候 7z 使其指向 "/tmp/test/a"，然后在解压 "link" 的时候 7z 使其指向 "a/b/link/../../"，最后到解压 "link/file" 的时候会被解压到 "/tmp/file"，构成路径穿梭。

```txt
a/b/link -> /a
link -> a/b/link/../../
link/file
```

解压后文件夹结构如下：

```txt
/tmp/test> tree
.
├── a
│   └── b
│       └── link -> /tmp/test/a
└── link -> a/b/link/../../

5 directories, 0 files
```

可以 gdb 动态调试一下发现这个神奇的利用：

```txt
(gdb) set args x arb_write.tar
(gdb) b NWindows::NFile::NIO::SetSymLink
Breakpoint 1 at 0x44bd00: file ../../../Windows/FileLink.cpp, line 606.
(gdb) r
Breakpoint 1, NWindows::NFile::NIO::SetSymLink (from=0x5b05c0 "./a/b/link", to=0x5af8b0 "/tmp/test/a")
    at ../../../Windows/FileLink.cpp:606
606       ir = symlink(to, from);
(gdb) c
Continuing.
Breakpoint 1, NWindows::NFile::NIO::SetSymLink (from=0x5b0480 "./link", to=0x5b0b80 "a/b/link/../../")
    at ../../../Windows/FileLink.cpp:606
606       ir = symlink(to, from);
(gdb) c
[Inferior 1 (process 44196) exited normally]
(gdb) q
```

## 修复方法

对于 CVE-2025-11001，是加强了 IsSafePath 的检查，使用 `NName::IsAbsolutePath` 进行校验。

对于 CVE-2025-55188，则是避免嵌套软链接，延迟链接的解压等一系列操作，来规避问题。毕竟一年 3 个漏洞都和路径穿梭有关系，肯定要加强注意。

## 总结

这两个漏洞虽然都是对路径处理出现了问题，但是出问题的方式还是不一样的，一个是对跨平台（Windows/Unix）文件路径的处理问题，另一个则是对链接的处理出现了问题。

## Refs

- [Diffing 7-Zip for CVE-2025-11001](https://pacbypass.github.io/2025/10/16/diffing-7zip-for-cve-2025-11001.html)
- [CVE-2025-55188: 7-Zip Arbitrary Code Execution](https://lunbun.dev/blog/cve-2025-55188/)
