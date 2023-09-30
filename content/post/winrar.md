+++
title = "WinRAR 最近的 2 个漏洞分析/复现"
date = 2023-09-30
[taxonomies]
tags = ["re"]
+++

其实这个漏洞的公告一出来我就开始进行分析了，只是因为空闲时间的利用非常的差，所以分析的很慢，最多就确认了漏洞修复地点。后来大佬们详细的分析就发出来了，所以这篇文章只能算是复现文章了...

## CVE-2023-40477

从下面的官方公告中可以知道代码修复的地方是在 RAR4 恢复卷的处理代码中。

> Critical Bug: CVE-2023-40477. The vulnerability allows remote attackers to execute arbitrary code on affected installations. User interaction is required to exploit this vulnerability. This is fixed in the RAR4 recovery volume processing code. 

ZDI 的公告也是一样的说法。

> The specific flaw exists within the processing of recovery volumes. The issue results from the lack of proper validation of user-supplied data, which can result in a memory access past the end of an allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the current process.

WinRAR 的 unrar 代码是可以下载的，所以通过 [GitHub 上的代码仓库](https://github.com/pmachapman/unrar) 可以下载和对比不同版本的代码，在 commit [2464dd1c376585f0e4ce51157d50aea358a50bbc](https://github.com/pmachapman/unrar/commit/2464dd1c376585f0e4ce51157d50aea358a50bbc) 可以看到下面的修改。加强了对数据的校验，防止整数溢出导致越界写入。

```diff
diff --git a/recvol3.cpp b/recvol3.cpp
index ecf6dd3..0138d0f 100644
--- a/recvol3.cpp
+++ b/recvol3.cpp
@@ -226,7 +226,7 @@ bool RecVolumes3::Restore(CommandData *Cmd,const wchar *Name,bool Silent)
       if (WrongParam)
         continue;
     }
-    if (P[1]+P[2]>255)
+    if (P[0]<=0 || P[1]<=0 || P[2]<=0 || P[1]+P[2]>255 || P[0]+P[2]-1>255)
       continue;
     if (RecVolNumber!=0 && RecVolNumber!=P[1] || FileNumber!=0 && FileNumber!=P[2])
     {
@@ -238,7 +238,14 @@ bool RecVolumes3::Restore(CommandData *Cmd,const wchar *Name,bool Silent)
     wcsncpyz(PrevName,CurName,ASIZE(PrevName));
     File *NewFile=new File;
     NewFile->TOpen(CurName);
-    SrcFile[FileNumber+P[0]-1]=NewFile;
+
+    // This check is redundant taking into account P[I]>255 and P[0]+P[2]-1>255
+    // checks above. Still we keep it here for better clarity and security.
+    int SrcPos=FileNumber+P[0]-1;
+    if (SrcPos<0 || SrcPos>=ASIZE(SrcFile))
+      continue;
+    SrcFile[SrcPos]=NewFile;
+
     FoundRecVolumes++;
 
     if (RecFileSize==0)
```

使用 Bindiff 找到类似特征，可以在 6.22.0 简体中文版本的 unrar+0x1BC03 (14001BC03) 地址找到修改。

查看源代码可以确认函数从恢复文件中的文件末尾中获取文件分卷数，并存放在 `P` 数组里。经过旧版本的溢出检查后，通过 `P` 数组的运算，往 `RecVolumes3 RecVol` 对象的私有成员 `File *SrcFile[256]` 里写入一个 `File *` 指针。而数组写入地址的索引是 `P[2]+P[0]-1`。

通过创建 RAR 压缩包，调整切分为分卷文本框的值来产生分卷，在“高级 - 分卷”里启用 1 个恢复卷，然后开启脚本修改 RAR 的 .rev 文件，删除一个分卷，通过 `unrar t test_delete.part01.rar` 即可触发漏洞，实现越界写入一个函数指针。这里我对 wildptr.io 的脚本进行小幅修改，让脚本将 P 数组的内容设置为 `[0xf0, 0x00, 0xf0]`。

```python
import zlib
import struct

def calculate_crc32(data):
	crc_value = zlib.crc32(data)
	return struct.pack("<I", crc_value & 0xFFFFFFFF)

with open("test_delete.part01.rev.origin", "rb") as f:
    data = f.read()
    p = bytes([0xf0, 0x00, 0xf0])
    new_data = data[:-7] + p + calculate_crc32(data[:-7] + p)
    with open("test_delete.part01.rev", "wb") as fw:
        fw.write(new_data)

```

在调试器中可以看到数组索引(rax 寄存器)已经越界到 0x1e2(482)，超过了 256，但是这样越界写并不能造成程序崩溃或者任意代码执行，因为写入的地址是往高地址方向越界，在调试器里看高地址空间都没什么重要数据...

![x64dbg0](/images/winrar.png)

后来我阅读了别人的分析文章，发现如果要造成崩溃，或覆盖返回地址的效果，可以用旧风格文件名中填充 `P` 数组，而不是从恢复文件中获得 `P` 数组的值。由于代码逻辑的问题，可以从文件名中读取出负数，从而实现覆盖返回地址。不过即使覆盖了返回地址，也只能造成程序崩溃，应该是没法造成代码执行。

```c
    if (NewStyle)
    {
      /* ... */ 
    }
    else
    {
      wchar *Dot=GetExt(CurName);
      if (Dot==NULL)
        continue;
      bool WrongParam=false;
      for (size_t I=0;I<ASIZE(P);I++)
      {
        do
        {
          Dot--;
        } while (IsDigit(*Dot) && Dot>=CurName+BaseNamePartLength);
        P[I]=atoiw(Dot+1);
        if (P[I]==0 || P[I]>255)
          WrongParam=true;
      }
      if (WrongParam)
        continue;
    }
```

## CVE-2023-38831

这个漏洞应该利用价值比较高，并且网上分析也很多，所以我就简单分析下。下面的代码是判断两文件名字是否相等函数的部分代码，可以看到在用 `wcsncmp` 比较文件文件名时候，只用到了第一个文件名字的长度(变量 `a1_len`)，而没有用到第二个文件名字的长度，而后面半部分代码则是检查文件名字的结尾是否为 '\' '/' 或者 0 字节。这就会导致如果压缩文件中存在相同名字的文件夹和文件时，例如 "test.txt/" 文件夹 "test.txt" 文件，两者的内容都会被释放到临时目录。

```c
    v7 = -1i64;
    a1_len = -1i64;
    do
      ++a1_len;
    while ( a1[a1_len] );
    if ( (unsigned int)(unsigned __int16)a3 - 2 > 2 )
    {
      if ( (a3 & 0x80000000) == 0 )
        neq = sub_1400AF168(a1, a2, a1_len);
      else
        neq = wcsncmp(a1, a2, a1_len);
      if ( !neq )
      {
        v10 = a2[a1_len];
        if ( v10 == '\\' || v10 == '/' || !v10 )
          return 1;
      }
      if ( v3 == 1 )
        return 0;
    }
```

配合上 `ShellExecuteExW` 对文件的处理，就造成了点击一个文件，让另一个文件被调用执行的情况...详细分析请看 [Refs](#refs)

## Refs

- [WinRAR 6.23 final released](https://www.win-rar.com/singlenewsview.html?&L=0&tx_ttnews%5Btt_news%5D=232&cHash=c5bf79590657e32554c6683296a8e8aa)
- [RARLAB WinRAR Recovery Volume Improper Validation of Array Index Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-23-1152/)
- [CVE-2023-40477 vulnerability](https://www.rarlab.com/vuln_rev3_names.html)
- [“Game of Rars” – Exploring a New Remote Code Execution Vulnerability in WinRAR with Proof-of-Concept (CVE-2023-40477)](https://wildptr.io/winrar-cve-2023-40477-poc-new-vulnerability-winrar-security-research/)
- [CVE-2023-40477 Root Cause Analysis](https://www.richardosgood.com/posts/cve---2023---4047-root-cause-analysis/)
- [CVE-2023-38831 WinRAR 漏洞分析](https://paper.seebug.org/3036/)
- [Winrar代码执行漏洞(CVE-2023-38831)的原理分析](https://www.cnblogs.com/GoodFish-/archive/2023/09/21/17715977.html)
