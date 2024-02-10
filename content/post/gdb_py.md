+++
title = "使用 Python 来自动化 gdb 调试"
date = 2024-02-10
[taxonomies]
tags = ["re", "gdb", "python"]
+++

在工作中碰到了很多地方只能用 gdb 进行调试，并且得进行很多冗余的操作。经过资料查询后发现，可以使用 Python 对 gdb 进行 api 调用，但是网上相关文档比较的少，所以本文将记录一些相关操作。

## 相关 API 介绍

### 基本操作

`gdb.execute (command [, from_tty [, to_string]])` 执行 gdb 命令。

`gdb.parse_and_eval (expression)` 解析一个表达式，并返回一个 `gdb.Value` 值。

### Breakpoint

通过类似下面的 Python 代码即可实现一个自定义的断点，并可以通过继承的方法进行相应的操作。例如下面的代码中可以在 `stop` 函数中加入断点到达时执行一些操作，最后通过初始化类实现在 `func_name` 下断点。

```python
class MyBreakpoint(gdb.Breakpoint):
    def stop(self):
        pass
MyBreakpoint("func_name")
```

### Inferiors

在 gdb 下运行的程序被称为 `inferiors`。

`gdb.selected_inferior ()` 返回当前 `inferior`。

`Inferior.read_memory (address, length)` 从 address 地址处读取 length 长度的字节，函数的返回类型为 memoryview。

`Inferior.write_memory (address, buffer [, length])` 往 address 地址写入 buffer 的内容。

`Inferior.search_memory (address, length, pattern)` 在 address 处搜索 pattern 的内容。

## 实战

### 在函数处读取某个结构体的相关值

我手里拿到了一份编译后的 yara 规则库，希望能知道这份 yara 规则库里包含了哪些规则，但是这个规则库没法被自己编译的 yara 加载，于是通过代码找到了在执行规则库时的遍历规则语句，并通过 IDA 在 ELF 可执行文件中找到了相似代码。

```c
YR_API int yr_scanner_scan_mem_blocks(
    YR_SCANNER* scanner,
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  // ...
  for (i = 0, rule = rules->rules_table; !RULE_IS_NULL(rule); i++, rule++)
  {
    // ...
  }
}
```

IDA 下看到的相关规则载入语句。

```txt
.text:0000000000050B18                 mov     rax, [rsp+888h+var_860]
.text:0000000000050B1D                 xor     ebx, ebx
.text:0000000000050B1F                 mov     r14d, 1Ch
.text:0000000000050B25                 mov     rbp, [rax+8]
.text:0000000000050B29                 mov     eax, [rbp+0]
.text:0000000000050B2C                 test    al, 4
.text:0000000000050B2E                 jnz     loc_50E29
.text:0000000000050B34                 nop     dword ptr [rax+00h]
```

结合反编译结果，可以确认 `YR_RULE` 结构体地址被载入了 $rbp 寄存器中，结合 yara 代码，编写出下面语句提取规则名字。下面的 Python 代码是在读取 rbp 寄存器的值，并且计算出每个 `YR_RULE` 的地址，并读取结构体中的指针，从而获取成员的值。

需要注意的是，下断点位置的代码在断点到达时还未被执行，所以我们需要在 0x50B25 的后一条语句 0x50B29 处下断点，这样 rbp 寄存器中才会存入相应的值。

```python
import gdb

def get_ptr_from_addr(addr, infer):
    mem = infer.read_memory(addr, 8)
    return int.from_bytes(bytes(mem), "little")

class YRSCANBP(gdb.Breakpoint):
    # yr_scanner_scan_mem_blocks
    def stop(self):
        rules = gdb.parse_and_eval("$rbp")
        inferior = gdb.selected_inferior()
        for i in range(466):
            rule_addr = rules + i * 6 * 8
            name = rule_addr + 8
            meta = rule_addr + 24
            nptr = get_ptr_from_addr(name, inferior)
            s = inferior.read_memory(nptr, 32)
            mptr = get_ptr_from_addr(meta, inferior)
            k = inferior.read_memory(get_ptr_from_addr(mptr, inferior), 32)
            v = inferior.read_memory(get_ptr_from_addr(mptr + 8, inferior), 32)
            print([bytes(i).split(b"\x00")[0] for i in [s, k, v]])

YRSCANBP("*(yr_scanner_scan_mem_blocks-0x50960+0x50B29)")
```

### 实现类似 gdb-peda 一样的信息输出

可以通过下面的语句设置 hook，实现在每一次到达断点时候执行 Python 代码。然后在 Python 代码中可以实现输出寄存器的值，输出内存中内容，输出指针指向等内容。

```txt
define hook-stop
    python run()
end
```

本人实现的脚本比较长，而且代码质量不太行，不过我还是上传到了[这里](https://github.com/chenx6/gadget/blob/master/ggddbb/ggddbb.py)，可以供读者参考。

## 总结

gdb + python 这个组合能发挥出很大的威力，能做到自动化调试，减少逆向工程负担。更多的操作可以查看 gdb 的官方文档。

## Refs

- [Python API](https://www.ece.villanova.edu/VECR/doc/gdb/Python-API.html)
- [Manipulating breakpoints using Python](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Breakpoints-In-Python.html)
