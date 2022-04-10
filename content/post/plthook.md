+++
title = "plt hook 项目代码分析和最小实现"
date = 2022-04-05
description = "虽然知道可以通过魔改 plt 表实现 hook 函数，但是不知道具体实现...碰巧最近用到了 plthook 这个库，于是我就研究了下 plthook 这个库，并且仿照着这个库重新实现一份代码。"
tags = ["re", "plt", "elf"]
+++
虽然知道可以通过魔改 plt 表实现 hook 函数，但是不知道具体实现...碰巧最近用到了 plthook 这个库，于是我就研究了下 plthook 这个库，并且仿照着这个库重新实现一份代码。

## 原理分析

根据命名规则，.rela.plt 表是负责 plt 表的重定位信息。.rela 表中有每项都有 2 个成员，r_offset 指向了该重定位入口所要修正的位置的第一个字节的虚拟地址， r_info 则是表示相关信息，可以通过 `ELF[32|64]_R_SYM` 获得其指向的 .dynsym 项的下标。

.dynsym 表（动态链接表）中存放动态链接需要的信息，可以通过 .dynsym 表从 .strtab 表中获得要链接的函数名字。

## 项目代码分析

经过阅读代码后，我大致了解了 plthook 在 Linux/x86_64 平台上的逻辑。

> 由于项目的代码支持多个 UNIX 系统（Windows 下则是实现了 IAT Hook），所以原项目中有一堆的宏和封装，下面的逻辑只对应着 Linux/x86_64 平台。

1. 获取 `link_map`
    - 对动态库使用 `dlinfo(hndl, RTLD_DI_LINKMAP, &lmap)`
    - 对可执行文件使用 `_r_debug.r_map` 结构体
2. 通过 `link_map` 获取相关 section 的信息。
    - 获取 "DT_SYMTAB DT_STRTAB DT_STRSZ DT_JMPREL DT_PLTRELSZ" 的相关信息
3. 在 rela 表中获得其在 dynsym 中的位置，然后通过 dynsym 获得名字
4. 如果是被替换函数，就通过修改 PLT 表进行替换。

## 重新复现

首先是通过 `dlopen` `dlinfo` 获得 `link_map`。使用 `sysconf` 则是获得了页的大小。

```c
/// @brief Initlize plthook_info
/// @param info empty plthook_info variable
/// @param name library name, NULL means program itself
plthook_status plt_hook_init(plthook_info *info, char *name) {
  page_size = sysconf(_SC_PAGESIZE);
  plthook_status status = PLTHOOK_SUCCESS;
  // Get link_map
  void *handle = dlopen(name, RTLD_LAZY | RTLD_NOLOAD);
  struct link_map *map = NULL;
  int result = dlinfo(handle, RTLD_DI_LINKMAP, &map);
```

然后是从 `link_map` 中获得各个 section（"DT_SYMTAB DT_STRTAB DT_STRSZ DT_JMPREL DT_PLTRELSZ"）的信息，供后续使用。

```c
  // Get information from link_map's address and dyn table
  info->base_addr = (uint8_t *)map->l_addr;
  size_t rela_size = 0;
  for (Elf64_Dyn *curr = map->l_ld; curr->d_tag != DT_NULL; curr++) {
    switch (curr->d_tag) {
    // Address of string table
    case DT_STRTAB:
      info->str_table = curr->d_un.d_ptr;
      break;
    case DT_STRSZ:
      info->str_sz = curr->d_un.d_val;
      break;
    // Address of relocation entries associated solely with the PLT
    case DT_JMPREL:
      info->rel = (Elf64_Rela *)curr->d_un.d_ptr;
      break;
    case DT_PLTRELSZ:
      rela_size = curr->d_un.d_val;
      break;
    // Address of symbol table
    case DT_SYMTAB:
      info->dynsym = (Elf64_Sym *)curr->d_un.d_ptr;
      break;
    }
  }
  info->rel_cnt = rela_size / sizeof(Elf64_Rela);
  return status;
}
```

然后是替换函数。主要流程就是通过 .rela.plt 表找到函数在 .dynsym 段的位置，然后再通过 .dynsym 段获取函数名字，如果是要替换的函数的话，就用 mprotect 将段加上可写权限，并通过写入 `r_offset` 指向的地址进行魔改。

```c
/// @brief Replace function with new function
plthook_status plt_hook_replace(plthook_info *info, char *name,
                                void *func_address) {
  if (info == NULL || name == NULL || func_address == NULL) {
    return PLTHOOK_ARGUMENT_ERROR;
  }
  // Get symbol index from relocation table, then get function name from symbol
  Elf64_Rela *rela = info->rel;
  for (size_t i = 0; i < info->rel_cnt; i++) {
    Elf64_Rela *curr = rela + i;
    size_t sym_idx = ELF64_R_SYM(curr->r_info);
    size_t str_idx = info->dynsym[sym_idx].st_name;
    if (strcmp(name, info->str_table + str_idx) != 0) {
      continue;
    }
    size_t *origin_func = (size_t *)(info->base_addr + curr->r_offset);
    mprotect(ALIGN_ADDR(origin_func), page_size,
             PROT_READ | PROT_WRITE | PROT_EXEC);
    *origin_func = (size_t)func_address;
    return PLTHOOK_SUCCESS;
  }
  return PLTHOOK_NOT_FOUND;
}
```

完整代码：<https://gist.github.com/chenx6/2624aae29873ffabbeb74b75d2351f22>

将代码和 `test_main.c` 一起编译(别忘了加上 -ldl)后，应该可以看到 `atoi` 的返回值从正确的 "123456" 变成了 "114514"，说明这个 POC 实现成功了。也可以通过用 ((constructor)) 修饰函数，通过 so 注入进行修改。

# Refs

- [kubo/plthook](https://github.com/kubo/plthook)
- `man elf`
- [ELF加载器的原理与实现](https://zhuanlan.zhihu.com/p/401446080)
- [计算机那些事(4)——ELF文件结构](http://chuquan.me/2018/05/21/elf-introduce/)
