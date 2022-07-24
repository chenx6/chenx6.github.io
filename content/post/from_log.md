+++
title = "从日志函数中回复无符号的函数名字"
date = 2022-07-24
tags = ["ida", "python"]
+++

在逆向二进制程序中，经常碰到将程序 strip 了，但是日志函数中保留着函数名字的情况。所以写文记录在这种情况下，使用 IDAPython 恢复函数名字的过程。

## 日志函数长什么样

下面是我手写的一个日志函数。主要有几个部分：

- 日志级别 `LogLevel`，记录日志的最低级别 `do_log_level`，用来在不同的情况下过滤日志。
- 日志文件 `log_file`，将日志输出到对应的文件中。
- 记录日志的函数 `logger_log`，还有几个辅助记录日志的宏。在宏中则是将函数的名称也记录了下来，方便后期调试。

代码也非常简单粗暴，唯一需要注意的是 `logger_log` 用了 C 中的变长函数参数，并且在相关的宏中用了 gcc 扩展 “GCC variadic macro” 来处理宏中的变长参数。

```c
#include <stdarg.h>
#include <stdio.h>

enum LogLevel { DEBUG = 0, INFO, WARNING, ERROR };

static FILE *log_file = NULL;
static int do_log_level = 0;

/// @brief init log file and log level
void logger_init(const char *file_path, int log_level) {
  if (file_path) {
    log_file = fopen(file_path, "a+");
  } else {
    log_file = stderr;
  }
  do_log_level = log_level;
}

/// @brief do log
void logger_log(int level, const char *fmt, ...) {
  if (log_file == NULL) {
    return;
  }
  if (level < do_log_level) {
    return;
  }
  va_list vl;
  va_start(vl, fmt);
  vfprintf(log_file, fmt, vl);
  fputc('\n', log_file);
  va_end(vl);
}

#define LOG_DEBUG(fmt, ...)                                                    \
  logger_log(DEBUG, "[DEBUG]   [%s] " fmt, __FUNCTION__, ##__VA_ARGS__);
#define LOG_INFO(fmt, ...)                                                     \
  logger_log(INFO, "[INFO]    [%s] " fmt, __FUNCTION__, ##__VA_ARGS__);
#define LOG_WARNING(fmt, ...)                                                  \
  logger_log(WARNING, "[WARNING] [%s] " fmt, __FUNCTION__, ##__VA_ARGS__);
#define LOG_ERROR(fmt, ...)                                                    \
  logger_log(ERROR, "[ERROR]   [%s] " fmt, __FUNCTION__, ##__VA_ARGS__);
```

接下来是一点测试代码

```c
int a_important_function() {
  LOG_WARNING("Warning world, return value: %d", 114514);
  return 1919810;
}

int main(int argc, char *argv[]) {
  logger_init(NULL, INFO);
  LOG_DEBUG("Debug, world!");
  LOG_INFO("Info, world!");
  // logger_log(INFO, "[INFO]   [%s] Info, world!", __FUNCTION__);
  int ret = 0;
  if ((ret = a_important_function()) != 0) {
    LOG_ERROR("Error world, exit code: %d", ret);
  }
  return 0;
}
```

下面是程序运行后的输出，可以看到 DEBUG 级别低于要记录的 INFO 级别，所以 DEBUG 级别的日志没有输出。

```bash
$ gcc test.c -o test -O0 -Wall
$ ./test                   
[INFO]    [main] Info, world!
[WARNING] [a_important_function] Warning world, return value: 114514
[ERROR]   [main] Error world, exit code: 1919810
```

## 在 IDA 中，上面的代码长什么样

在反汇编结果中，可以看到虽然 DEBUG 级别的日志没有输出，但是相关的函数调用仍然在代码中保留着。并且每个日志函数的调用，在参数中都有函数名字。在这种情况下，就可以使用 IDAPython 进行自动化提取函数名字并且恢复回去了。

```c
int sub_401156(int a1, const char *a2, ...)
{
  int result; // eax
  gcc_va_list arg; // [rsp+8h] [rbp-D0h]

  result = (signed int)stream;
  if ( stream )
  {
    if ( dword_404070 <= a1 )
    {
      va_start(arg, a2);
      vfprintf(stream, a2, arg);
      result = fputc(10, stream);
    }
  }
  return result;
}

__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char *a4; // [rsp+1Ch] [rbp-4h]

  sub_401156(0LL, 1LL, a3);
  sub_4011A0(0, "[DEBUG]   [%s] Debug, world!", "main", a2);
  sub_4011A0(1, "[INFO]    [%s] Info, world!", "main");
  LODWORD(a4) = sub_40127B(1LL, "[INFO]    [%s] Info, world!");
  if ( (_DWORD)a4 )
    sub_4011A0(3, "[ERROR]   [%s] Error world, exit code: %d", "main", (unsigned int)a4);
  return 0LL;
}
```

## IDAPython 登场

下面是脚本。思路则是使用 `idautils.CodeRefsTo` 获取日志函数的调用，并且从调用处使用 `idaapi.get_arg_addrs` 获得带函数名字参数的地址，然后从这个地址读取出函数名字，调用 `idc.set_name` 重命名当前函数。

```python
import idaapi
import idautils
import idc
import ida_ida

func_addr = 0x4011a0  # log function address, Use 'y' to declare argument's type first
# https://reverseengineering.stackexchange.com/questions/25301/getting-function-arguments-in-ida
name_idx = 2  # function name in log call position
# https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml
if idaapi.IDA_SDK_VERSION <= 700:
    min_ea = idc.MinEA()
    max_ea = idc.MaxEA()
else:
    min_ea = ida_ida.inf_get_min_ea()
    max_ea = ida_ida.inf_get_max_ea()


def is_addr_invalid(addr):
    """Check `addr` is valid address"""
    return (
        addr == 0
        or addr == 0xFFFFFFFF
        or addr == 0xFFFFFFFFFFFFFFFF
        or addr < min_ea
        or addr > max_ea
    )


def read_c_str(addr, limit=32):
    """Read C string from `addr`"""
    if addr == 0 or addr == 0xFFFFFFFF or addr == 0xFFFFFFFFFFFFFFFF:
        return b""
    curr_addr = addr
    ret = b""
    while True:
        data = idc.get_bytes(curr_addr, 1)
        if data == b"\x00" or data == 0:
            break
        if curr_addr > addr + limit:
            break
        ret += data
        curr_addr += 1
    return ret


def search_nearest_function(addr):
    """Search function that `addr` belongs to"""
    prev_func = 0x0
    for func in idautils.Functions():
        if func > addr:
            break
        prev_func = func
    return prev_func


refs = list(idautils.CodeRefsTo(func_addr, 0))
print("[+] ref len %d" % len(refs))
for xref_addr in refs:
    # Get function argument
    args = idaapi.get_arg_addrs(xref_addr)
    if not args or len(args) <= name_idx:
        print("[-] No args")
        continue
    # Get argument address
    arg_addr = args[name_idx]
    if is_addr_invalid(arg_addr):
        print("[-] Argument address is invalid")
        continue
    # Get argument's immendiate value
    insn = idaapi.insn_t()
    length = idaapi.decode_insn(insn, arg_addr)
    func_name_addr = insn.ops[1].value
    if is_addr_invalid(func_name_addr):
        print("[-] Function name address is invalid")
        continue
    # Get function name
    func_name = read_c_str(func_name_addr)
    func = search_nearest_function(xref_addr)
    print("[+] %x %s" % (func, func_name))
    idc.set_name(func, func_name, 0)

```

有些地方需要注意：判断函数地址是否在程序运行虚拟地址，读取 C 式字符串，获得当前指令所属的函数地址是自己写的函数，可能有更好的内置函数来辅助判断。还有 `get_arg_addrs` 函数，获得的是给参数赋值的指令地址，例如对下面的代码，使用 `["%x" % i for i in idaapi.get_arg_addrs(0x4012d6)]`，得到的返回值是 `['4012cc', '4012c7', '4012c2']`，而不是字符串地址，所以得对指令使用 `idaapi.decode_insn` 进行解码，获得立即数的地址，即字符串的地址。还有就是日志函数有可能类型定义有问题，会导致 `get_arg_addrs` 返回 None，这种情况下，对着日志函数按 "y" 对参数类型和数量进行编辑，编辑后再次运行脚本即可获取参数。

```assembly
.text:00000000004012C2                 mov     edx, offset aMain ; "main"
.text:00000000004012C7                 mov     esi, offset aDebugSDebugWor ; "[DEBUG]   [%s] Debug, world!"
.text:00000000004012CC                 mov     edi, 0          ; a1
.text:00000000004012D1                 mov     eax, 0
.text:00000000004012D6                 call    sub_4011A0
```

代码运行结果如下，可以看到，补全了没有符号的 `a_important_function` 函数名字，达到了基本效果。

```log
[+] ref len 4
[+] 40127b a_important_function
[+] 4012a4 main
[+] 4012a4 main
[+] 4012a4 main
```

## Refs

- The Beginner’s Guide to IDAPython Version 6.0
- [Getting function arguments in ida](https://reverseengineering.stackexchange.com/questions/25301/getting-function-arguments-in-ida)
- [Porting from IDAPython 6.x-7.3, to 7.4](https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml)
