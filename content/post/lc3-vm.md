+++
title = "LC3-VM 学习和实现"
date = 2020-01-15
description = "本文是根据 <https://justinmeiners.github.io/lc3-vm> 和 <https://justinmeiners.github.io/lc3-vm/supplies/lc3-isa.pdf> ISA 写出 LC3 VM 的实现过程。"
tags = ["vm"]
+++

本文是根据 <https://justinmeiners.github.io/lc3-vm> 和 <https://justinmeiners.github.io/lc3-vm/supplies/lc3-isa.pdf> ISA 写出 LC3 VM 的实现过程。

代码已上传到了 Github 上：<https://github.com/chenx6/lc3-vm>

## LC3 架构

### 内存

LC3 架构有 2^16 个地址，每个地址包含一个 word (2 byte, 16 bit)。是大端序存储。所以用 C 表示如下。

```c
uint16_t *memory = malloc(UINT16_MAX * sizeof(uint16_t));
```

### 指令

指令长度为固定 16 bit (不定长的 x86 出来挨打)。12-15 bit 用于表示 opcode，其他部分则是根据 opcode 来发挥其用途。下面是使用枚举类型表示出 LC3 指令的 opcode。

```c
enum Opcode
{
    OP_BR = 0, /* branch */
    OP_ADD,    /* add  */
    OP_LD,     /* load */
    OP_ST,     /* store */
    OP_JSR,    /* jump register */
    OP_AND,    /* bitwise and */
    OP_LDR,    /* load register */
    OP_STR,    /* store register */
    OP_RTI,    /* unused */
    OP_NOT,    /* bitwise not */
    OP_LDI,    /* load indirect */
    OP_STI,    /* store indirect */
    OP_JMP,    /* jump/ret */
    OP_RES,    /* reserved (unused) */
    OP_LEA,    /* load effective address */
    OP_TRAP    /* execute trap */
};
```

### 寄存器

LC3 有三种寄存器，通用寄存器 (R0-R7)，指令计数器 (PC)，条件寄存器 (COND)。

条件寄存器则是存储着三种状态：负数 (N)，零 (Z)，正 (P)。

下面是使用枚举类型表示出寄存器的下标，还有条件寄存器的条件。

> 枚举类型的最后一个无实际价值，只是用来表示寄存器的数量

```c
enum Register
{
    R_R0 = 0, /* General purpose registers */
    R_R1,
    R_R2,
    R_R3,
    R_R4,
    R_R5,
    R_R6, /* User Stack Pointer */
    R_R7,
    R_PC,   /* Program counter */
    R_COND, /* Condition codes */
    R_COUNT /* Counter */
};

enum Condition
{
    FL_POS = 1 << 0, /* Positive */
    FL_ZRO = 1 << 1, /* Zero */
    FL_NEG = 1 << 2, /* Negative */
};
```

### 其他

LC3 还有中断，内存映射的 IO，优先级等。

在 LC3 中有个类似 x86 int 的 TRAP，实现输入输出等功能。

```c
enum Trap
{
    TRAP_GETC = 0x20,  /* get character from keyboard */
    TRAP_OUT = 0x21,   /* output a character */
    TRAP_PUTS = 0x22,  /* output a word string */
    TRAP_IN = 0x23,    /* input a string */
    TRAP_PUTSP = 0x24, /* output a byte string */
    TRAP_HALT = 0x25   /* halt the program */
};
```

在内存中映射的寄存器，可以通过内存地址进行访问，这里可以访问内存知道当前键盘按下与否，按下的按键，还有输出状态的功能。

```c
enum Memory
{
    MR_KBSR = 0xFE00,  /* keyboard status */
    MR_KBDR = 0xFE02,  /* keyboard data */
    MR_DSR = 0xFE04,   /* display status */
    MV_DDR = 0xFE06,   /* display data */
    MCR = 0xFFFE       /* machine control */
};
```

## 虚拟机实现

### 虚拟机基本架构

原文将读取文件和解析指令耦合在了一起，并且将内存和寄存器都变成了全局变量，那样就不能同时跑多个虚拟机了。所以在我的实现中，将读取文件，和解析指令并执行进行了拆分，将存储内存和寄存器的数组从全局变量变成了动态内存，还从别的项目里偷了测试样例 <https://github.com/viking/lc3-vm/>，最后写个 CMake 来负责处理编译依赖。

通过一个结构体表示虚拟机的状态 (内存和寄存器) 会方便管理一些。

```c
typedef struct _vm_ctx
{
    uint16_t *memory;
    uint16_t *regs;
} vm_ctx;

vm_ctx *init_vm(const char *path)
{
    vm_ctx *curr_vm = malloc(sizeof(vm_ctx));
    curr_vm->memory = read_image(path);
    curr_vm->regs = malloc(sizeof(uint16_t) * R_COUNT);
}

void destory_vm(vm_ctx *curr_vm)
{
    free(curr_vm->memory);
    free(curr_vm->regs);
    free(curr_vm);
}
```

整个虚拟机先从参数指向的程序读取程序镜像，然后开始不断运行程序，直到虚拟机解析到相关 Trap 时终止程序运行。

```c
int main(int argc, char **argv)
{
    vm_ctx *curr_vm;
    if (argc == 2)
    {
        curr_vm = init_vm(argv[1]);
    }
    else
    {
        fprintf(stderr, "Usage: %s [program]\n", argv[0]);
        exit(-1);
    }

    int running = 1;
    while (running)
    {
        running = execute_inst(curr_vm);
    }
    destory_vm(curr_vm);
    return 0;
}
```

### 读取程序

就是上面代码中出现的 `read_image` 函数。

由于程序为大端序，而平时使用的 x86 PC 是小端序，所以在读取时需要将程序转换成小端序以方便后面的解析。

我们通过 `read_image` 函数来将程序加载到内存中，并且转换为小端序的操作。

```c
/* change endianness */
uint16_t swap16(uint16_t x)
{
    return (x << 8) | (x >> 8);
}

uint16_t *read_image(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (!file)
    {
        printf("[-] Read error!");
        return NULL;
    }
    uint16_t *memory = malloc(sizeof(INT16_MAX * sizeof(uint16_t)));

    /* the origin tells us where in memory to place the image */
    uint16_t origin;
    fread(&origin, sizeof(origin), 1, file);
    origin = swap16(origin);

    /* we know the maximum file size so we only need one fread */
    uint16_t max_read = UINT16_MAX - origin;
    uint16_t *p = memory + origin;
    size_t read = fread(p, sizeof(uint16_t), max_read, file);

    /* swap file content to little endian */
    while (read-- > 0)
    {
        *p = swap16(*p);
        ++p;
    }
    fclose(file);
    return memory;
}
```

### 执行指令

执行指令前得解析指令格式，我们可以从前面的链接中拿到 ISA，根据上面的格式来进行解析。

#### ADD

例如 ADD 指令编码如下

```bash
 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
+--------------------+--------+--------+--------+
| 0| 0| 0| 1|   DR   |  SR1   | 0| 00  |  SR2   |
+--------------------------------------+--------+
| 0| 0| 0| 1|   DR   |  SR1   | 1|    imm5      |
+--------------------+--------+-----------------+
```

汇编格式

```c
ADD DR, SR1, SR2
ADD DR, SR1, imm5
```

描述

> If bit [5] is 0, the second source operand is obtained from SR2. If bit [5] is 1, the second source operand is obtained by sign-extending the imm5 ﬁeld to 16 bits. In both cases, the second source operand is added to the contents of SR1 and the result stored in DR. The condition codes are set, based on whether the result is negative, zero, or positive.

通过上面的资料可以知道 ADD 指令的编码的 12-15 bit 为 ADD 的 opcode 0001，9-11 bit 为目标寄存器 8-6 bit 为源寄存器 1。由指令的 `bit [5]` 第 5 个 bit 指定操作对象，一种操作对象为立即数，另一种操作对象是寄存器。

所以根据分析写出如下代码，通过位操作取出目标寄存器和源寄存器的下标，或者取出立即数，通过下标访问不同寄存器进行计算。最后根据运算结果更新条件寄存器。

```c
switch (op)
{
case OP_ADD:
    /* using {} to declare varible in labels */
    {
        uint16_t dr = (instr >> 9) & 0x7;
        uint16_t sr1 = (instr >> 6) & 0x7;
        uint16_t is_imm = (instr >> 5) & 0x1; /* check the op2 is sr2 or imm */

        if (is_imm)
        {
            uint16_t imm5 = sign_extend(instr & 0x1F, 5);
            curr_vm->regs[dr] = curr_vm->regs[sr1] + imm5;
        }
        else
        {
            uint16_t sr2 = instr & 0x7;
            curr_vm->regs[dr] = curr_vm->regs[sr1] + curr_vm->regs[sr2];
        }
        update_flags(dr, curr_vm->regs);
    }
    break;
    /* ... */
}
```

取出立即数时需要注意立即数的长度为 5 bit，但是寄存器的长度为 16 bit。例如在长度为 4 bit 内使用补码表示 -1，则 0-3 bit 存储着 `1111`，直接转换为长度到 16 bit 时则和 31 `0000000000001111` 相等，造成混乱。这就需要对立即数进行扩展。

```c
/* convert to 16 bit with sign */
uint16_t sign_extend(uint16_t num, int bit_count)
{
    if ((num >> (bit_count - 1)) & 1)
    {
        num |= (0XFFFF << bit_count);
    }
    return num;
}
```

在进行完运算后，要根据结果将条件寄存器进行更新，这就是 `update_flags` 函数。

```c
/* using regs[index] to update flags */
void update_flags(uint16_t index, uint16_t regs[])
{
    if (regs[index] == 0)
    {
        regs[R_COND] = FL_ZRO;
    }
    else if (regs[index] >> 15)
    {
        regs[R_COND] = FL_NEG;
    }
    else
    {
        regs[R_COND] = FL_POS;
    }
}
```

#### LD

同样我们可以解析并执行 LD 语句的 C 语言代码。

```c
 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
+--------------------+--------------------------+
| 0| 0| 1| 0|   DR   |        PCoffset9         |
+--------------------+--------------------------+
```

LD 语句就是从 PC + 相对偏移得到地址后，从地址中取出值并赋予 DR。当然 pc_offset 又是需要进行扩展的。

```c
case OP_LD:
{
    uint16_t dr = (instr >> 9) & 0x7;
    uint16_t pc_offset = sign_extend(instr & 0x1ff, 9);

    curr_vm->regs[dr] = mem_read(curr_vm->regs[R_PC] + pc_offset, curr_vm->memory);
    update_flags(dr, curr_vm->regs);
}
```

#### BR

而 BR 语句则是负责条件跳转，条件则为指令中的 9-11 bit 进行决定。例如指令中 N 位为 1，而且寄存器中的条件寄存器 N 也为 1，则跳转。N, P, Z 这三种条件可以自由组合，只要满足某一个条件就跳转。跳转表示为 PC 指针加上偏移值。

```c
case OP_BR:
{
    uint16_t n_flag = (instr >> 11) & 0x1;
    uint16_t z_flag = (instr >> 10) & 0x1;
    uint16_t p_flag = (instr >> 9) & 0x1;
    uint16_t pc_offset = sign_extend(instr & 0x1FF, 9);

    if ((n_flag && (curr_vm->regs[R_COND] & FL_NEG)) ||
        (z_flag && (curr_vm->regs[R_COND] & FL_ZRO)) ||
        (p_flag && (curr_vm->regs[R_COND] & FL_POS)))
    {

        curr_vm->regs[R_PC] += pc_offset;
    }
}
```

#### mem_read 函数

由于有内存映射的寄存器的存在，所以要将访问某些特殊地址时实际上是想访问某些寄存器，所以在读写特殊内存地址时要进行魔改。例如在访问 MR_KBSR 地址时候就需要将按键状态返回。

```c
uint16_t mem_read(uint16_t address, uint16_t *memory)
{
    /* reading the memory mapped keyboard register triggers a key check */
    if (address == MR_KBSR)
    {
        if (check_key())
        {
            memory[MR_KBSR] = (1 << 15);
            memory[MR_KBDR] = getchar();
        }
        else
        {
            memory[MR_KBSR] = 0;
        }
    }
    return memory[address];
}
```

`check_key` 函数用于将按键状态返回给程序。首先将 STDIN 绑定到集合中，然后通过 `select` 函数监视文件描述符的状态，如果有按键输入，则返回 1，否则返回 0；

```c
/* get keyboard status */
uint16_t check_key()
{
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    return select(1, &readfds, NULL, NULL, &timeout) != 0;
}
```

#### TRAP

在处理中断时使用函数来进行处理，降低代码耦合度。

```c
case OP_TRAP:
{
    running = execute_trap(curr_vm, instr, stdin, stdout);
}
break;
```

### Trap 翻译

将不同中断用 C 语言表示就行。由 ISA 可以知道 Trap 向量由 0-7 bit 表示。上面已经提及过了 Trap 的路径和功能，所以相关功能使用 C 语言表示如下。

```c
switch (instr & 0xFF)
{
case TRAP_GETC:
{
    uint16_t c = getc(in);
    curr_vm->regs[R_R0] = c;
}
break;
/* ... */
}
break;
```

## 虚拟机测试

通过位运算构造相应的指令，然后运行此指令，看看预期和结果是否相符。如果不相符就是挂了，返回 0；如果通过了那就返回 1。

```c
int test_add_1(vm_ctx *curr_vm)
{
    int pass = 1;
    uint16_t add_instr =
        ((OP_ADD & 0xf) << 12) |
        ((R_R0 & 0x7) << 9) |
        ((R_R1 & 0x7) << 6) |
        (R_R2 & 0x7);

    curr_vm->memory[0x3000] = add_instr;
    curr_vm->regs[R_R1] = 1;
    curr_vm->regs[R_R2] = 2;

    int result = execute_inst(curr_vm);
    if (result != 1)
    {
        printf("Expected return value to be 1, got %d\n", result);
        pass = 0;
    }

    if (curr_vm->regs[R_R0] != 3)
    {
        printf("Expected register 0 to contain 3, got %d\n", curr_vm->regs[R_R0]);
        pass = 0;
    }

    if (curr_vm->regs[R_COND] != FL_POS)
    {
        printf("Expected condition flags to be %d, got %d\n", FL_POS, curr_vm->regs[R_COND]);
        pass = 0;
    }

    return pass;
}
```

通过将不同测试函数用指针数组装起来，不断调用，通过返回值判断测试样例是否通过。

```c
int test_env()
{
    vm_ctx curr_vm;
    curr_vm.regs = malloc(sizeof(uint16_t) * R_COUNT);
    curr_vm.memory = malloc(UINT16_MAX * sizeof(uint16_t));
    int (*test_case[])(vm_ctx * curr_vm) = {test_add_1, test_add_2};

    int result = 1;
    int case_num = sizeof(test_case) / sizeof(uint16_t *);
    for (int i = 0; i < case_num; i++)
    {
        curr_vm.regs[R_PC] = 0x3000;
        memset(curr_vm.memory, 0, UINT16_MAX);
        memset(curr_vm.regs, 0, R_COUNT);
        result = test_case[i](&curr_vm);
        if (result == 0)
        {
            printf("Test %d fail!\n", i);
            free(curr_vm.memory);
            free(curr_vm.regs);
            return result;
        }

        else if (result == 1)
        {
            printf("Test %d passed!\n", i);
        }
    }
    free(curr_vm.memory);
    free(curr_vm.regs);
    return result;
}
```

原文中还有编译好的 2048 和 rouge，可以试着跑一下。

## 编译

使用 CMake 进行依赖处理，将测试程序和源程序分开，并且使用 `make test` 就可以跑测试了。

```cmake
if( POLICY CMP0048 )
  cmake_policy( SET CMP0048 NEW ) # CMake 3.0
endif()

project( lc3-vm VERSION 0.1 )
cmake_minimum_required( VERSION 2.6 )
set( CMAKE_C_STANDARD 99 )
add_library( read_image OBJECT lc3.h read_image.c )
add_library( exec_inst OBJECT lc3.h exec_inst.c )
add_executable( ${PROJECT_NAME} $<TARGET_OBJECTS:read_image> $<TARGET_OBJECTS:exec_inst> main.c )

add_executable( ${PROJECT_NAME}-test $<TARGET_OBJECTS:read_image> $<TARGET_OBJECTS:exec_inst> test.c )
enable_testing()
add_test(NAME ${PROJECT_NAME}-test COMMAND ./${PROJECT_NAME}-test )
SET_TESTS_PROPERTIES( ${PROJECT_NAME}-test PROPERTIES
  PASS_REGULAR_EXPRESSION "All test passed!"
  FAIL_REGULAR_EXPRESSION "Test [\\d]+ fail!"
)
```

## refs

原文 <https://justinmeiners.github.io/lc3-vm>
这个 C 实现的虚拟机封装比较完整 <https://github.com/rpendleton/lc3sim-c>
这个实现里加了测试样例 <https://github.com/viking/lc3-vm>
