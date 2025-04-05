+++
title = "CPU 微指令集测试初步探索"
date = 2025-04-05
description = "之前看了 Chips and cheese 这个博客，发现他们对 CPU 的测试方法很独特，不是像国内的 KOL 一样跑几个跑分软件然后拿分数进行对比，而是会测试像 CPU 的分支预测，乱序执行，内存读取延迟等指标。所以我也想学习一下这些测试的原理。"
[taxonomies]
tags = ["cpu"]
+++

之前看了 Chips and cheese 这个博客，发现他们对 CPU 的测试方法很独特，不是像国内的 KOL 一样跑几个跑分软件然后拿分数进行对比，而是会测试像 CPU 的分支预测，乱序执行，内存读取延迟等指标。所以我也想学习一下这些测试的原理。

## 指令重排序缓存(Reorder Buffer)

现代 CPU 会使用乱序执行来加快指令的执行速度。但是在程序员视角里，指令是顺序执行的。这时候就需要通过指令重排序缓存(Reorder Buffer)来记录下这些乱序执行的指令的顺序，执行完成的指令不会立即提交，而是先在缓存中等着，在所有指令都提交后才提交到寄存器中。

因为在缓存中的指令执行是并行的，所以可以通过填充一条需要长时间执行的指令来阻塞提交，并且观察在阻塞提交时候，还能执行多少条指令，来推算出指令重排序缓存大小。

在测试中，可以使用缓存未命中的读取内存指令当作需要长时间执行的指令。在两条这样的指令之间塞入一堆 NOP 指令，如果两条指令处于缓存中的话，这两条指令是并行执行的，反之则会串行执行。这时候就可以观察 NOP 指令的数量和指令的执行时间推算出指令重排序缓存大小。

运行 "Veedrac/microarchitecturometer" Repo 里的测试，可以看到生成了类似下面的测试代码，即通过在单个函数的两条读取内存指令中间，填充上不同数量的 NOP 指令，并计算出单个函数的执行时间，来计算出缓存的大小。

```c
__attribute__((noinline))
uint64_t time_rob_000002(void **list_0, void **list_1) {
    uint64_t start = get_nanos();

    uint64_t mem[1]; *mem = (uint64_t)mem;
    uint64_t r0 = 0, r1 = 0, r2 = 0, r3 = 0, r4 = 0, r5 = 0, r6 = 0, r7 = 0;
    _Pragma("nounroll")
    for (uint64_t i = 0; i < 10000; ++i) {
        list_0 = (void **)*list_0;
        asm volatile("""nop\n""nop\n" : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4), "+r"(r5), "+r"(r6), "+r"(list_0), "+r"(list_1) :: "cc");
        list_1 = (void **)*list_1;
        asm volatile("""nop\n""nop\n" : "+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3), "+r"(r4), "+r"(r5), "+r"(r6), "+r"(list_0), "+r"(list_1) :: "cc");
    }

    return get_nanos() - start;
}
```

下面是在我的笔记本 CPU "AMD Ryzen 7 PRO 4750U with Radeon Graphics" 上运行 "Veedrac/microarchitecturometer" 测试的结果，可以发现在 padding 为 220-224 的时候，时间(time taken 列)有一个明显的增幅，和 Wikichip 上记载的 ROB 大小为 224 吻合。

```txt
padding time taken      time taken (baseline)
200     1132683 1838407
202     1084975 1853388
204     1108399 1850021
206     1142985 1885061
208     1127969 1847312
210     1076971 1849623
212     1089703 1809988
214     1149620 1827609
216     1116124 1824020
218     1209005 1886430
220     1424102 1887275
222     1767155 1896801
224     1916405 1936087
226     1906684 1926581
228     1899979 1914918
230     1920952 1913612
232     1914101 1896864
234     1887261 1910685
236     1886835 1897932
238     1913479 1894720
240     1915728 1929277
```

## 返回地址栈(Return Address Stack)

现代 CPU 会通过分支预测来提升指令的执行速度，使用返回地址栈来进行返回地址的预测是一种特殊的分支预测。存储返回地址的返回地址栈的大小是有限制的，每一层函数调用都需要在栈中占用一个条目，如果调用层级过深，可能会导致超过大小限制，导致返回地址预测错误。

在测试中，可以通过编写不同的函数，并逐步增加函数调用的嵌套深度来进行测试。由于在发生返回地址预测错误的时候，函数的执行时间会变长，通过这个变化即可计算出返回地址分支预测的深度。

在 "clamchowder/Microbenchmarks" 的 "ReturnStackTest.cs" 中，会按照上面文字描述的流程，生成一堆的汇编来测试返回地址栈的大小，并在不同深度的测试外层加上了循环，来让测试更明显的观察到函数执行时间变动。

```asm
.global returnstack2
returnstack2:
  xor %rax, %rax
returnstack2_loop:
  call returnstack2_0
  dec %rdi
  jne returnstack2_loop
  ret
.global returnstack2_0
.align 128
returnstack2_0:
  add %rdi, %rax
  call returnstack2_1
.align 128
  ret
.global returnstack2_1
.align 128
returnstack2_1:
.align 128
  ret
```

因为我电脑上没有 C# 环境，所以我让 Deepseek 将对应的 C# 代码转换成了 Python 代码，来生成上面的汇编，并手写了下面的 C 代码来配合汇编进行测试。

```c
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>

extern void returnstack12(uint64_t loop_count);

long time_lapsed(struct timeval begin, struct timeval end) {
  long seconds = end.tv_sec - begin.tv_sec;
  long microseconds = end.tv_usec - begin.tv_usec;
  return seconds * 1000000 + microseconds;
}

int main() {
  struct timeval begin, end;

  gettimeofday(&begin, 0);
  returnstack12(1000);
  gettimeofday(&end, 0);
  printf("12 %ld\n", time_lapsed(begin, end));

  // 省略不同深度的调用

  return 0;
}
```

下面是测试结果，在调用深度为 28-33 的时候，每增加一层调用，测试函数的执行时间增幅约为 10 ms，但是在调用深度为 33-36 的时候，测试函数的执行时间增幅就变为了 40 ms。和 Wikichip 上介绍的 Zen2 架构有 "A 32-entry return address stack (RAS) predicts return addresses from a near call." 接近。

```txt
$ ./return_stack
28 271
29 297
30 287
31 302
32 312
33 316
34 362
35 422
36 436
```

> 使用 blog.stuffedcow.net 提供的 ret.c 测试出来的结果更加准确，部分输出如下
>
> ```txt
> ras_depth: A chain of calls and returns
> Depth,Min,Max,Clocks,Clocks2
> 省略一部分数据
> 28, 45.49, 48.10, 45.71, 45.71
> 29, 48.06, 50.62, 48.27, 48.27
> 30, 48.78, 52.51, 49.11, 49.11
> 31, 52.03, 55.05, 52.42, 52.42
> 32, 60.07, 63.08, 60.48, 60.48
> 33, 70.94, 73.58, 71.47, 71.47
> 34, 78.65, 81.23, 79.07, 79.07
> 35, 90.43, 94.01, 91.05, 91.05
> 36, 97.27, 100.23, 97.71, 97.71
> 37, 107.76, 110.55, 108.18, 108.18
> 38, 115.89, 118.62, 116.37, 116.37
> 39, 126.38, 129.32, 127.14, 127.14
> ```

## 分支历史表(Branch History Table)

在现代 CPU 的分支预测中，分支历史表是用来记录分支指令的历史行为，来预测分支语句是否跳转。分支历史表和分支目标缓冲区(Branch Target Buffer)是 CPU 分支预测单元的组成部分。

在 "clamchowder/Microbenchmarks" 的 "BranchHistoryTest.cs" 测试中，可以看到程序会生成一堆的跳转指令，每一个跳转的条件则是从程序生成的数组中读取出来，并通过改变数组的大小和内容，跳转语句的数量，来完整的测试 CPU 的分支预测能力。

```asm
branchhist2:              ; rdi iterations, rsi arr, rdx arrLen
  push %rbx
  push %r8
  push %r9
  xor %rbx, %rbx
  xor %r8, %r8
  xor %r9, %r9

branchhist2_loop:
  xor %r11, %r11          ; set index into arr of arrs to 0
  mov (%rsi,%r11,8), %r10 ; load array base pointer into r10
  inc %r11
  mov (%r10,%rbx,4), %eax ; read element from branch history test array
  test %eax, %eax
  jz branchhist2_zero0    ; conditional branch on test array value
  inc %r8
branchhist2_zero0:
  mov (%rsi,%r11,8), %r10
  inc %r11
  mov (%r10,%rbx,4), %eax
  test %eax, %eax
  jz branchhist2_zero1
  inc %r8
branchhist2_zero1:
  inc %rbx                ; loop around in pattern history test array if necessary
  cmp %rbx, %rdx
  cmove %r9, %rbx
  dec %rdi
  jnz branchhist2_loop
  mov %r8, %rax
  pop %r9
  pop %r8
  pop %rbx
  ret
```

## Refs

1. [Chips and Cheese](https://chipsandcheese.com/)
2. [Zen 2 - Microarchitectures - AMD](https://en.wikichip.org/wiki/amd/microarchitectures/zen_2)
3. [Veedrac/microarchitecturometer](https://github.com/Veedrac/microarchitecturometer)
4. [【计算机体系结构】重排序缓存ROB](https://zhuanlan.zhihu.com/p/501631371)
5. [Measuring Reorder Buffer Capacity](https://blog.stuffedcow.net/2013/05/measuring-rob-capacity/)
6. [Microbenchmarking Return Address Branch Prediction](https://blog.stuffedcow.net/2018/04/ras-microbenchmarks/)
7. [BranchHistoryTest.cs](https://github.com/clamchowder/Microbenchmarks/blob/master/AsmGen/tests/BranchHistoryTest.cs)
