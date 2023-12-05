+++
title = "类似 Rust 中的 enum (Sum type) 在 C 语言中的实现"
date = 2023-12-05
[taxonomies]
tags = ["c"]
+++

在 C 语言中，没有类似 ML 系语言或者 Rust 那样的 enum 实现。所以本文用于记录 C 中那些用于实现这个特性的相关方法，例如 tagged union, tagged pointer, NaN boxing。

## 在 Rust 中的表示

例如在之前的博客中，我使用了下面的代码来表示词法分析中分析的 Token。

```rust
pub enum Token {
    Number(i32),
    Operator(u8)
}
```

在 Rust 语言的底层的实现与下面的 Tagged union 类似。

## Tagged union

这个应该是最直接的表示方法，通过 `tag` 成员表示对象类型，并且通过 union 节省数据的占用空间。

```c
struct TaggedUnion {
    uint32_t tag;
    union {
        int number;
        char operator;
    };
};
```

## Tagged pointer

由于大部分系统分配的内存通常是以 8 字节对齐的，所以指针中存放的值中，即低 3 位(bit)为 0。这种情况下就可以通过低 3 位存储指针相关信息，可以表示 2 ^ 3 = 8 种不同的类型。

```c
union TaggedPointer {
    uint64_t as_uint64;
    void *as_pointer;
};
```

然后通过相关的宏来实现从 tagged pointer 中读取和存储数值。

```c
#define IS_INT(v) (v.as_uint64 & 0x1)
#define GET_AS_INT(v) ((int32_t)(v.as_uint64 >> 1))
#define MAKE_INT(i) (((uint64_t)(i) << 1) | 0x1)
```

## NaN boxing

在 IEEE 754 标准中，通过将指数位全部置为 1，并且将最少 1 个分数位置为 1 来表示 NaN，这种情况下 NaN 的值中，剩下 51 位为空，可以用来表示其他的值。可以通过指数位以及分数位前 2 位数值，将 NaN 与 double 数值，还有别的类型的数值进行区分开来。由于大部分系统地址空间只有 48 位，所以剩余的空间也足够存储一个内存地址。

在下面的例子中，我们通过自定义的 NaN 值将 double 数值和 NaN boxing 的数值进行区分。

```c
union NaNBoxing {
    uint64_t as_uint64;
    double as_double;
};

// NaN:
// 0 11111111111 1000000000000000000000000000000000000000000000000000
#define NANISH_MASK 0x7ffc000000000000
// 0 11111111111 1100000000000000000000000000000000000000000000000000
#define IS_DOUBLE(v) ((v.as_uint64 & NANISH) != NANISH)
#define GET_AS_DOUBLE(v) (v.as_double)
```

在使用 `IS_DOUBLE` 时，如果传入的值为 NaN 的话，与 NANISH_MASK 的值不相等。而传入 double 值时，由于 double 值中指数位必有 1 位为 0，所以运算后与 NANISH_MASK 不相等。

## 几种方法的对比

对比上面的几种表示方法，可以发现 tagged union 表示直接，但是在空间利用率上不如后面 2 种方法，会多出来一个 uint32_t 的内存占用。而 tagged pointer 的类型的转换稍微比 NaN boxing 麻烦一些，需要多做一些位运算。这几种方法都可以在现有的项目中找到使用痕迹。

## Refs

- [Modern C++真的很烂——std::variant](https://zhuanlan.zhihu.com/p/645810896)
- [Rust Binary Analysis, Feature by Feature](https://research.checkpoint.com/2023/rust-binary-analysis-feature-by-feature/)
- [NaN Boxing](https://craftinginterpreters.com/optimization.html#nan-boxing)
- [NaN boxing or how to make the world dynamic](https://piotrduperas.com/posts/nan-boxing)
- [Storing data in pointers](https://muxup.com/2023q4/storing-data-in-pointers)
