+++
title = "使用 Parser combinator 解析 METAR 报文"
date = 2023-05-21
[taxonomies]
tags = ["python", "plt"]
+++

# 使用 Parser combinator 解析 METAR 报文

因为我是骑自行车上下班的，对风向和风速很敏感，然后我住的离机场比较近，于是我想通过机场的天气状况判断下我的通勤是否容易。在翻阅资料后，发现机场的天气是使用 METAR 报文进行发送的，所以我将尝试用 Parser combinator 对报文进行解析，来获得天气状况。

本文采用的是 Python 进行编程，因为 Python 明显会比 Haskell 和 Rust 简单易读，Python 的缺点就是 lambda 函数很菜。

> 在写文章的时候发现我写的 parser 解析的信息不够完全，所以这个 parser 只供学习使用，请勿用于生产环境！

## 概念介绍

下面介绍转载自 Wikipedia。简单来说，parser combinator 就是一个高阶函数，接受多个 parser 作为输入，并将组合而成的新的 parser 作为输出。而 parser 则是接受一个字符串作为参数，然后将解析成功或失败的结果作为输出的函数。

> In computer programming, a parser combinator is a higher-order function that accepts several parsers as input and returns a new parser as its output. In this context, a parser is a function accepting strings as input and returning some structure as output, typically a parse tree or a set of indices representing locations in the string where parsing stopped successfully.

## 辅助函数

下面是最基本的框架，定义了语法分析器的输入，输出类型。

```python
from typing import NamedTuple, Callable, Any, Optional


class Stream(NamedTuple):
    src: str
    idx: int


class OutputValue(NamedTuple):
    stream: Stream
    value: Any

Result = OutputValue | None
Parser = Callable[[Stream], Result]
```

### Parser

下面的 parser 函数生成了一个解析单个字符的 parser。这个 parser 在字符匹配时，返回结果，否则将返回 None。

```python
def char(ch: str) -> Parser:
    """Consume a char"""

    def parser(s: Stream) -> Result:
        return (
            OutputValue(Stream(s.src, s.idx + 1), s.src[s.idx])
            if s.idx < len(s.src) and s.src[s.idx] == ch
            else None
        )

    return parser
```

运行效果如下，可以看到在解析成功时，返回了 `OutputValue` 参数，解析失败时返回了 None.

```python
>>> parse_a = char("a")
>>> parse_a(Stream("abcd", 0))
OutputValue(stream=Stream(src='abcd', idx=1), value='a')
>>> parse_a(Stream("bcd", 0))
>>> 
```

同理，我们可以写出解析一个 identifier 的 parser，这里省略。

```python
def identifier(ch: str) -> Parser:
    """Consume a identifier"""
    ...
```

### Combinator

下面的 combinator 函数可以将不同的 parser 组合起来。例如 `or_` parser combinator 是将 `p1` 或者 `p2` parser 组合起来，返回的新 parser 能在使用 `p1` parser 解析失败后使用 `p2` parser 进行解析。`and_` 类似。

`one_or_more` parser combinator 则是使用一个 parser 解析 1 到多次，实现代码也非常简单。先尝试用 `p` parser 解析 1 次，然后再解析到 `p` parser 解析不了为止，最后返回解析结果。同理可以写出 `zero_or_more` 和 `n_or_more`。

```python
def or_(p1: Parser, p2: Parser) -> Parser:
    def parser(input_: Stream) -> Result:
        return p1(input_) or p2(input_)

    return parser


def and_(p1: Parser, p2: Parser) -> Parser:
    def parser(input_: Stream) -> Result:
        if r := p1(input_):
            if r2 := p2(r.stream):
                return OutputValue(r2.stream, flatten([r.value, r2.value]))
        return None

    return parser


def one_or_more(p: Parser) -> Parser:
    """Use parser to consume one or more chars"""

    def parser(input_: Stream) -> Result:
        ret = []
        inp: Stream | None = None
        if curr := p(input_):
            inp = curr.stream
            ret.append(curr)
        else:
            return None
        while curr := p(inp):
            inp = curr.stream
            ret.append(curr)
        return OutputValue(inp, flatten([i.value for i in ret]))

    return parser


def zero_or_more(p: Parser) -> Parser:
    """Use parser to consume zero or more chars"""
    ...


def n_or_more(n: int, p: Parser) -> Parser:
    ...
```

下面的 combinator 函数则是组合更多个 parser。例如 `any_`，是通过多个 `or_` 将 parser 组合起来，达到满足其中一个 parser 能解析就返回解析结果的效果。

```python
def any_(*args: Parser) -> Parser:
    return reduce(or_, args)


def and_then(*args: Parser) -> Parser:
    """Consume chars with parser in args"""
    return reduce(and_, args)
```

下面的 combinator 函数则是辅助函数，`any_char` 是匹配 `ch` 中任意字符，而 `map_` 是将 parser 的输出结果传递给函数进行处理。

```python
def any_char(ch: str) -> Parser:
    def parser(input_: Stream):
        return any_(*map(char, ch))(input_)

    return parser


def map_(parser: Parser, fn: Callable) -> Parser:
    def p(input_: Stream):
        if out := parser(input_):
            return OutputValue(out.stream, fn(out.value))

    return p
```

## 解析报文

这里只讲部分报文片段的解析。

### 开头

METAR 报文的开头可以是 "METAR" 或者 "METAR/SPECI"，那么解析报文的 parser 如下。

```python
def metar_expr() -> Parser:
    metar = identifier("METAR")
    slash = char("/")
    speci = identifier("SPECI")
    return and_(metar, zero_or_more(and_(slash, speci)))
```

调用效果如下。

```python
>>> metar_expr()(Stream("METAR/SPECI", 0))
OutputValue(stream=Stream(src='METAR/SPECI', idx=11), value=['METAR', '/', 'SPECI'])
>>> metar_expr()(Stream("METAR", 0))
OutputValue(stream=Stream(src='METAR', idx=5), value=['METAR'])
>>> 
```

### 风

下面是我最关心的天气要素：风。风相关的报文类似 "10009G19KT"，前 3 个数字代表风向，后 2 个数字代表风速，如果这 5 个数字后面有 "G" 的话，则后面 2 个数字是阵风；最后是单位，单位有 MPS/KT/KMH。所以解析代码如下。

```python
class WindExpr(NamedTuple):
    direction: str
    speed: str
    unit: str
    g: Optional[str] = None


def wind_expr() -> Parser:
    digit = digit_expr()
    mps = identifier("MPS")
    kt = identifier("KT")
    kmh = identifier("KMH")
    g = and_then(char("G"), map_(n_or_more(2, digit), join))

    direc = map_(or_(n_or_more(3, digit), identifier("VRB")), join)
    speed = map_(n_or_more(2, digit), join)
    return map_(
        and_then(
            direc,
            speed,
            zero_or_more(g),
            any_(mps, kt, kmh),
        ),
        lambda v: WindExpr(v[0], v[1], v[-1], v[3] if v[2] == "G" else None),
    )
```

解析效果如下。

```python
>>> wind_expr()(Stream("10009G19KT", 0))
OutputValue(stream=Stream(src='10009G19KT', idx=10), value=WindExpr(direction='100', speed='09', unit='KT', g='19'))
>>> 
```

### 结合在一起

将多个 parser 结合在一起，即可解析整个报文。

```python
def full_expr() -> Parser:
    return one_or_more(
        and_then(
            any_(
                metar_expr(),
                identifier("CAVOK"),  # Put this before ICAO Parser
                trend_expr(),
                icao_expr(),
                time_expr(),
                wind_expr(),
                wind_vary_expr(),
                wind_shear_expr(),
                visibility_expr(),
                runway_expr(),
                weather_expr(),
                cloud_expr(),
                tmpr_expr(),
                pres_expr(),
            ),
            or_(char(" "), char("=")),
        )
    )
```

解析报文效果如下。

```python
>>> report = "METAR/SPECI ZUCK 221630Z 24002MPS 0600 R02L/1000U FZFG SCT010 M02/M02 Q1018 BECMG TL1700 0800 BECMG AT1800 3000 BR="
>>> metar_parser = full_expr()
>>> metar_parser(Stream(report, 0))
OutputValue(stream=Stream(src='METAR/SPECI ZUCK 221630Z 24002MPS 0600 R02L/1000U FZFG SCT010 M02/M02 Q1018 BECMG TL1700 0800 BECMG AT1800 3000 BR=', idx=115), value=['METAR', '/', 'SPECI', ' ', 'ZUCK', ' ', DateExpr(day='22', time='1630'), ' ', WindExpr(direction='240', speed='02', unit='MPS', g=None), ' ', VisibilityExpr(num='0600'), ' ', ('R', '02L', '/', '1000U'), ' ', 'FZFG', ' ', CloudExpr(desc='SCT', num='010', cb=None), ' ', TemperatureExpr(temperature='M02', dew='M02'), ' ', PressureExpr(unit='Q', num='1018'), ' ', 'BECMG', ' ', 'TL1700', ' ', VisibilityExpr(num='0800'), ' ', 'BECMG', ' ', 'AT1800', ' ', VisibilityExpr(num='3000'), ' ', ('BR',), '='])
```

### 碰到的问题

可能是因为二义性的问题，在解析 ICAO 片段时，会和解析 "CAVOK" identifier 冲突，所以将解析 "CAVOK" identifier 的优先级提前来解决。

```python
def test_failed_llk():
    """Because of the limit of LL(k), this case will failed."""
    p = and_then(or_(icao_expr(), identifier("CAVOK")), char(" "))
    assert p(Stream("CAVOK ", 0)) == None
    p = and_then(or_(identifier("CAVOK"), icao_expr()), char(" "))
    assert p(Stream("CAVOK ", 0)) != None
```

## 总结

Parser combinator 能让手动编写 parser 变得简单一些，并且能应付解析简单的语法的情况，所以花点时间来学习还是挺好的。

最后代码[在这](https://github.com/chenx6/gadget/tree/master/metar)。

## Refs

- [Building a tiny little broken calculator with parser combinators](https://blog.jfo.click/building-a-tiny-little-broken-calculator-with-parser-combinators/)
- [Learning Parser Combinators With Rust](https://bodil.lol/parser-combinators/)
- [This is how you read a METAR](https://metar-taf.com/explanation)
