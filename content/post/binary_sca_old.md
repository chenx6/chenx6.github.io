+++
title = "恢复一个可执行文件中的函数名 -- 守旧派方法"
date = 2026-10-09
[taxonomies]
tags = ["re"]
+++

在逆向工程中，有时候对着一个开源库分析了半天，然后才发现这是一个开源库，会让人非常懊恼。所以我研究了一下多种恢复函数的方法，对比这些方法的性能，效果等方面。这篇文章先讲述传统方法：通过固定特征和函数之间的关系来恢复函数名字。

## 现有的恢复方法

- 通过固定特征，例如常量，字符串等特征。优点在于对于不同优化等级，架构产生的可执行文件中，这些特征变化不大。缺点在于有些开源库固定特征不明显，这时候没法检测。这个方法是 BDBA [^1] 正在使用的方法。
- 通过图相似性。优点在于市面上较多实现。缺点在于图神经网络的训练较为困难，并且对于不同优化等级的二进制文件识别不好，而且可扩展性未知。这个方法在学术界使用较多。
- 通过对反编译后的代码进行 RAG。优点在于借助大模型，可以对不同优化等级和架构的文件进行分析。缺点在于分析速度较慢，需要进行反编译，Embedding, 查找等步骤。这个方法是腾讯的 BinaryAI 正在使用的方法。
- 符号执行，向量搜索等等更新的方法。

在这篇文章里，我将尝试第一种“守旧派”方法。

## 主要思路

主要分为两部分，收集特征和检测特征。收集特征使用二进制分析工具，提取特征和函数之间的关系，并存入数据库进行后续查询。检测特征也是先提取特征和函数之间的关系，然后去查找提取出来的特征。

这个思路和逆向工程中的思路类似，例如我知道 curl 开源库的 "tool_help" 函数使用了 "Usage: curl [options...] <url>" 字符串，那么我在逆向别的文件中看到 "Usage: curl [options...] <url>" 字符串的时候，就可以考虑这个函数是不是 curl 开源库中的 "tool_help" 函数了，如果别的开源库都没有这个字符串，那说明这个函数很大概率就是 "tool_help" 函数。

## 具体实现

### 数据库设计

特征 <1=N> (开源库, 版本, 函数)。特征为字符串经过 xxhash 得到的值。

```sql
CREATE TABLE IF NOT EXISTS info (
    id INTEGER PRIMARY KEY,
    library TEXT,
    version TEXT,
    function TEXT,
    offset INTEGER,
    callrefs TEXT,
    UNIQUE(library, version, function)
);
CREATE TABLE IF NOT EXISTS hash_info (
    hash INTEGER,
    info_id INTEGER,
    UNIQUE(info_id, hash)
);
```

### 提取特征和函数之间的关系

这里使用了 rizin 这个分析工具，使用 "aaa" 命令进行分析，然后使用 "afl" 命令获取函数的名字，偏移等信息，并将函数和数据的引用关系信息存储。在后面获取函数中字符串常量，通过之前的引用关系，查找字符串和函数的关系。这里将字符串使用 xxhash 进行哈希，并在数据库中做了索引，来降低查找字符串特征的时间。录入文件的时候可以下载他的 debuginfo, rizin 会在分析的时候自动加载 debuginfo，来完善函数名字信息，函数名字会带有 "dbg." 开头。

```python
def analysis(file: str) -> tuple[list[Function], list[StringAnalyseResult]] | None:
    with rzopen(file) as p:
        p.cmd("aaa")
        # Functions
        res = p.cmdj("aflj")
        if not res:
            return
        funcs = [
            Function(i["name"], i["offset"], i["size"], i.get("callrefs", []))
            for i in res
        ]
        data_to_funcs: dict[int, list[int]] = defaultdict(list)
        for func_idx, i in enumerate(res):
            # Process dataref to get data => functions index
            for ref in i.get("datarefs") or []:
                data_to_funcs[ref["to"]].append(func_idx)
        # Strings
        res = p.cmdj("izj")
        if not res:
            return
        strings: list[StringAnalyseResult] = []
        for v in res:
            for func_idx in data_to_funcs.get(v["vaddr"], ()):
                s = v["string"]
                strings.append((func_idx, s, xxh3_signed(s.encode())))
        return (funcs, strings)
```

### 查找提取出来的特征

在查找特征的时候，我们将被检测文件中的所有特征和数据库中的特征进行对比，统计特征在哪些开源库中出现过，然后和开源库的所有特征数量进行对比，如果重合度超过了阈值，则说明被检测文件用了这个开源库。0.4 这个阈值是经验参数，降低会同时提高误报率和检出率，个人建议最低也得是 0.2。

```python
def query_library(
    conn: "Connection", funcs: list[Function], strings: list[StringAnalyseResult]
):
    cnt: Counter[tuple[str, str]] = Counter()
    for h in {i for _, _, i in strings}:
        # Calculate (library,version) match count
        cur = conn.execute(
            """
            SELECT library, version
            FROM info, hash_info
            WHERE hash = ? AND info.id = hash_info.info_id
            """,
            (h,),
        )
        res = cur.fetchall()
        for r in res:
            cnt[r] += 1
    for info, count in cnt.items():
        # Get all hash count for current library and version
        cur = conn.execute(
            """
            SELECT COUNT(hash)
            FROM info, hash_info
            WHERE library = ? AND version = ? AND info.id = hash_info.info_id
            """,
            info,
        )
        res = cur.fetchone()
        total = res[0]
        # Check confidence
        confidence = count / total
        if confidence < 0.4:
            continue
        print(info, confidence, count, total)
        recover_funcname(conn, info, funcs, strings)
```

在知道了被检测文件用了哪些开源库的情况下，我们可以根据数据库中开源库函数和特征的关系，来还原出被检测文件中函数和特征的关系。先确认开源库，再确认函数这种做法，能降低某些字符串出现在多个不同的开源库的不同函数中，导致错误检测的情况。如果出现一个提取出来的字符串对应多个函数的情况，我们直接忽略，不将这个字符串作为识别特征。

```python
def recover_funcname(
    conn: "Connection",
    info: tuple[str, str],
    funcs: list[Function],
    strings: list[StringAnalyseResult],
):
    matched = set()
    for func_idx, string, h in strings:
        # Recover function name by using string match
        if h in matched:
            continue
        matched.add(h)
        cur = conn.execute(
            """
            SELECT function
            FROM info, hash_info
            WHERE library = ? AND version = ? AND hash = ? AND info.id = hash_info.info_id
            """,
            (
                info[0],
                info[1],
                h,
            ),
        )
        res = cur.fetchall()
        if not res or len(res) > 1:
            # If current hash mapped to multiple function, ignore it
            continue
        orig_func_name = res[0][0]
        print(funcs[func_idx].name, "=>", orig_func_name, string.encode())
```

> 完整代码请查看文章末尾的链接

## 效果

我从 Debian 上下载了 bash, curl, libcrypto 和其对应的符号文件，arm64 架构的，来作为输入文件，总共录入了 6463 条特征。并对我电脑上 OpenSUSE x86_64 发行版中的不同版本 curl 进行了检测，成功检测出了 curl 开源软件，并且成功地将 46 个函数的名字进行了恢复，抽取前 5 个函数进行人工校验，3 个函数识别正确，1 个函数（dbg.read_field_headers）由于内联导致识别错误，1 个函数由于版本变化（录入特征的版本为 8.14.1，/usr/bin/curl 为 8.19.0）导致特征发生变化，产生识别错误。并且对无关的二进制文件进行检测，没有产生误报。

部分输出如下：

```txt
$ uv run recover.py detect /usr/bin/curl
('curl', '8.14.1') 0.889090909090909 489 550
fcn.0000de00 => dbg.get_param_word b'Trailing data after quoted form parameter'
fcn.0000fd10 => dbg.read_field_headers b'Out of memory for field headers'
fcn.0000fd10 => dbg.get_param_part b'Out of memory for field header'
fcn.0000fd10 => dbg.get_param_part b'Field filename not allowed here: %s'
fcn.0000fd10 => dbg.get_param_part b'Field encoder not allowed here: %s'
fcn.00010980 => dbg.formparse b'error while reading standard input'
fcn.00010980 => dbg.formparse b'garbage at end of field specification: %s'
fcn.00010980 => dbg.formparse b'Illegally formatted input field'
fcn.00012190 => dbg.getparameter b"The filename argument '%s' looks like a flag."
fcn.00012190 => fcn.00013ac0 b'--trace overrides an earlier trace/verbose option'
fcn.00012190 => fcn.00013ac0 b'--trace-ascii overrides an earlier trace/verbose option'
fcn.00012cc0 => dbg.ipfs_url_rewrite b'IPFS automatic gateway detection failed'
fcn.00012cc0 => dbg.ipfs_url_rewrite b'--ipfs-gateway was given a malformed URL'
fcn.00013650 => dbg.config2setopts b'ignoring %s, not supported by libcurl with %s'
fcn.000137e0 => dbg.config2setopts b'CURLOPT_SSL_SIGNATURE_ALGORITHMS'
...
$ uv run recover.py detect /usr/bin/zstd
ERROR: Cannot peek memory without specifying an address (esil address: 0x0009d718)
# 前面是 rizin 的无关报错，可以直接忽略
$ uv run recover.py detect /usr/bin/objcopy
$
```

## 总结

这种方法和业界的 SOTA BDBA 正在使用的方法类似，BDBA 通过比较数据库中的特征和被检测文件中特征的重合度，来判断被检测文件是否用了开源项目。我在此基础上，加入函数和特征的关系分析，来实现恢复函数名字。如果只是检测程序中是否使用了开源库，可以将提取特征和函数之间的关系改成直接提取特征，降低分析程序带来的时间复杂度。对于版本识别，可以使用简单的正则表达式，提取出开源库的版本，使用更靠近的开源库版本特征，来实现更好的恢复函数和特征的关系。这个代码在后期还可以继续做出性能优化，包括降低分析的等级，对数据库进行优化，并发搜索等优化方法来减少分析的时间。

在下一篇文章中，我将会探索深度学习，大模型等“维新派方法”来进行函数名恢复。

完整代码在这：<https://github.com/chenx6/gadget/tree/master/bsca_old>

## Refs

[^1]: [Black Duck Binary Analysis](https://www.blackduck.com/software-composition-analysis-tools/binary-analysis.html)
