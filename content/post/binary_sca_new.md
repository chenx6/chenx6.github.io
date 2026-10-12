+++
title = "恢复一个可执行文件中的函数名 -- 维新派方法（反编译+嵌入向量搜索）"
date = 2026-10-12
[taxonomies]
tags = ["re"]
+++

自从大模型横空出世以来，每隔几个月都会带来巨大进步，同时也带来了恢复函数名字的方法变革。因为大模型对代码的理解能力相对于传统方法有了提升，甚至可以使用自带的知识来恢复出被去除的函数信息。所以我直接开蹭，下面是我测试的通过反编译+嵌入（Embedding）向量搜索进行恢复函数名字的方法的记录。

这种方法有如下优势：

- 因为反编译器内部复杂的管道会对汇编进行分析，优化处理，最终会减小不同架构和不同编译等级带来的差异，所以使用反编译结果能带来巨大优势：跨架构和跨编译等级。
- 嵌入向量可以实现在大量的函数中间搜索到相似的函数。

> 因为新来公司的 "CTO" 想找一个熟悉 Agent 的人，来实现公司内部的“中台”化，所以本人也成为了大模型的受害者，成功享受了“无限期年假”了。如果有公司正在招人，欢迎联系！

## 主要思路

通过对已知开源库的二进制文件使用 IDA 进行反编译，然后将对应的函数进行索引，然后再将要被恢复的函数进行反编译，并将反编译结果在索引中使用嵌入向量进行搜索，找到最相似的函数，由人类或者大模型进行判别结果是否正确，即可实现恢复函数名字。

## 具体实现

### 使用模型

嵌入模型使用的是 "jinaai/jina-embeddings-v5-text-small-retrieval-GGUF", 在本机启动 llama.cpp 来提供嵌入 API。

### 数据结构设计

数据结构分为两块，faiss 存储的向量数据以及对应的索引，还有检索函数的原始信息，包括路径，声明，内容，指纹，划分的窗口。

```python
class FunctionRecord(TypedDict):
    path: str
    declaration: str
    content: str
    fingerprint: list[int]
    n_windows: int
```

### 建立索引

首先是从文件中提取不同的函数，并且对较大的函数按照函数长度进行切分来符合嵌入模型的输入大小，然后使用 faiss 进行向量存储，供后续检索。

```python
def embedding_preprocess(text: str):
    """
    Strip comment and remove whitespace
    """
    text = sub(r"//[^\n]*", "", text)
    return " ".join(text.split())


def index(repo_path: Path, index_folder: Path):
    funcs, window_texts = chunk_files(repo_path)
    vecs = embedding([embedding_preprocess(t) for t in window_texts])
    index = IndexFlatIP(vecs.shape[1])  # inner product on normalized vectors = cosine
    index.add(vecs)
    write_index(index, str(index_folder / "index.faiss"))
    with open(index_folder / "func.json", "w") as f:
        dump(funcs, f)
```

函数的切分用的是 tree-sitter query, 可以借助 tree-sitter 的威力，快速的获取到函数本体和函数定义。通过 `min_func_len` 变量过滤掉较小的函数，避免干扰。

```python
def chunk_files(
    repo_path: Path, min_func_len: int = 10
) -> tuple[list[FunctionRecord], list[str]]:
    c_lang = Language(language())
    parser = Parser(c_lang)
    query = Query(c_lang, "(function_definition declarator: (_)@decl)@fnc_def")
    cur = QueryCursor(query)
    funcs: list[FunctionRecord] = []
    window_texts: list[str] = []
    for file in repo_path.rglob("*.c"):
        file_content = file.read_bytes()
        tree = parser.parse(file_content)
        for _, caps in cur.matches(tree.root_node):
            # Get all functions
            func = caps["fnc_def"][0]
            if func.end_point[0] - func.start_point[0] < min_func_len:
                # Filter small function
                continue
            decl = caps["decl"][0]
            declaration = file_content[decl.start_byte : decl.end_byte].decode()
            # Normalize function name
            func_name = declaration.split("(")[0]
            content = (
                file_content[func.start_byte : func.end_byte]
                .decode()
                .replace(func_name, "sub_0")
            )
            windows = split_window(content)
            window_texts.extend(windows)
            funcs.append(
                {
                    "path": str(file),
                    "declaration": declaration,
                    "content": content,
                    "fingerprint": sorted(winnow(canonicalize(content))),
                    "n_windows": len(windows),
                }
            )
    return funcs, window_texts
```

### 查询

首先是从文件里读取要被恢复的函数，通过 faiss 的索引进行查询。

```python
def search(
    query: Path,
    index_folder: Path,
    top_k: int,
    lexical_weight: float = 3.0,
    candidate_factor: int = 10,
):
    query_text = query.read_text()
    query_embed_text = query_text
    # Generate vector and search
    query_vec = embedding([embedding_preprocess(query_embed_text)])
    index = read_index(str(index_folder / "index.faiss"))
    n_candidates = min(index.ntotal, max(top_k * candidate_factor, top_k))
    _, ids = index.search(query_vec, n_candidates)
```

然后对查询结果进行重排，包括选择当前窗口对应的函数的所有窗口，重新计算一遍余弦相似性，来找到最大值，这个做法是因为在函数较大的时候，可能出现函数和目标函数里的单个窗口相似性较小的情况，通过这么处理可以避免这种情况。然后是加入了 winnowing 算法来计算指纹，jaccard 算法来计算指纹的相似度，来提高 `n_candidates` 内有明显相似特征的函数的分数，避免部分通用函数的余弦相似性高于真实函数的情况。可以通过微调 `lexical_weight` 和 `candidate_factor`，来调整 winnowing+jaccard 算法的权重，达到更适合的工况。

```python
    # Rerank
    with open(index_folder / "func.json") as f:
        funcs: list[FunctionRecord] = load(f)
    #  offsets[function_index] => window index start
    #  offsets[function_index+1] => window index end
    offsets = [0]
    for f in funcs:
        offsets.append(offsets[-1] + f["n_windows"])
    candidate_funcs = {bisect_right(offsets, int(i)) - 1 for i in ids[0] if i >= 0}
    query_fp = winnow(canonicalize(query_text))
    reranked: list[tuple[float, float, float, int]] = []
    for k in candidate_funcs:
        # Take max cosine over all windows of the function
        best_cos = max(
            float(np.dot(index.reconstruct(r), query_vec[0]))
            for r in range(offsets[k], offsets[k + 1])
        )
        lexical = jaccard(query_fp, set(funcs[k]["fingerprint"]))
        combined = best_cos + lexical_weight * lexical
        reranked.append((combined, best_cos, lexical, k))
    reranked.sort(key=lambda item: item[0], reverse=True)
```

`winnow` 和 `jaccard` 函数是 winnowing 和 jaccard 算法的标准实现，请直接参考文末提及的代码仓库。

### 测试准备

我从 Debian 下载了 libcap, libcjson, libuuid, nanopb amd64 版本，自己编译了 mjs，将他们的 IDA 反编译结果作为索引的输入。然后从 GitHub 上下载了 flipperzero (arm 架构的设备)的 SDK，将里面的 firmware.elf 抽取出一些函数作为查询函数，来模拟真实的环境。然后还复制了个索引中没有的函数，作为反例。

### 测试结果

测试输出如下。可以看到在查询到相应函数的时候，余弦相似度和 Jaccard 相似度都较高，达到了 0.83 和 0.27，在查询不到函数的时候，余弦相似度和 Jaccard 相似度都不高，只有 0.57 和 0.12。我总共准备了 6 个函数，5 个函数是在索引输入有的，1 个函数在索引输入中没有的，5 个函数都找到其对应的原函数，平均余弦相似度为 0.81，1 个在索引输入中没有的函数余弦相似度为 0.57，结合 Jaccard 相似度判断没有找到对应的函数。通过设置合适的阈值，即可实现对可执行文件中函数名的恢复。并且索引输入函数和查询函数的架构和编译等级都不一样，证明该方法可以跨架构跨编译等级。

```bash
$ uv run --env-file .env main.py search -f test_search/mjs_struct_to_obj.c -i index/
  embedded 1/1
// 1. cosine=0.8386 jaccard=0.2794 mjs_struct_to_obj(_QWORD *a1, __int64 a2, _QWORD *a3)
unsigned __int64 __fastcall sub_0(_QWORD *a1, __int64 a2, _QWORD *a3)
$ uv run --env-file .env main.py search -f test_search/deflateInit2_.c -i index/
  embedded 1/1
// 1. cosine=0.5792 jaccard=0.1258 sub_4E30(__m128i *a1, __m128i *a2)
__int64 __fastcall sub_0(__m128i *a1, __m128i *a2)
```

## 总结

这篇文章讲了如何蹭大模型的热点，使用反编译+嵌入向量搜索来进行函数名字恢复。对于小函数的恢复，其实可以在上面的代码的基础上，加上对函数调用关系的记录，从而在恢复大函数的时候，通过函数调用关系，来恢复小函数的函数名字。本次索引的的库和函数数量都较少，如果要工程化的话，得对函数存储，向量存储选用更通用的方法。使用的大模型也是通用的大模型，如果能进行微调的话，能让嵌入搜索的效果更好。相对于上一篇讲的“传统派”方法来说，维新派的方法能恢复没有明显字符串特征的函数，但是需要一张强力的显卡，硬件要求更高。

完整代码在这：<https://github.com/chenx6/gadget/tree/master/bsca_new>

> 我灵机一动，突然想到：因为大模型对于 grep 的使用炉火纯青，所以可以直接让大模型去搜索相应的代码结构特征，然后借助大模型能力再做一个重排。缺点是要消耗的 Token（词元）数量会比较多，而且速度上会变得很慢。这个等我后续写文章了。
