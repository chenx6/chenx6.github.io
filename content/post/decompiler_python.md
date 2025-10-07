+++
title = "实现一个不太能用的 Python 字节码反编译器"
date = 2025-10-07
[taxonomies]
tags = ["re"]
+++

写一个反编译器是我在大学的时候就有的一个想法，因为现有的反编译器支持的架构和语言很有限，能自己写反编译器就能支持更多语言了。结果发现这是一个大坑，公开的资料很少，而且需要手动处理很多很多的边界条件，在研究了好几个月之后，我才开始写这一篇文章，记录一个还没完成的反编译器实现。*代码质量不好，并且可能无法工作，敬请见谅。*

由于 Python 在不同版本之间，可能会调整字节码的生成逻辑，所以较难找到一个通用的规则去进行匹配，这篇文章里的内容只针对 Python 3.11 的字节码。

## 总体架构

Python 在执行程序的时候，会将 Python 代码转换成 Python 字节码，然后供 Python 解释器执行。Python 解释器是一个栈虚拟机，并且由于 Python 是一个动态类型语言，所以反编译器的大致架构如下。

- 反汇编 -- 从 .pyc 文件中提取出字节码。
- 控制流图(Control flow graph)恢复 -- 通过跳转语句等特征，对字节码进行分割，得到控制流图。
- 控制流(Control flow)构建 -- 通过不同控制流的特征（例如 if, while 语句的特征），来识别出控制流并进行构建。
- 反编译语句 -- 通过栈虚拟机的执行流程，反向推理出原本的代码。

## 具体实现

### 反汇编

通过 Python 的 dis 模块即可将 Python 代码转换成字节码的反汇编形式。也可以直接通过命令行调用 `python3.11 -m dis $code.py` 来进行转换。转换后的输出如下。

```txt
  1           0 RESUME                   0

  2           2 LOAD_FAST                0 (a)
              4 LOAD_FAST                1 (b)
              6 COMPARE_OP               4 (>)
             12 POP_JUMP_FORWARD_IF_FALSE     2 (to 18)

  3          14 LOAD_FAST                0 (a)
             16 RETURN_VALUE

  2     >>   18 LOAD_CONST               0 (None)
             20 RETURN_VALUE
```

或者通过 pycdc 中的 pycdas 程序来将 .pyc 文件转换成反汇编形式。

通过上面两个工具，我们得到反汇编形式的输出。将这些输出进行转换成对应的数据结构，会比自己写 .pyc 的解析器方便不少。

### 控制流图恢复

通过 `JUMP`/`RETURN` 语句将指令划分成一个个的基本块(Basic block)，`JUMP` 语句本身可以作为一个基本块的最后一条指令，其跳转的地址，也可以作为切割开基本块的标志。接下来则是遍历基本块，找到地址上相连，但是却断开的基本块，对其进行连接。

由于代码比较冗余，所以在文章里忽略。

### 控制流构建

这个是最复杂的一个地方了，我参考了 angr 里的 decompiler 实现，将构建分成了非循环控制流构建和循环控制流构建。通过拓扑排序，对控制流图进行遍历和识别控制流，在每次识别到一个控制流的时候，就将其中的几个基本块进行合并，合并成同一个节点并加入控制流图中，替换掉之前的节点。

在识别控制流的时候，可以使用 networkx + graphviz 将控制流图绘制出图片，来找到不同的控制流中，不同基本块之间的关系，来辅助编写控制流识别的条件。还有就是 angr 使用的是一个魔改过的拓扑排序，不太适合移植到我写的小 Demo 中，经过研究，我选择了直接使用 BFS，因为可以避开出现循环的情况，而且在输出上接近预期结果。

在识别非循环控制流的时候，通过不同控制流之间的特征，来区分和还原控制流。例如常见的 `if cond: ...; else: ...` 语句，特征是一个基本块有两个后继的基本块，而这两个基本块也只有一个后继基本块，如果识别到这个特征，则将这几个基本块从控制流图中删除，并将其合并成一个新的节点，加入新的控制流图中。样例代码如下。

```python
succs = list(graph.successors(node))
left_succs = list(graph.successors(left))
right_succs = list(graph.successors(right))
left_pred = list(graph.predecessors(left))
right_pred = list(graph.predecessors(right))
if (
    len(left_succs) == 1
    and left_succs == right_succs
    and len(left_pred) == 1
    and len(right_pred) == 1
):
    # match: if cond: ... else: ...
    # Rearrange graph for further matching
    # remove sucessor, connect node and sucessor's sucessor
    graph.remove_node(left)
    graph.remove_node(right)
    cg = IfElseNode(node.label, node, left, else_=right)
    for pred in graph.predecessors(node):
        graph.add_edge(pred, cg)
    graph.add_edge(cg, left_succs[0])
    graph.remove_node(node)
    return cg
```

在识别循环控制流的时候，需要识别出控制流里构成循环的基本块，这里 decompilation.wiki 列出了 3 种算法，我选择了 Havlak-Tarjan 算法，这个算法不止可以用来检测循环，而且也可以用于不同语言之间性能的检测，例如 [rsc/benchgraffiti](https://github.com/rsc/benchgraffiti)。Havlak 算法首先用 DFS 来分配每个节点的前序编号，然后通过编号对节点进行分类，分为有前序节点和无前序节点两种类型，接下来则是使用 worklist 算法来计算祖先节点。*这里我偷懒了一下，我的实现和原本的实现存在差别，等后面继续完善了。*

```python
def havlak(start_node, graph: nx.DiGraph):
    """
    Havlak-Tarjan
    ref: https://github.com/rsc/benchgraffiti/blob/master/havlak/havlak1.cc
    and https://decompilation.wiki/fundamentals/structuring/loop-reduction/
    """
    # 用 DFS 来分配前序编号
    visited = set()
    last_dic = {}
    dfs(graph, start_node, visited, last_dic, 0)
    # 通过编号来判断祖先关系
    back_preds = defaultdict(list)
    non_back_preds = defaultdict(list)
    for node in graph.nodes:
        for pred in graph.predecessors(node):
            if is_ancestor(node, pred, last_dic):
                back_preds[node].append(pred)
            else:
                non_back_preds[node].append(pred)
    # 用 worklist 算法来计算祖先
    loop_node: dict[Node, list[Node]] = {}
    for node in reversed(list(graph.nodes)):
        node_list = list(back_preds[node])
        worklist = list(node_list)
        while len(worklist):
            x = worklist.pop(0)
            for y in non_back_preds.get(x, []):
                if is_ancestor(node, y, last_dic):
                    worklist.append(y)
                    node_list.append(y)
        loop_node[node] = node_list
    return loop_node
```

### 反编译语句

Python 通过栈虚拟机来执行代码，所以在分析代码的时候可以模拟代码执行，创建一个表达式栈，并根据操作将变量放入放出栈中，从而实现恢复语句。

例如下面反汇编得到的结果，展示了 `value = a + b` 这个语句，我们可以通过模拟栈操作，来实现对代码的还原。

```txt
 20          36 LOAD_FAST                0 (a)
             38 LOAD_FAST                1 (b)
             40 BINARY_OP                0 (+)
             44 STORE_FAST               3 (value)
```

下面是还原语句的代码。

```python
def parse_block_stack(insts: DecompLines):
    stack: list[str] = []
    lines: list[str] = []
    for linenum, inst in insts:
        if inst.op.startswith("LOAD_"):
            stack.append(inst.args)
        elif inst.op.startswith("STORE_"):
            value = stack.pop()
            lines.append(f"{inst.args} = {value}")
    return lines
```

在上面的步骤中，我们还原出了控制流，即我们构建出了一个类似 AST 一样的树状结构，可以通过 BFS 或者 DFS 来不断遍历这棵树，来还原相应的语句，碰到叶子节点的时候，则使用上面讲的模拟栈方法，来还原相应的语句。

## 总结

这篇文章主要讲了反编译 Python 字节码的 4 个步骤以及细节。但是因为工程量大，很多细节没有完善，等待后续完善了。代码：<https://github.com/chenx6/gadget/tree/master/pydec>。

## Refs

- [Decompilation Wiki](https://decompilation.wiki)
- [vineflower/ARCHITECTURE.md](https://github.com/Vineflower/vineflower/blob/master/ARCHITECTURE.md)
- [zrax/pycdc](https://github.com/zrax/pycdc)
- [angr/angr/analyses/decompiler](https://github.com/angr/angr/tree/master/angr/analyses/decompiler)
