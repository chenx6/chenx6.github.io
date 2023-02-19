+++
title = "使用编译原理的知识，用 Rust 写一个计算器"
date = 2022-06-02
[taxonomies]
tags = ["plt", "rust"]
[extra]
katex = true
+++

”想写个计算器“这件事情应该是我刚学会 C 语言时候的事情，当时还看不懂栈，逆波兰式等结构。但是现在不一样了，我不仅学过数据结构，还学过了编译原理。这次我就拿学过的编译原理相关知识写个计算器。

## 前置知识

上下文无关语法(CFG)：描述了语句是如何形成的。

语句：从语法规则里推导出的一个符号串。

产生式：CFG 中每个规则都称为一个产生式。

非终结符：语法产生式中的变量

终结符：出现在语句中的单词，单词包含一个词素及语法范畴。在语法中，单词通过其语法范畴表示。

## 整体架构

整体流程就是 “词法分析 -> 语法分析 -> 解析语法树” 进行计算。

几个文件分布如下：

```plaintext
.
├── Cargo.lock
├── Cargo.toml
└── src
    ├── lexer.rs  # 手写词法分析
    ├── main.rs   # 程序入口，实现表达式计算
    └── parser.rs # 递归下降语法分析
```

## 词法分析

先定义好 Token。Rust 的枚举类型异常强大，写起来没什么问题。主要是括号，算数运算符，还有数字。

```rust
#[derive(Debug, PartialEq)]
pub enum OperatorType {
    Plus,
    Sub,
    Div,
    Mul,
}

#[derive(Debug, PartialEq)]
pub enum BracketType {
    Left,
    Right,
}

#[derive(Debug, PartialEq)]
pub enum Token {
    Number(i32),
    Operator(OperatorType),
    Bracket(BracketType),
}
```

然后是定义一个 `Scanner`。主要作用就是扫描用户输入，通过函数调用不断的返回用户输入字符串的一部分，还有就是向下一个字符前进。

```rust
struct Scanner {
    raw: String,
    pos: usize,
}

impl Scanner {
    fn new(s: &str) -> Scanner {
        Scanner {
            raw: String::from(s),
            pos: 0,
        }
    }

    fn peek(&mut self) -> Option<char> {
        self.raw.chars().nth(self.pos)
    }

    fn next(&mut self) -> Option<char> {
        self.pos += 1;
        self.raw.chars().nth(self.pos - 1)
    }
}
```

接下来就是词法分析本体。主要工作就是从 `Scanner` 读取和解析用户输入，并且在调用相应的函数时，返回相应的 Token。相当于一个手写的状态机。

```rust
/// A hand-written lexer
#[derive(Debug)]
pub struct Lexer {
    tokens: Vec<Token>,
    pos: usize,
}

impl Lexer {
    pub fn new(s: &str) -> Result<Lexer, LexerError> {
        let mut scanner = Scanner::new(s);
        let mut tokens = vec![];
        while let Some(ch) = scanner.peek() {
            match ch {
                // 省略一大堆代码
                _ => {}
            }
        }
        Ok(Lexer { tokens, pos: 0 })
    }

    pub fn next(&mut self) -> Option<&Token> {
        self.pos += 1;
        self.tokens.get(self.pos - 1)
    }

    pub fn peek(&mut self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }
}
```

下面是之前代码中省略的部分，即读取和解析用户输入字符，通过当前字符来来生成不同的 Token。例如解析数字 Token 这部分则是不断的读取是数字的字符到 `buf` 里，等到不是数字的字符时停止读取，并从 `buf` 里解析数字。还有就是在碰到空格时则跳过当前字符。

```rust
match ch {
    // Operator
    '+' | '-' | '*' | '/' => {
        let op = match ch {
            '+' => OperatorType::Plus,
            '-' => OperatorType::Sub,
            '*' => OperatorType::Mul,
            '/' => OperatorType::Div,
            _ => return Err(LexerError::LexError),
        };
        tokens.push(Token::Operator(op));
        scanner.next();
    }
    // Number
    '0'..='9' => {
        let mut buf = String::new();
        while let Some(ch) = scanner.peek() {
            if !('0'..='9').contains(&ch) {
                break;
            }
            buf.push(ch);
            scanner.next();
        }
        tokens.push(Token::Number(
            buf.parse::<i32>()
                .map_err(|_| LexerError::NumberFormatError)?,
        ))
    }
    // Bracket
    '(' | ')' => {
        let br = match ch {
            '(' => BracketType::Left,
            ')' => BracketType::Right,
            _ => return Err(LexerError::LexError),
        };
        tokens.push(Token::Bracket(br));
        scanner.next();
    }
    // Skip blank
    ' ' => {
        scanner.next();
    }
    _ => return Err(LexerError::UnknownChar),
}
```

## 语法分析

我们需要根据上下文无关文法来进行语法分析。下面是带优先级的算数表达式语法。可以看到这有 3 级别优先级，括号优先级最高，乘除第二，加减第三。为了给输入符号串推断出一个推导，我们选用自顶向下分析器，从语法树的根开始构造语法树。

```plaintext
Goal   -> Expr
Expr   -> Expr + Term
        | Expr - Term
        | Term
Term   -> Term * Factor
        | Term / Factor
        | Factor
Factor -> ( Expr )
        | number
```

> 如果是处理编程语言中的一元运算符，得按照下面的文法进行处理。一元运算符优先级比 Factor 优先级低，比乘除优先级高。
> 
> ```plaintext
> Goal   -> Expr
> Expr   -> Expr + Term
>         | Expr - Term
>         | Term
> Term   -> Term * Value
>         | Term / Value
>         | Value
> Value  -> || Factor
>         | Factor
> Factor -> ( Expr )
>         | number
> ```

### 左递归

这个文法的第二个产生式可以一直往 Expr 非终结符推导，不断的递归下去，不能正确解析语法。

```plaintext
Expr -> Expr
Expr -> Expr Expr
Expr -> Expr Expr Expr
...
```

导致这种问题的原因是因为产生了左递归。所以通过类似下面文法的做法，消除左递归（产生右递归）。

```plaintext
Fee -> Fee a  => Fee  -> b Fee'
     | b         Fee' -> a Fee'
                       | e
```

消除过左递归的文法如下：

```plaintext
E  -> T E'
E' -> + T E'
    | - T E'
    | ε
T  -> F T'
T' -> * F T'
    | / F T'
    | ε
F  -> ( E )
    | i
```

### 回溯

如果语法分析器用了错误的产生式扩展 AST 的下边缘节点，语法分析树的下边缘和词法分析器返回的 Token 会出现不匹配的情况，这时候就得回溯回之前的状态，重新选择新的产生式子。

例如在下面的产生式中，可能出现先选择了产生式 1，发现不匹配后又回退到 2。这种情况相比直接选择产生式 2 就浪费了时间。

```plaintext
1 Expr   -> Expr + Term
2         | Expr - Term
3         | Term
```

下面是为了避免回溯所需要的相关集合。

FIRST 集合：对于语法符号 $\alpha$ $，FIRST( \alpha)$ 是从 $\alpha$ 推导出的语句开头可能出现的终结符集合通过 FIRST 集前瞻一个符号来避免回溯，选择合适的语句，实现高效解析。

FOLLOW 集合：对于非终结符 $\alpha$，$FOLLOW(\alpha)$ 是在语句中紧接 $\alpha$ 出现的单词的集合。通过 FOLLOW 集判断能不能将非终结符推导为 ε，来区分当前输入为合法输入还是语法错误。

通过构造 FIRST+ 集，可以准确规定使得某个语法对自顶向下语法分析器无回溯条件。

$$
FIRST^{+}(A\to \beta) =
\begin{cases}
FIRST(\beta)                & \text 如果 \epsilon \notin FIRST(\beta) \cr
FIRST(\beta) \cup FOLLOW(A) & \text 剩余情况 \cr
\end{cases}
$$

### 代码实现

接下来就是编写递归下降语法分析器了。语法分析则是从 lexer 中不断的读取 Token，并使用递归下降进行解析。

```rust
/// A recursive descent parser
pub struct Parser {
    lexer: Lexer,
}

impl Parser {
    pub fn new(lexer: Lexer) -> Parser {
        Parser { lexer }
    }

    pub fn parse(&mut self) -> Result<Node, ParseError> {
        self.e()
    }
    // 省略
}
```

接下来是代码中最长的部分，按照文法编写递归下降解析器。对于每个非终结符，只需按照产生式依次调用相应的函数即可进行相应的分析。对于终结符，可以直接对 Token 进行处理。在编写程序时，可以将当前步骤产生的 AST 节点传递给下一个函数继续处理，从而实现完整的构造 AST。

在下面的代码可以看到处理 "E'" 非终结符的 `equote` 函数，对应的产生式是 "E' -> +TE'|-TE'|ε"。在函数中 match arm 有 3 个 arm。第一个 arm 处理当前 Token 为 "+" 和 "-" 的情况，在这种情况下，继续调用 `t`, `equote` 函数进行处理。第二个 arm 则是看下当前 Token 是否在 FIRST+ 集合里，如果在的话，则说明当前语句处理结束。如果前 2 个 arm 都没有匹配上，说明输入有问题，返回错误。

```rust
impl Parser {
    pub fn parse(&mut self) -> Result<Node, ParseError> {
        self.e()
    }

    // E -> TE'
    fn e(&mut self) -> Result<Node, ParseError> {
        let t = self.t()?;
        self.equote(t)
    }

    // E' -> +TE'|-TE'|ε
    fn equote(&mut self, val: Node) -> Result<Node, ParseError> {
        // Select sentence by looking for FIRST+
        match self.lexer.peek() {
            // E' -> +TE'|-TE'
            Some(&Token::Operator(ref op @ (OperatorType::Plus | OperatorType::Sub))) => {
                let op = op.clone(); // Get op from reference
                self.lexer.next();
                let t = self.t()?;
                self.equote(Node::BinaryExpr {
                    op,
                    lhs: Box::new(val),
                    rhs: Box::new(t),
                })
            }
            // E' -> ε
            Some(&Token::Bracket(BracketType::Right)) | None => Ok(val),
            _ => Err(ParseError::Unmatch),
        }
    }
```

## 运算

这里对 AST 进行了 DFS 来计算 AST 的值。后面有空的话，可以实现个虚拟机来处理。

```rust
/// Eval AST
fn eval(node: &Node) -> i32 {
    match node {
        Node::Number(n) => *n,
        Node::UnaryExpr { op, child } => {
            let child = eval(child);
            match op {
                OperatorType::Plus => child,
                OperatorType::Sub => -child,
                _ => child,
            }
        }
        Node::BinaryExpr { op, lhs, rhs } => {
            let lhs_ret = eval(lhs);
            let rhs_ret = eval(rhs);

            match op {
                OperatorType::Plus => lhs_ret + rhs_ret,
                OperatorType::Sub => lhs_ret - rhs_ret,
                OperatorType::Mul => lhs_ret * rhs_ret,
                OperatorType::Div => lhs_ret.checked_div(rhs_ret).unwrap_or(0),
            }
        }
    }
}
```

## 总结

最后放上代码 [代码在这](https://gist.github.com/chenx6/4534d36819562dc4eb6b0b32678ad4d0)。看下代码行数，可以看到只用了 300 行左右（带注视，空格）就完成了个基础的计算器。

> 这个项目还值 7000 USD，血赚 233

```plaintext
$ scc
───────────────────────────────────────────────────────────────────────────────
Language                 Files     Lines   Blanks  Comments     Code Complexity
───────────────────────────────────────────────────────────────────────────────
Rust                         3       334       28        24      282          3
TOML                         1         8        2         1        5          0
gitignore                    1         2        0         0        2          0
───────────────────────────────────────────────────────────────────────────────
Total                        5       344       30        25      289          3
───────────────────────────────────────────────────────────────────────────────
Estimated Cost to Develop (organic) $7,337
Estimated Schedule Effort (organic) 2.124802 months
Estimated People Required (organic) 0.306786
───────────────────────────────────────────────────────────────────────────────
Processed 9429 bytes, 0.009 megabytes (SI)
───────────────────────────────────────────────────────────────────────────────
```

## Refs

- 《编译器设计》第二版
- [语法分析：LL(1)分析](https://blog.csdn.net/kafmws/article/details/98319767)

> 知乎上的大佬们推荐的这本《编译器设计》比龙书更加通俗易懂，贴近现实，强烈推荐！
