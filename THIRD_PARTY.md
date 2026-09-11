# 第三方来源与许可证

本仓库**不分发**任何第三方源码。`agentdojo` 是经 PyPI 安装的依赖，其源码落在 `.cache/`
（已在 `.gitignore` 中），因此不随本仓库分发。

但本仓库**分发由 AgentDojo 派生的数据文件**，按 MIT 要求，其版权声明与许可证正文一并列在下方。

## 1. AgentDojo（派生数据）

- 包名与版本：`agentdojo` `0.1.35`
- 来源：PyPI wheel（`agentdojo-0.1.35-py3-none-any.whl`）
- 上游：<https://github.com/ethz-spylab/agentdojo>
- 许可：MIT License，Copyright (c) 2024 Edoardo Debenedetti, Jie Zhang, Mislav Balunovic,
  Luca Beurer-Kellner, Marc Fischer, and Florian Tramèr

### 本仓库中由它派生的文件

| 文件 | 派生内容 | 生成工具 |
|---|---|---|
| `data/agentdojo_corpus.json` | 230 条注入载荷（54 个官方目标 × 5 个官方模板组合而成） | `tools/build_agentdojo_corpus.py` |
| `data/agentdojo_bench.json` | 91 个工具定义、52 个用户任务、由基准自身的 `ground_truth()` 定义的危害集合 | `tools/build_agentdojo_bench.py` |

两个文件内部各自带有 `source` 字段，重复声明包名、版本、许可与上游 URL。
抽取方式与已知偏差记录在各文件的 `extraction.note` 中。

### 未被使用的部分

本工作**未运行** AgentDojo 的 agent 循环（那需要 LLM 与被测框架），
只抽取了静态的工具定义、任务文本、注入载荷与危害标注。因此本仓库不含其运行时行为。

### MIT 许可证正文

```
MIT License

Copyright (c) 2024 Edoardo Debenedetti, Jie Zhang, Mislav Balunovic, Luca Beurer-Kellner, Marc Fischer, and Florian Tramèr

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 2. 其他依赖

本仓库自身代码（`src/`、`experiments/`、`tools/`、`replication/`）的**非标准库依赖只有 `cryptography`**
（用于 Ed25519 签名与校验），其余全部为 Python 标准库。已核验：不含任何第三方项目源码的拷贝。

`tools/landscape_scan.py` 生成的 `results/landscape.md` 逐篇引用了 arXiv 论文的
「局限与未来工作」段原文，每段均以其 arXiv ID 与标题作为出处标注。**该文件是引用汇编，不是本工作的原创内容。**

## 3. 本仓库自身的许可证

**尚未指定。** 这是作者的选择，不由本文件代为决定。
在指定之前，本仓库的原创部分（代码与文档）默认保留全部权利。

## 4. 来源可核验的边界

- 可机械核验：本仓库代码与 AgentDojo 源码的 10-gram 重合为 **0**；除引用汇编外，
  本仓库文档与所扫描的 146 篇论文摘要的 10-gram 重合为 **0**。
- **不可核验**：本项目的**初始构想文档**（`agent-security-v2.md` v1 的 24 节提案）由用户提供，
  其来源不在本仓库内，其思想出处无法由此处查证。本仓库记录的是**由此之后**的工作。
