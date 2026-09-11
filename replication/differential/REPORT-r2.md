# 第二轮差分测试报告

**被测两侧**

| 侧 | 位置 | 关系 |
|---|---|---|
| `mine` | `replication/mechanism.py` + `replication/patterns.py` | 本轮按更新后的 `spec/spec.md`（463 行）改写 |
| `ref` | `src/runtime.py` 等 | **黑盒调用**：只用 `System`/`src.model`/`src.crypto`/`src.patterns` 的公开 API。**全程未读 `src/` 源码** |
| `oracle` | `replication/differential/oracle.py` | 规格 §2.3/§2.8/§3.2 的直译判据，独立于上述两者 |

**防反推机制（与上一轮相同）**：场景输入只从规格条文构造，期望值写在独立的 `oracle.py`；装置中不存在任何形如 `if ref.decision == ...` 的反向拟合；分类依据是规格条文的字面措辞与 `oracle` 的三方交叉，不是"哪边是参考实现"。

**本轮规格变更（以 `spec/spec.md` 为准）落点**

| 变更 | 规格位置 | 我的实现落点 |
|---|---|---|
| §2.8 段不得为空（精确切分、不归一化；`matches`/`subsumes` 共用） | L149–155 | `patterns.py`：新增 `is_unconditional`/`is_degenerate`；`matches` 对退化资源只放行无条件模式；`subsumes` 对"无条件 child ⊆ 有约束 parent"恒返回假 |
| §2.3 verify 顺序：撤销 → 过期 → 密钥作废 | L62–65 | `mechanism.py:PEP.verify_token`：撤销判定前移到过期之前 |
| §3.2 双向窗口，默认 `max_request_age = 50` | L298–302 | `MAX_REQUEST_AGE = 50.0`；`_decide` 步骤 1c 改为 `0 ≤ now - ts ≤ MAX` |
| §5 凭证刷新语义（按链根解析；未刷新方旧令牌有效；已刷新方报 STALE；刷新须更新本级根令牌） | L352, L360–369 | `Authority.grant_history`/`grant_for_root_id`；`Token.root_grant_id`；`PEP.install_grant`/`resolve_grant`；`_decide` 步骤 4 改用**链根解析出的**授权 |
| §2.5 删除 `UNKNOWN_TASK` | L104–106 | 我的实现本就不产生它，无需改动 |

**装置文件**：`oracle.py`、`drivers.py`、`scenarios.py`、`run_diff.py`、`repro_r2.py`、`results.json`（本轮）、`results.prefix.json`（第一轮，用于对照）。

---

## 1. 剩余分歧（3 项，23 个用例）

| # | 场景 | 输入 | 我的输出 | 参考实现输出 | 类别 | 依据 |
|---|---|---|---|---|---|---|
| E1 | §2.3「撤销 → 过期 → 密钥作废」中"撤销"是否涵盖规则 6 | 令牌**未被** `revoke_token` 撤销、**已过期**、且其 `key_epoch` **已作废**（`revoke_key_epochs(A,1)`） | `TOKEN_EXPIRED` | `TOKEN_REVOKED` | **参考实现 bug**（若"撤销"被读作同时涵盖规则 5 与 6，则转为规格歧义） | §2.3 L62 明写「规则 4–6 的**触发优先级为 撤销 → 过期 → 密钥作废**」，三项分别对应规则 5、规则 4、规则 6。规格把"密钥作废"单列为第三个触发点，故它不可能同时属于第一个；按该顺序，`exp=1, key=1` 应命中"过期"。参考实现把规则 6 并入撤销检查（实测 `rev=0,exp=0,key=1` 也报 `TOKEN_REVOKED`）。**注意**：若把"撤销"读作"任何撤销类事实（规则 5 ∪ 规则 6）"，参考实现自洽，此时规格该句应当改写。 |
| E2 | §2.3 派生规则的**触发优先级** | 父令牌 `redelegatable=False`，且子范围 `order.write@orders/*` ⊄ 父范围 `order.read@orders/*` | `DENY SCOPE_VIOLATION` | `DENY NOT_REDELEGATABLE` | **规格歧义** | §2.3 派生规则 1–5 是编号列表，但**没有**像 verify 规则那样补一句顺序（verify 那句是上一轮差分后补的 L62）。我按编号顺序（规则 2 范围检查在规则 5 封条之前）；参考实现把封条前置。**两侧都拒绝，只是码不同**，不影响安全性。 |
| E3 | §3.1 派生者是否保留所授令牌的**副本** | A→B 授出 t；随后 A 用 t 向 **A 自己**发请求（issuer==from==A） | `DENY TOKEN_INVALID` | `ALLOW OK` | **规格歧义** | §3.1 L292 只写「`B_pep: verify(...) 成功则存入本地 token store`」，未规定派生者是否留副本。参考实现两侧都存（实测 `t in s.peps['A'].tokens == True`），我只存接收方。§2.3.1 的 `token_issuer(t)==req.from_id` 在两种读法下都可满足（接收方持有即可），故规格无强制；影响面限于"issuer 作为自身请求的 `to`"这类退化配置。 |
| E4 | §3.2 双向窗口与**时钟偏移** | `System.clock_skew = k > 0`，`ts = now + d`（`0 ≤ d ≤ k`） | `REPLAY` | `OK` | **规格歧义** | §3.2 L298–309 把窗口钉死为 `0 ≤ now - req.ts ≤ max_request_age`，**全文未出现 `clock_skew`**（只在 §3.3 的 P3 前置假设里提"时钟偏移有界"）。参考实现的窗口实测为 `-clock_skew ≤ now - req.ts ≤ max_request_age`（`clock_skew=5` 时 `now-ts=-5` 放行、`-6` 拒绝）。`clock_skew=0` 时两者重合，故只有显式设置偏移才暴露。 |

### 最小复现（`python3 replication/differential/repro_r2.py` 逐项打印）

**E1**
```python
import sys; sys.path.insert(0, "."); sys.path.insert(0, "replication/differential")
from drivers import RefDriver, MyDriver
for D in (RefDriver, MyDriver):
    d = D(); d.add_agent("A","c",["order.read@orders/*"]); d.add_agent("B","w",[])
    t = d.delegate("A","B",["order.read@orders/*"],"T1", ttl=5)   # 5 tick 后过期
    d.revoke_key_epoch("A", 1)                                    # 规则 6：密钥作废
    d.advance(50)                                                 # 跨过期 + 跨拉取周期
    r = d.force_request("A","B",t,"order.read","orders/1","T1","n", d.now)
    print(D.__name__, r.decision, r.reason_code)
# ref DENY TOKEN_REVOKED / mine DENY TOKEN_EXPIRED
```

**E2**
```python
d = RefDriver(); d.add_agent("A","c",["order.read@orders/*"])
for h in ("B","C"): d.add_agent(h,"w",[])
tid = d.delegate("A","B",["order.read@orders/*"],"T1", None, None, False)  # 封条
d.delegate("B","C",["order.write@orders/*"],"T1", None, tid, True)         # 越界
# ref: Deny NOT_REDELEGATABLE / mine: DerivationRejected SCOPE_VIOLATION
```

**E3**
```python
d = RefDriver(); d.add_agent("A","c",["order.read@orders/*"]); d.add_agent("B","w",[])
t = d.delegate("A","B",["order.read@orders/*"],"T1")
print(t in d.s.peps["A"].tokens)      # ref: True      （我的实现为 False）
r = d.force_request("A","A",t,"order.read","orders/1","T1","n", d.now)
# ref: ALLOW OK / mine: DENY TOKEN_INVALID
```

**E4**
```python
d = RefDriver(); d.add_agent("A","c",["order.read@orders/*"]); d.add_agent("B","w",[])
t = d.delegate("A","B",["order.read@orders/*"],"T1")
d.set_clock_skew(5)                    # 参考实现：System.clock_skew
r = d.force_request("A","B",t,"order.read","orders/1","T1","n", d.now + 5)
# ref: OK / mine: REPLAY        （我的实现按 §3.2 字面公式，无偏移项）
```

---

## 2. 已消除的分歧（对比 `results.prefix.json`）

| 第一轮分歧 | 第一轮计数 | 本轮计数 | 消除原因 |
|---|---:|---:|---|
| D1 §2.8 资源串空段（`a/*` vs `a/` 等） | 195 + 61（系统级） | **0 + 0** | 规格 L149–155 钉死"精确切分、不归一化、退化资源只有无条件模式匹配"；我按新规则改写 `patterns.py`，参考实现亦不再 `strip("/")` |
| D2 撤销 vs 过期的 `reason_code` | 9 | **0** | 规格 L62–65 钉死"撤销 → 过期 → 密钥作废"；我把撤销判定前移 |
| D3a `max_request_age` 常数 | 24 | **0** | 规格 L298 钉死默认 50 |
| D3b 未来 `ts` 放行 | 同上 24 中的一部分 | **0** | 规格 L299 钉死双向窗口 `0 ≤ now - ts ≤ max_request_age` |
| D4 非持有者派生抛裸 `KeyError` 逃逸 | 28 | **0** | 参考实现改为 `Deny TOKEN_INVALID`；我的实现抛出等价的 `Denied("TOKEN_INVALID")` |
| D5 权威重签发使在途令牌全部 `TOKEN_INVALID` | 1 | **0** | 规格 §5 L360–369 钉死"按链根解析授权；未刷新方旧根令牌仍有效；已刷新方报 `STALE_CREDENTIAL`；刷新须同时更新本级根令牌"；我照此重写 `PEP`/`Authority` |
| D6 §2.12 复合动作 `required` 未实现 | 32 | **0** | 上一轮已修，本轮回归通过 |

**逐族对照**（`cases` 为本轮用例数；`r1` 取自 `results.prefix.json`）

| 场景族 | 用例数 | 本轮分歧 | 第一轮分歧 |
|---|---:|---:|---:|
| F1a `matches` 穷举（80 模式 × 39 资源） | 3120 | 0 | 195 |
| F1b `subsumes` 穷举（80 × 80） | 6400 | 0 | 0 |
| F1c 系统级 `matches`（经真实令牌+请求路径） | 240 | 0 | 61 |
| F1d 系统级 `subsumes`（经 `delegate` 衰减检查） | 200 | 0 | 0 |
| F1e §2.8 健全性扫描（`subsumes ⇒ matches`） | 34905×2 三元组 | 0 反例（ref/mine/oracle 三方各 0） | 0 |
| F2 衰减链 | 60 | 0 | 28 |
| F3 判定顺序（多重违反叠加） | 50 | 0 | 9 |
| F4 重放与时效 | 79 | 0 | 24 |
| F5 撤销与凭证 | 54 | 0 | 1 |
| F6 复合动作 `required` | 65 | 0 | 32 |
| F7 任务绑定 | 44 | 0 | 0 |
| **F8 空段规则 + 自洽性（新）** | 113 | 0 | — |
| **F9 双向时效窗口（新）** | 78 | 0 | — |
| **F10 凭证刷新全序列（新）** | 44 | 0 | — |
| **F11 撤销/过期/密钥作废优先级矩阵（新）** | 38 | **1** | — |
| **F12 随机操作序列（新，240 条 × 50 步）** | 240 | **4** | — |
| **F13 窗口与 clock_skew（新）** | 88 | **18** | — |
| **合计** | **10913**（另有 69810 健全性三元组） | **23** | 350 |

### 新增族的覆盖说明

- **F8 空段规则**：`a` vs `a/`、`/a`、`a//`、`/a/`、`//a`；`a/*` vs `a/`；`*` vs `""`、`"/"`；`**` / `""` vs 全部退化串；`*/*` vs `a/`；另有 60 组随机组合与 20 组"无条件模式必须放行退化资源"的定向用例。**自洽性**由 F1e 的 34905×2 个三元组穷举：`subsumes(p,q) ∧ matches(p,r) ⇒ matches(q,r)`，ref/mine/oracle **三方各 0 反例**——即 `matches` 与 `subsumes` 确实共用同一套空段规则。
- **F9 双向窗口**：偏移 `0,1,25,49,50,51,60,100,300,1000,-1,-5,-49,-50,-100,-500,-10⁶` 共 17 个边界 + 60 组随机 + 一次"时钟推进后 ts 固定"的序列。**0 分歧**：两侧都在 `now-ts ∈ [0,50]` 放行、`=51` 或 `=-1` 拒绝。
- **F10 刷新全序列**：`A、B 都未刷新 → issue_grant → B 刷新 → A 也刷新` 的逐步判定（含 `refresh` 返回值、旧令牌在新旧两侧的码、新令牌是否放行）；另有"只刷新 A""只刷新 B""三跳链中 C 先刷新""刷新顺序 × 是否刷新"40 组随机。**0 分歧**，与 `repro_r2.py` 的 E6 输出一致。
- **F11 优先级矩阵**：`{revoked} × {expired} × {key_revoked}` 全 8 格 + 30 组"撤销+过期"叠加 task/scope 违规的随机用例。**仅 E1 一格分歧**；`revoked+expired → TOKEN_REVOKED`、`stale` 优先于 revoked/expired/task/scope 均两侧一致。
- **F12 随机操作序列**：240 条序列 × 50 步，随机混合 `add_agent / delegate / request / revoke_token / revoke_subject / revoke_key_epoch / issue_grant / refresh_grant / advance / set_partition`，逐步比对。**发现 5 类此前未编入用例的差异**，其中 4 类经查证是**我的装置或实现的缺陷**（见 §4），1 类归入 E3。
- **F13 窗口 + clock_skew**：4 个偏移值 × 7 个 ts 偏移 + 60 组随机。**18 处分歧**，全部落在 `-clock_skew ≤ now-ts < 0` 这一条带上（E4）。

---

## 3. 明确零分歧的场景族

除上表 0 分歧的各族外，下列**子场景在两侧完全一致**（均有实测输出）：

| 子场景 | 两侧一致的结果 |
|---|---|
| `revoked + expired` | `TOKEN_REVOKED`（规格 L62 钉死项） |
| `stale + revoked / expired / task / scope`（实测 4 组） | 两侧一律 `STALE_CREDENTIAL`（步骤 4 先于步骤 5–7） |
| 密钥作废的**主体粒度** | 撤销 A 的 key → 链上含 A 的令牌全拒；撤销 B 的 key → 只拒链上含 B 的令牌；撤销 C 的 key → 全放行 |
| 主体撤销对**后续投递**的效力 | 被撤销主体不得再接收新委托令牌（`TOKEN_REVOKED`）；但其作为 issuer 仍可向他人派生 |
| 主体撤销与**分区** | 分区中的主体不受撤销影响；恢复分区后下一次拉取即生效 |
| 新加入主体的撤销基线（实测 key / subject 两组） | 新 `add_agent` 的主体初始即带权威当前撤销状态，两侧均 `DENY TOKEN_REVOKED` |
| 空段自洽性 | `subsumes ⇒ matches`，34905×2 三元组 0 反例 |
| 越权派生三构造（异能力/放宽模式/超集） | 两侧各 0 次成功 |
| 复合动作 `required` 全在/部分在/全不在/空 | 两侧一致（全在放行，其余 `SCOPE_VIOLATION`，副作用 0） |
| 令牌 TTL 到期、撤销跨拉取周期、父令牌撤销后子令牌存活 | 两侧 tick 级一致 |

---

## 4. 本轮由 F12 随机序列查出并已修正的问题

| # | 现象 | 归属 | 修正 |
|---|---|---|---|
| A1 | 已刷新到新 epoch 的一方，`refresh_grant` 装入**更旧**的授权时参考实现返回 `False`（拒绝回滚），我无条件返回 `True` 并把本级根令牌回滚到旧根 | **我的实现 bug**（P2 回滚抵抗） | `PEP.install_grant`：`grant.cred_epoch < max_seen_cred` 时返回 `False`，不装入、不重建根令牌 |
| A2 | `set_partition([...])` 对**之后才 `add_agent`** 的主体是否生效 | **装置缺陷**（非协议分歧） | §2.12 把 `partitioned` 定义为 PEP 的属性，故只作用于已存在的 PEP；`MyDriver.set_partition` 改为逐 PEP 置位、`_pull` 改读 `p.partitioned` |
| A3 | 新加入主体的撤销基线 | **装置缺陷** | `MyDriver.add_agent` 用驱动侧当前撤销状态初始化新 PEP（`revoked_tokens` / `revoked_key_epochs` / `revoked_subjects`）；`set_partition` 不作用于新建主体 |
| A4 | `revoke_key_epoch` 作废上界被后来的小值覆盖 | **装置缺陷** | 改为 `max(旧值, 新值)`（规则 6 的语义是"上限"） |

A2–A4 是我上一轮驱动适配器的建模偏差，不是 `mechanism.py` 的协议逻辑问题；但在修掉它们之前，F12 的 240 条序列里绝大多数"分歧"都是假阳性——这也说明随机序列差分必须配合逐条归因，不能只看计数。

**验证**：修正 A1–A4 后，`F12` 在 60 条 × 40 步的规模上由 **54 → 0**；随后把规模扩到 240 条 × 50 步以增大搜索面，暴露 4 处分歧，逐条归因后全部落在 E1/E2/E3 三个已知分歧上。`replication/r1_run.py` 与 `replication/selfcheck.py` 仍通过（subsumption 反例 0、衰减不放大反例 0、非平凡性 True）。

---

## 5. 新规格文本仍不够清楚的地方

以下每一条都是我**在实现时不得不自行决定**的地方（不是"可以更好"，而是"照规格写不出来"）。按影响排序。

1. **§2.3「撤销 → 过期 → 密钥作废」中"撤销"的外延**（对应 E1）。
   规格把"密钥作废"单列为第三个触发点，故"撤销"应仅指规则 5；但反读（"撤销"= 任何撤销类事实）也通。**建议改为**：「规则 5（令牌撤销）→ 规则 4（过期）→ 规则 6（密钥作废）」并注明密钥作废的 `reason_code` 取 `TOKEN_REVOKED`。

2. **§2.3 派生规则的触发优先级**（对应 E2）。
   verify 规则有 L62 的顺序句，派生规则 1–5 没有。规格应补一句（我倾向"按编号顺序"，或明确"封条优先"）。

3. **§3.2 的窗口公式缺 `clock_skew`**（对应 E4）。
   规格钉死 `0 ≤ now - req.ts ≤ max_request_age`，但 §3.3 的 P3 前提是"时钟偏移有界"，参考实现的窗口带 `-clock_skew` 松弛。**建议改为**：`-clock_skew ≤ now - req.ts ≤ max_request_age`，并定义 `clock_skew` 的默认值与调参来源。

4. **§2.3 规则 6 的 `reason_code`**。
   §2.5 的清单里没有"密钥作废"专属码。我按参考实现取 `TOKEN_REVOKED`；规格应写明。

5. **§5"按令牌链根解析"的链根表示**。
   规格要求"必须按令牌**链根**解析出该链实际根植的那份授权"，但没有定义链根用什么键表示、验证方从哪里取（本地副本还是权威历史）。我加了 `Token.root_grant_id = H(根授权 body)` 字段并让权威保留 `grant_history`（§5 表的前置假设写了"权威保留授权历史"，但那是表格里的假设，不是正文规则）。**这是"离线验证"的必要输入，规格不写就无法实现。**

6. **§5"刷新"的失败语义**。
   规格说"已刷新方旧根令牌报 `STALE_CREDENTIAL`"，但没说**装入更旧授权的动作本身要拒绝**（实测参考实现 `refresh_grant` 返回 `False` 且不生效）。我按 P2 的单调性实现。需要写清 `refresh_grant` 的返回契约。

7. **§3.3 主体撤销的效力范围**。
   规格只给粒度优先级"令牌 > 边 > 主体 > 密钥"。没有定义：被撤销主体能否**再接收**新令牌（实测参考实现：不能）；能否**继续作为 issuer 派生**（实测：能）；撤销是否传播到该主体已授出的下游令牌（实测：不传播）。

8. **§3.3 撤销基线的获取时点**。
   实测参考实现：**已存在**的 PEP 要等下一次性拉取；**新加入**的 PEP 初始即带权威当前撤销状态。规格 §2.12 只说"`PEP.partitioned` 为真时停止拉取撤销状态"，没有定义新加入主体的初始基线。这直接影响 P3 的 `pull_interval + ttl` 上界推导。

9. **§2.8 空资源串的归类**。
   规格说"含空段者不匹配任何有约束的模式"。`""` 按 `/` 精确切分得到 `[""]`，是含空段的——但这需要读者自己推。**建议直接写明**"空资源串按一个空段处理"。（两侧实现恰好一致，属运气而非规格保证。）

10. **§2.8 越出语法的模式**。
    `**` 只能作末段，但规格没说违约形态（如 `**/**`、`a/**/b`）如何处置。我的实现把末段 `**` 当尾巴，于是 `**/**` 的语言退化为空集；实测与参考实现在 80×80 的 `subsumes` 表上仍完全一致，但这是**两个实现各自碰巧选到了同一个退化语义**，不是规格保证。

11. **§3.1 派生者是否保留令牌副本**（对应 E3）。
    §3.1 只规定接收方存库。若派生者不留副本，§2.3.1「只有把这份范围授予我的人，才能以这份范围来驱使我的 PEP」的**主语**在"驱使"动作中就必须另持令牌——规格未说明该令牌从何而来。

12. **§3.2 `RootGrant` 副本版本与链根的关系**。
    §3.2 前言说"接收方自行持有其信任的根授权副本"。当一个主体存在多份历史授权时（§5 的刷新场景），"副本"指**哪一份**未定义；我最终实现为"按链根解析 + 另存 `max_seen_cred` 判新旧"，但这是从 §5 反推的，不是 §3.2 的原文。

13. **§2.12 复合动作失败时与其它检查的顺序与码**。
    §2.12 说"整体拒绝（原子）"但未给 `reason_code`；§3.2 的步骤 7 也只覆盖单个 `capability`。我按参考实现取 `SCOPE_VIOLATION`，并把 `required` 检查放在步骤 7 之后。

14. **§3.2 步骤 4 在"链根解析失败"时的码**。
    解析不到该链根的授权时（例如令牌被人为改造），规格未定义报 `TOKEN_INVALID` 还是 `TOKEN_REVOKED`。我取 `TOKEN_INVALID`。

---

## 6. 一句话结论

上一轮 6 项分歧中的 6 项（D1–D6）**全部消除**，规格新增的 4 条规则（空段、判定顺序、双向窗口、凭证刷新）在我的实现与参考实现之间**逐条一致**（F8/F9/F10 共 235 个定向用例 0 分歧，F1e 健全性 0 反例）；剩余 23 处分歧收敛为 4 类，且全部落在**规格新文本仍未覆盖的缝隙**上——密钥作废与"撤销"的外延（E1）、派生拒绝的优先级（E2）、派生者是否留令牌副本（E3）、窗口缺 `clock_skew` 项（E4）。这 4 类中只有 E1 有明确文本可判（我判为参考实现 bug，附相反读法）。
