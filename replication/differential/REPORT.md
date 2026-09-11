# 差分测试报告：独立实现 vs 参考实现

**被测两侧**

| 侧 | 位置 | 关系 |
|---|---|---|
| `mine`（我上一轮的独立实现） | `replication/mechanism.py` + `replication/patterns.py` | 只依据 `spec/spec.md` 写成，未读参考实现 |
| `ref`（参考实现） | `src/runtime.py` 等 | **黑盒调用**：只使用 `System` 公开方法、`src.model` 公开 dataclass、`src.crypto` 公开原语、`src.patterns` 公开谓词。未读取任何 `src/` 源码内容 |
| `oracle`（第三方裁决） | `replication/differential/oracle.py` | 规格 §2.8/§3.2 的直译判据，独立于上述两者写成 |

**防止"从参考实现反推场景"的机制**：场景输入在 `scenarios.py` 里从规格条文构造（§2.8 语法穷举、§2.3 派生规则、§3.2 判定顺序表、§2.12 复合动作与分区），期望值写在 `oracle.py`；两侧实现只在运行时被调用，装置代码中不存在任何形如 `if ref.decision == ...` 的反向拟合。分歧的类别判定以 `oracle` 与规格条文的字面措辞为依据，不以"哪边是参考实现"为依据。

**装置**（均在本目录，可独立运行）

| 文件 | 作用 |
|---|---|
| `oracle.py` | 规格直译判据（模式语言 + 判定顺序） |
| `drivers.py` | 两侧实现的对称门面（`RefDriver` / `MyDriver`） |
| `scenarios.py` | 7 个场景族的用例生成（固定种子 `20240911`） |
| `run_diff.py` | 跑全部用例 → `results.json` |
| `repro.py` | 每处分歧的最小复现 + 两个否定性探测 |
| `results.prefix.json` | **修复我方 bug 之前**的结果（用于对照） |

---

## 1. 分歧表

类别含义：**A** = 规格歧义（规格允许两种读法）；**B** = 参考实现 bug；**C** = 我的实现 bug。

| # | 场景 | 输入 | 我的输出 | 参考实现输出 | 类别 | 依据 |
|---|---|---|---|---|---|---|
| D1 | §2.8 资源串中的空段 | 令牌范围 `order.read@a/*`，请求资源 `a/` | `ALLOW` | `DENY SCOPE_VIOLATION` | **A** | §2.8 只定义了 `PATTERN` 的语法，**从未定义资源串的分段规则**。两读法都自洽：我方把 `a/` 切成 `['a','']`（空段是普通一段，`*` 可匹配）；参考实现把资源串去掉首尾 `/` 再切段（实测 3120 格全中，见 §2.3）。 |
| D2 | §3.2 步骤 5 内部顺序 | 令牌同时**已过期**且**已被撤销** | `TOKEN_EXPIRED` | `TOKEN_REVOKED` | **A** | §2.3 `verify` 的编号规则 4（时窗）排在规则 5（撤销）之前，§3.2 步骤 5 也写作 "TOKEN_INVALID/EXPIRED/REVOKED"；但该串可能只是枚举而非优先级。**规格未钉死**。若按编号读作优先级，则参考实现偏序错。 |
| D3a | §3.2 步骤 1c 的常数 | `max_request_age` 的取值 | `300` | `50` | **A** | §3.2 步骤 1c 使用 `max_request_age` 但**从未给出数值**，也未给出标定方法。两实现各自拍定。 |
| D3b | §3.2 步骤 1c 的负半轴 | `ts = now + 500` | `ALLOW` | `DENY REPLAY` | **A**（含我方缺陷） | 规格只写 `now - req.ts ≤ max_request_age`；未来 ts 使差为负，字面读法放行（我方照做）。规格未定义负半轴。**但该读法可被利用**：发送方只要把 `ts` 写大，请求就永不过窗，步骤 1c 形同虚设。实测参考实现的规则是 `ts ≤ now + clock_skew`：默认 `clock_skew = 0` 时 `ts = now + 6` 与 `ts = now + 500` 均判 `REPLAY`；把 `System.clock_skew` 置为 1000 后，`ts = now + 500` 变为 `OK`、`ts = now + 2000` 仍为 `REPLAY`。**建议规格改为区间检查**，届时我方也须改。 |
| D4 | §2.3 派生规则 1（非持有者派生） | C 持 `token_id` 但令牌持有者是 B，C 调用派生 | `Denied: TOKEN_INVALID` | `KeyError: 'a6742c6d…'`（**未捕获异常逃逸出 API**） | **B** | §2.3 规则 1 要求"派生者必须持有父令牌"；§2.5 的 `reason_code` 全集里没有 `KeyError` 这种形态。拒绝本身两侧一致，但参考实现以未捕获异常终止调用者，调用方无法用 `reason_code` 分支处理。`src.model.Deny` 已存在且被用于其它派生拒绝（`NOT_REDELEGATABLE` 走的是 `Deny`），此处不一致。 |
| D5 | §2.3.1 根授权重签发 | 权威对 A 调用 `issue_grant` 后，A→B 的在途令牌再请求 | `ALLOW OK` | `DENY TOKEN_INVALID` | **A** | §3.2 前言规定接收方持有"自己信任的根授权副本"并使用它判定，§2.3 `verify` 只要求该副本签名验通且 `grant.subject_id == token.root_subject_id`——**没有任何一条说"权威重签发会使在途令牌失效"**。参考实现把令牌锚定到 `root_token_id(grant)`，重签发即换锚（实测：`issue_grant` 之后连**新发起**的派生也报 `链断裂`），我方保留旧锚。两种读法都通，但参考读法有一个可实现性后果：一次常规凭证轮换会静默作废该主体全部在途令牌——这更像 bug 而非设计。 |
| D6 | §2.12 复合动作 `required` | 令牌范围 `order.read@orders/*`，请求 `(order.read, orders/1)` 且 `required = ("db.export@x/y",)` | **`ALLOW OK`，副作用执行 1 次** | `DENY SCOPE_VIOLATION`，副作用 0 次 | **C** | §2.12 明确要求 `{capability@resource} ∪ required` **全部**落在同一令牌范围内，否则整体拒绝（原子）。我方 `mechanism.py` 的 `ActionRequest` **根本没有 `required` 字段**，`_decide` 也不检查——即该条完全未实现。**已修复**（见 §4）。 |

---

## 2. 每处分歧的最小复现

`python3 replication/differential/repro.py` 一次跑完全部；以下为各自的独立片段。

### D1 —— 资源串空段

```python
import sys; sys.path.insert(0, "."); sys.path.insert(0, "replication")
import src.patterns  # 参考实现
import patterns      # 我的实现
print(src.patterns.matches("a/*", "a/"), patterns.matches("a/*", "a/"))   # True False
print(src.patterns.matches("*/a", "/a"), patterns.matches("*/a", "/a"))   # True False
print(src.patterns.matches("a",   "a/"), patterns.matches("a",   "a/"))   # True False
```

### D2 —— 撤销 vs 过期

```python
import sys; sys.path.insert(0, "."); sys.path.insert(0, "replication/differential")
from drivers import RefDriver, MyDriver
for D in (RefDriver, MyDriver):
    d = D(); d.add_agent("A", "c", ["order.read@orders/*"]); d.add_agent("B", "w", [])
    tid = d.delegate("A", "B", ["order.read@orders/*"], "T1", ttl=5)
    d.revoke_token(tid); d.advance(50)
    r = d.force_request("A", "B", tid, "order.read", "orders/1", "T1", "n", d.now)
    print(D.__name__, r.decision, r.reason_code)
# ref DENY TOKEN_REVOKED / mine DENY TOKEN_EXPIRED
```

### D3 —— 时窗常数与未来 ts

```python
for age in (50, 51, 300, 301): ...   # 落后 51/300 时 ref=REPLAY, mine=OK；301 时两侧都 REPLAY
force_request(..., ts=d.now + 500)   # ref=REPLAY, mine=OK
```

### D4 —— 非持有者派生

```python
d = RefDriver(); d.add_agent("A","c",["order.read@orders/*"])
for s in ("B","C"): d.add_agent(s,"w",[])
tid = d.delegate("A","B",["order.read@orders/*"],"T1")
d.delegate("C","A",["order.read@orders/*"],"T1",None,tid)
# KeyError: 'a6742c6df9e41073cdd31db08acb68e3'   ← 未捕获异常
```

### D5 —— 根授权重签发

```python
d = RefDriver(); d.add_agent("A","c",["order.read@orders/*"]); d.add_agent("B","w",[])
tid = d.delegate("A","B",["order.read@orders/*"],"T1")
d.force_request("A","B",tid,"order.read","orders/1","T1","a",d.now)   # OK
d.issue_grant("A", ["order.read@orders/*"])
d.force_request("A","B",tid,"order.read","orders/1","T1","b",d.now)   # ref: TOKEN_INVALID
```

### D6 —— 复合动作（已修复）

```python
required = ("db.export@x/y",)     # §2.12：元素是 "cap@resource" 字符串，不是元组
# 令牌范围 order.read@orders/*；请求 order.read@orders/1 + 上述 required
# 修复前 mine: ALLOW OK(副作用 1)   修复后 mine: DENY SCOPE_VIOLATION(副作用 0)
```

### 附：D1 的机制刻画（实测确认）

参考实现对**资源串**做 `strip('/')` 后再按 `/` 切段。把该规则实现出来与 `src.patterns.matches` 在 80 模式 × 39 资源 = **3120 格**上逐格比对，**0 处不符**（`oracle.py` 与 `patterns.py` 的规则在该网格上则是 195 格不符，全部集中在带首/尾 `/` 的资源）。因此 D1 不是"某处特例"，而是一条完整的、规格未写出的归一化规则。

---

## 3. 统计

固定种子 `20240911`，`ttl=1000`、`pull_interval=10`。

| 场景族 | 用例数 | 分歧数（修复我方 bug 后） | 分歧数（修复前） | 分歧承载点 |
|---|---:|---:|---:|---|
| F1a `matches` 穷举（80 模式 × 39 资源） | 3120 | **195** | 195 | D1 |
| F1b `subsumes` 穷举（80 × 80） | 6400 | **0** | 0 | — |
| F1c 系统级 `matches`（经真实令牌+请求路径） | 280 | **61** | 61 | D1 |
| F1d 系统级 `subsumes`（经 `delegate` 衰减检查） | 200 | **0** | 0 | — |
| F1e §2.8 健全性扫描（`subsumes`⇒`matches`，34905 三元组 × 2 侧） | 34905×2 | **0** | 0 | — |
| F2 衰减链（多级/封条/越权/非持有者） | 60 | **28** | 28 | D4 |
| F3 判定顺序（多重违反叠加） | 50 | **9** | 9 | D2 |
| F4 重放与时效 | 79 | **24** | 24 | D3a/D3b |
| F5 撤销与凭证 | 54 | **1** | 1 | D5 |
| F6 复合动作 `required` | 65 | **0** | 32 | D6（已修） |
| F7 任务绑定 | 44 | **0** | 0 | — |
| **合计** | **10352**（另有 34905×2 = 69810 个健全性三元组） | **318** | 350 | 6 处分歧 |

**两侧副作用（世界模型）一致性**（把 352 个 F2–F7 用例在两侧各重跑一遍，比较副作用总条数）：**25 例不一致，全部落在 F4**，且全部可归因到 D3（时窗常数 / 未来 ts）——参考实现拒绝而我方放行，于是我方多执行了副作用。修复 D6 之前，F6 另有 32 例我方多执行副作用；修复后归零。

**判定与副作用的不变式**：在全部带 `eff` 记录的用例中，两侧均未出现 `ALLOW` 而副作用为 0、或 `DENY` 而副作用 > 0 的情况（0 反例）。即两侧都守住了 §3.2「第 8 步之外无副作用」，分歧只改变"是否放行"，不改变"放行即执行"这一对应关系。

### 3.1 零分歧的场景族（同样是有信息量的结果）

**整族零分歧：**

- **F1b `subsumes` 模式包含**：6400 例，与我方、与 `oracle` 三方**完全一致**。§2.8 的包含判定本身没有分歧——§2.8 记录的"`a/**` 曾被判为 `a/*/**` 的子集"这一历史缺陷，在参考实现中确已修复。
- **F1d 系统级衰减检查**：200 例，经 `delegate` 的真实拒绝路径，0 分歧。
- **F1e 健全性**：`subsumes(p,q) ⇒ matches(p,r) ⇒ matches(q,r)`，参考实现、我方、`oracle` 三者各 34905 个三元组，**0 反例**。两侧都满足 §2.8 的健全性硬要求。
- **F6 复合动作**（修复我方 bug 后）：65 例 0 分歧，含"全部在范围内/部分在/全不在/空 `required`/`required` 中资源为 `*`"。
- **F7 任务绑定**：44 例 0 分歧，含 `token.task_id != req.task_id`、空字符串 task、跨跳任务链：实测两侧完全相同 —— `t1_T1=OK`、`t2_T1=TASK_MISMATCH`、`t2_T2=OK`。

**子场景零分歧（族内其它点有分歧，但这些点两侧一致）：**

| 子场景 | 用例数 | 两侧一致的结果 |
|---|---:|---|
| 同一 nonce 重放 | 1（含 1 次重发） | `REPLAY` / 第二次 `REPLAY`，第二次副作用 0 |
| 重发**同一个请求对象** | 1 | `REPLAY` |
| 不同 `from_id` 用同一 nonce | 1 | 两侧都 `OK`（实测；§3.2 步骤 1b 的键确为 `(from_id, nonce)`，两实现一致） |
| 坏签名（`sig=""`） | 1 | `REQUEST_UNSIGNED`，副作用 0 |
| 令牌 TTL 到期 | 1 | 两侧同一 tick 转为 `TOKEN_EXPIRED` |
| 撤销令牌（含跨拉取周期） | 随机 45 例 | 未跨周期 `OK`、跨周期 `TOKEN_REVOKED`，两侧一致 |
| 分区下撤销 | 1 + 随机 | 分区期间一律 `OK`，恢复分区后立即 `TOKEN_REVOKED`，两侧一致（符合 §2.12 的 `pull_interval + ttl` 上界） |
| 撤销主体（持有者 / 根主体 / 链上签发者） | 3 + 随机 | 两侧一致：撤销生效于**令牌的持有者**，不影响其子孙令牌、也不影响以被撤销主体为根的令牌 |
| 撤销父令牌后子令牌 | 1 | 两侧一致：`parent=TOKEN_REVOKED`，`child` 仍 `OK` |
| 签发者绑定（`token_issuer(t) != req.from_id`） | 1 + 随机 | `TOKEN_INVALID`，两侧一致 |
| `redelegatable=False` 后再派生 | 60 例中的 `seal_after` | `NOT_REDELEGATABLE`，两侧一致 |
| 越权派生（异能力 / 放宽模式 / 超集三构造） | 60 例 × 3 | **两侧各 0 次成功**，全部拒绝 |
| 多跳衰减范围非增 / `depth` / `holder_id` | 60 例 | 两侧令牌结构字段逐项一致 |
| 凭证副本刷新（同一真签发件） | 1 | 两侧都接受，请求仍 `OK` |

### 3.2 无法构造的场景（及其原因）

| 场景 | 结论 | 原因 |
|---|---|---|
| `STALE_CREDENTIAL` | **两侧都不可达**（无法构造） | §3.2 步骤 4 要求"`grant.cred_epoch < max_seen_cred` ⇒ DENY STALE_CREDENTIAL"。穷举了黑盒可及路径：`refresh_grant` 传入真实签发的**更旧** cred_epoch 副本 → 返回 `False`（拒绝装载）；传入**篡改**过 cred_epoch 的副本 → 返回 `False`（签名覆盖 `cred_epoch`，篡改验不过）；`pull` 传入回退的 `RevocationEpoch` → 无异常、无判定变化。**结论：参考实现实际上是用"签名覆盖 cred_epoch + 拒绝回滚装载"来挡回滚的，而不是用步骤 4 的 `STALE_CREDENTIAL` 分支**——该分支在黑盒可及路径上是死代码。我方则把步骤 4 实现在 `_decide` 里（`cred_epoch < max_seen_cred` ⇒ `STALE_CREDENTIAL`），但因同一原因也拿不到可触发的输入。**该项两侧判定为"无分歧"仅因为都不可达，不构成一致性证据。** |
| 经 `System.request` 门面做重放 | 不可达 | 门面每次调用生成新 nonce（`request_id` 亦递增），无法通过公开签名制造重复 nonce。已改用**下一个公开层级**：`src.model.ActionRequest` + `PEP.handle(req)`（仍是黑盒调用公开 API，未读源码，签名载荷通过黑盒比对确定为 `to_dict()` 去掉 `sig`）。 |
| `required` 用 `(cap, resource)` 元组传入 | 参考实现 `AttributeError` 逃逸 | 初版装置按"元组序列"构造 `required`，参考实现在 `cap, _, res = item.partition("@")` 处抛 `AttributeError: 'tuple' object has no attribute 'partition'`（未捕获）。§2.12 规定元素是 `"cap@resource"` 字符串，故**这是我的装置构造错误**，非被测行为；但参考实现对畸形输入以未捕获异常逃逸这一点与 D4 同源，一并记录。 |

---

## 4. 我方实现的处置

| 分歧 | 处置 |
|---|---|
| **D6（我的 bug，§2.12 未实现）** | **已修改** `replication/mechanism.py`：`ActionRequest` 增加 `required: tuple[str, ...] = ()` 字段并纳入签名载荷；`PEP._decide` 在步骤 7 之后增加 7b，逐条解析 `"cap@resource"` 并校验，失败返回 `SCOPE_VIOLATION`（§2.12 未规定该情形的 reason_code，取值与参考实现一致）。`replication/differential/drivers.py` 的 `MyDriver` 同步透传。**验证**：F6 从 32 处分歧降到 **0**；`replication/r1_run.py` 仍通过；`replication/selfcheck.py` 仍通过（subsumption 反例 0、衰减不放大反例 0、非平凡性 True）。修复前的结果留档于 `results.prefix.json`。 |
| **D3b（规格歧义，字面读法对我方有利但可被利用）** | **未改**。理由是先把规格钉死：若规格接受"未来 ts 合法"，则参考实现多了一条检查（无害，属加严）；若规格改为区间检查，我方需补 `now - req.ts ≥ -clock_skew`。在规格表态前单方面改动会让下一轮差分失去可判定性。**建议给规格加一句**：`-clock_skew ≤ now - req.ts ≤ max_request_age`。 |
| **D1 / D2 / D3a / D5（规格歧义）** | **未改**，需规格先钉死：D1 补资源串分段规则（是否丢弃首尾 `/`）；D2 补步骤 5 内部优先级；D3a 补 `max_request_age` 的取值与标定方式；D5 补"根授权重签发是否作废在途令牌"。每条都已给出两侧读法及其后果，供规格选择。 |
| **D4（参考实现 bug）** | 不在本轮可改范围（`src/` 只读）。**建议**：把非持有者派生的失败路径改为 `raise Deny("TOKEN_INVALID", ...)`，与同文件其它派生拒绝（`NOT_REDELEGATABLE`）保持一致。 |

---

## 5. 一句话结论

§2.8 的**模式包含代数**本身两侧完全一致（6400+200+34905×2 例零分歧，健全性零反例）；分歧全部集中在**规格没写、或写得可两读的地方**——资源串分段（D1）、步骤 5 内部优先级（D2）、时窗常数与负半轴（D3）、根授权重签发的语义（D5）——外加一处参考实现的异常逃逸（D4）和一处我方确凿的遗漏（D6，已修复）。
