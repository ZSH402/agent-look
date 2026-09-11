# round3：新钉死条文的独立实现检验

独立实现者（本轮首次接触本仓库）**只读 `spec/spec.md`**、其余只做黑盒调用，逐条实现被钉死的条文并与参考实现实际比对。

产物：`my_impl.py`（我按规格写的判定逻辑）、`compare.py`（黑盒对照，24 项 + 链根 1 项）、
`probe_core.py` / `probe_time.py` / `probe_chain.py` / `probe_chain2.py` / `probe_extra.py` / `probe_epoch.py` / `probe_offline.py`。
只读的文件：`spec/spec.md`。未读 `src/` 源码（仅用 `import`/`inspect.signature`/`dir` 与黑盒调用）。
全部脚本已重跑一遍，退出码均为 0；下文每个数字都来自这些脚本的实际输出。

## 0. 结论总览

| # | 条文 | 规格能否唯一确定 | 我的实现 | 参考实现 | 判定 |
|---|---|---|---|---|---|
| 1 | §2.3 verify 顺序 撤销→过期→密钥 | 能（该场景） | `TOKEN_EXPIRED` | `TOKEN_EXPIRED` | **一致** |
| 1' | 同上，但"主体撤销"指哪个主体 | **不能** | 两种读法都实现 | 只按 `holder_id` | 规格缺口（见 A2） |
| 2 | §2.3 派生规则顺序 | 能（码值除外） | `SCOPE_VIOLATION` | `SCOPE_VIOLATION` | **一致**；规则 2 的码值规格未命名（A5） |
| 3 | §3.1 令牌副本 | 能 | 委托方无副本 ⇒ 不可作父令牌 | 同 | **一致**；"持有"的定义未写（A7） |
| 4 | §3.2 `clock_skew=20` 未来 `ts∈[1,20]` | **不能（自相矛盾）** | 放行 | 放行 | **一致**，但规格正文两处冲突（A1） |
| 5 | §2.3 链根表示 | **不完全能** | 链根可算，链可离线复算 | 同 | **部分一致**；H、签名编码、逐 epoch 公钥、历史授权解析 4 处缺字段（A9–A12） |

`compare.py` 黑盒对照：**25/25 AGREE**（在我按 A2/A5/A6/A7 选定读法之后）。

## 1. §2.3 verify 的检查顺序：撤销 → 过期 → 密钥作废

**规格读法**（L70–76）：规则 4–6 的触发优先级为 撤销（仅规则 5，`revoke_token`/`revoke_subject`）→ 过期（规则 4）→ 密钥作废（规则 6，失败报 `TOKEN_REVOKED`，L62）。
故「未 `revoke_token` 撤销、已过期、密钥 epoch 已作废」⇒ 第二级命中 ⇒ **`TOKEN_EXPIRED`**。

**我的实现**：`my_impl.verify_reason()` 按 令牌撤销/主体撤销 → `now > not_after` → 涉事 `key_epoch ≤ revoked_upper` 的顺序短路返回。

**参考实现实际行为**（`probe_core.py` / `compare.py`，撤销均已经过 `advance` 拉取生效）：

| 情形 | 观察结果 |
|---|---|
| 未撤销 + 已过期（`not_after=101, now=121`）+ `revoke_key_epochs("A",1)` | `DENY TOKEN_EXPIRED` |
| 已 `revoke_token` + 已过期 | `DENY TOKEN_REVOKED` |
| 仅 `revoke_key_epochs("A",1)`（未过期） | `DENY TOKEN_REVOKED` |
| 仅 `revoke_token` | `DENY TOKEN_REVOKED` |
| 基线（无撤销） | `ALLOW OK` |
| 撤销后**未拉取**（不 `advance`） | `ALLOW OK`；`advance(10)` 后 `DENY TOKEN_REVOKED` |

**判定：一致**。错误码与钉死的优先级相符；`revoke_token` 与密钥作废同为 `TOKEN_REVOKED`，靠触发顺序区分而非码值区分。
边界补充（`probe_epoch.py`）：过期边界是 `now > not_after` 才过期（`now=101=not_after` → `ALLOW`，`now=102` → `TOKEN_EXPIRED`），与规则 4「当前时间 ≤ not_after」一致。
`revoke_key_epochs(sid, upto)` 的 `upto` 为**含端点**：`upto=0` → `ALLOW`，`upto=1` → `TOKEN_REVOKED`（对应「严格大于；等于即为已作废」）。

## 2. §2.3 派生规则顺序：父令牌已封条 且 子范围越界

**规格读法**（L46–53）：规则 1–5 的列举顺序即检查顺序。范围包含是规则 **2**，封条是规则 **5** ⇒ 报规则 2 的码。规格未给规则 2 命名码值，我取 `SCOPE_VIOLATION`（§2.5 枚举中语义唯一契合者，且钉死段落自述第二种实现就报这个码）。

**参考实现实际行为**（`probe_core.py` / `probe_extra.py`）：

| 情形 | 结果 |
|---|---|
| 封条父令牌 + 子范围越界（派生者=holder B） | `Deny SCOPE_VIOLATION: 派生范围超出父令牌` |
| 封条父令牌 + 子范围**在界内** | `Deny NOT_REDELEGATABLE: 父令牌不可转委托` |
| 未封条 + 子范围越界 | `Deny SCOPE_VIOLATION` |
| 封条 + 越界 + 派生者非 holder（A） | `Deny TOKEN_INVALID: A 不持有父令牌` |

**判定：一致**（规则 1 先于规则 2 也得到验证：非 holder 时不是 `SCOPE_VIOLATION`）。
规则 3 的截断也一致（`ttl=100`、`now=1` ⇒ `not_after=101`，与 `min(now+ttl, parent.not_after)` 相符）。

## 3. §3.1 令牌副本

**规格读法**（L301–302）：委托方**不保留**所授令牌的可用副本，令牌只存于持有者的 PEP；配合规则 1「派生者必须持有父令牌」⇒ 授出方**不能**再拿它当父令牌派生。

**参考实现实际行为**（`probe_extra.py` S3c、`probe_core.py` S3a/S3b）：

```
A store has t1: False   B store has t1: True   C store has t1: False
B store has t2: False   C store has t2: True
S3a 授出方 A 用 t1 派生 -> Deny TOKEN_INVALID: A 不持有父令牌 <id>
S3b 持有者 B 用 t1 派生 -> 成功
```

**判定：一致**：委托方不保留副本；授出方（即使是签发者/root）不能再以该令牌派生。
（A 的 store 里确实有 1 个令牌，那是 A 自己的根令牌，不是它授出的那份。）

## 4. §3.2 时效窗口：`clock_skew=20`

**规格读法**（L312–319 + §3.2 步骤 1c）：可接受区间 `[now - max_request_age, now + clock_skew]`，
步骤 1c 写作 `-clock_skew ≤ now - req.ts ≤ max_request_age` ⇒ `ts` 在未来 `[1,20]` 应当**放行**。
但同一段末尾又写「判定为 `0 ≤ now - req.ts ≤ max_request_age`——**未来时间戳同样拒绝**」，按此读法则**拒绝**。**规格自身冲突**，见 A1。

**我的实现**：`my_impl.window_ok()` 取步骤 1c 的公式（`-skew ≤ now-ts ≤ max_age`），端点含。

**参考实现实际行为**（`probe_time.py`；`request()` 无 `ts` 参数，故先以 `ts=t0` 造请求，再把接收方时钟设为 `t0-k`，并清空 `seen_nonces` 以越过步骤 1b 重放检查到达 1c）：

| `clock_skew` | `now-ts` | 结果 |
|---|---|---|
| 0 | 0 / -1 / -20 | `OK` / `REPLAY` / `REPLAY` |
| 20 | 0 / -1 / -20 / -21 | `OK` / `OK` / `OK` / `REPLAY` |
| 0 | +50 / +51 | `OK` / `REPLAY` |
| 20 | +51 | `REPLAY` |

**判定：一致**（与步骤 1c 完全吻合，端点含）；规格正文那句「未来时间戳同样拒绝」**与参考实现不符**，只在默认 `clock_skew=0` 时巧合成立。
谁错：按 §3.2 伪代码（可执行条文）为准，那句话是上一版默认 `skew=0` 时的产物，应限定为 `clock_skew=0` 的特例。

## 5. §2.3「链根」的表示

**规格读法**（L65–68）：有链时为 `chain[0].parent_token_id`，无链时为 `token.token_id`；验证方以该标识在权威授权历史中解析出实际根植的那份授权。
字段方面，`Link` 已含 12 个字段（与实现一致），足以重算 `token_id`——**前提是知道 H 是什么**。

**参考实现实际行为**（`probe_chain.py` / `probe_offline.py`）：

```
2 跳链 token（C 持有）：chain 长度 2，chain[0].parent_token_id = 603c2bf1…  (= A 的根令牌 id)
Link[0]/Link[1] 重算 token_id == 存储 token_id  ✓（用参考的 derive_token_id）
Link sig 离线验签 ✓（payload = Link 全部字段去掉 sig 的 canonical dict；我用 sign() 反推得到）
RootGrant sig 离线验签 ✓（payload = grant 全部字段去掉 sig）
规则 7：末链 6 个字段与 token 字段一一相符 ✓
```

**判定：部分一致 / 无法仅凭规格实现**。链根**标识**现在确实唯一可定（两种情形都明确），我的 `my_impl.chain_root()` 与参考一致。
但要让一个外部实现者**离线**验证一条链，规格还缺 4 样东西（A9–A12），其中 A9 使我无法写出与参考可互操作的实现。

## 6. 规格仍未讲清楚、逼我自行决定的地方

- **A1（§3.2，最重要）**：规格说「区间为 `[now - max_request_age, now + clock_skew]`」且步骤 1c 写 `-clock_skew ≤ now - req.ts ≤ max_request_age`；
  **没说**末尾那句「`0 ≤ now - req.ts ≤ max_request_age`、未来时间戳同样拒绝」是否只适用于 `clock_skew=0`，两句在 `clock_skew≠0` 时互相排斥。
  我选 Y1=步骤 1c 公式（`ts` 未来 1..20 ⇒ 放行）；也可选 Y2=按 `0 ≤ …` 字面（⇒ `REPLAY`）。
  二者结果不同（`clock_skew=20`、`ts` 领先 1..20 tick 时 `ALLOW OK` vs `DENY REPLAY`）。参考实现是 Y1。
- **A2（§2.3 规则 5 / L71）**：规格说撤销「令牌/主体被 `revoke_token`/`revoke_subject`」，**没说** `revoke_subject(sid)` 是拿 `sid` 与 `token.holder_id`、`token.root_subject_id` 还是 `token_issuer` 比较。
  我最初选 Y1=`root_subject_id`；参考是 Y2=`holder_id`。可观察差异：`revoke_subject("A")`（A 是链根/签发者，B 是持有者）+ 令牌已过期 + A 的密钥 epoch 作废
  ⇒ Y1 报 `TOKEN_REVOKED`，Y2 报 `TOKEN_EXPIRED`（参考实测为后者）。这正是本次要检验的那条边界的**码值**，规格在此仍未唯一确定。
  另实测：`revoke_subject("B")`（holder）+ 已过期 ⇒ `TOKEN_REVOKED`（撤销确实优先于过期）。
- **A3（§2.3 规则 6）**：规格说「**所有涉及的** `key_epoch`」，**没说**涉及集合是否包含持有者/请求方的 epoch。我选 Y1={根授权 epoch} ∪ {各级 `Link.attenuator_key_epoch`}（不含 holder）。参考一致：
  `revoke_key_epochs("B",1)` 对 A→B 令牌无影响（`ALLOW OK`），`revoke_key_epochs("A",1)` 才 `TOKEN_REVOKED`；链上中间衰减者 B 被作废 ⇒ B→C 令牌 `TOKEN_REVOKED`。
  若 Y2 把 holder 也计入，结果会不同（`DENY TOKEN_REVOKED`）。
- **A4（§3.3 API）**：`revoke_key_epochs(sid, upto, now)` 的 `upto` 是否含端点，规格未定义该接口；实测含端点（`upto=1` 作废 epoch 1，`upto=0` 不作废）。
- **A5（§2.3 规则 2）**：规格只写「否则拒绝派生」，**没给码值**。我选 Y1=`SCOPE_VIOLATION`，也可选 Y2=`TOKEN_INVALID`（规则 1、3、7 失败在参考里用这个码）。结果码值不同，行为相同。
- **A6（§2.3 规则 1）**：同 A5，规格未给规则 1 的码值；参考为 `TOKEN_INVALID`。
- **A7（§2.3 规则 1 + §3.1）**：「派生者必须**持有**父令牌」**没说**「持有」= 本地 token store 中有该项，还是进程内持有该对象。
  我选 Y1=store 成员（与 §3.1「不保留可用副本」自洽）；Y2=对象可达。二者对第 3 条问题给出**相反答案**（Y1：授出方不能再派生；Y2：能）。参考是 Y1。
- **A8（§2.3 规则 3）**：`ttl` 参数缺省（`ttl=None`）时取哪个 ttl，规格未写（§2.2 只说 `not_after = issued_at + ttl`）。我选系统级 `ttl`；实测一致（ttl=100 ⇒ child `not_after=101`）。
- **A9（§2.3 规则 3 的 H）**：**规格未定义 H**（哈希函数、字段编码、输出长度都没写），只写了 `token_id = H(...)`。
  我无法据此实现：我尝试了 5 种常见构造（`md5(join('|'))`、`md5(json(list))`、`md5(concat)`、`sha256[:32]` 等）复算参考的 `derive_token_id`，**全部不匹配**；只能用参考自带的 `derive_token_id` 才能让 `Link.token_id` 重算通过。
  后果：一个只读规格的实现无法与参考互操作（自算的 token_id 与参考不同），规则 3 的「可重算验证」只能在实现内部自洽。
- **A10（§2.3 规则 2 的验签）**：规格说「用 `attenuator` 的公钥验签」，**没说**被签名的消息如何规范化。我实测反推出参考用的是「Link 全部字段（去掉 `sig`）的 canonical JSON」，但这是我用 `sign()` 试探出来的，不是规格给的。
  （顺带：`ActionRequest` 的签名 payload 我用同样 2 种候选**没能**复现，说明不同对象的签名编码不同且规格都未定义。）
- **A11（§2.3 规则 6 + §2.2）**：规则 6 需要「验证方记录的 `revoked_key_epoch` 上限」，`RevocationEpoch` 有该字段，但规格**没说**它是按主体记录的（实测是按 `subject_id` 记录，与 `max_seen_cred` 一样按主体）。
  另外，验签要靠 `attenuator_key_epoch` 对应的**历史公钥**，而规格没有任何「key_epoch → 公钥」的表或目录；参考的 registry 只存**当前**公钥。实测：`rotate_key("A", 2, scope)` 之后，用旧 epoch 的父令牌派生 ⇒ `Deny TOKEN_INVALID: 派生链接签名无效 (A)`，旧链**无法**再离线验证。
- **A12（§2.2 + §2.3 链根）**：规格要求「以链根标识在权威授权历史中解析出那份授权」，但 §2.2 的 `RootGrant` 只有 `{subject_id, scope, key_epoch, cred_epoch, issued_at, not_after, sig}`，**没有任何字段能承载链根令牌标识**；
  实际解析要 `(root_subject_id, chain_root)` 两个键（参考接口 `grant_for_root_id(subject, root_token_id)`），且授权历史由权威持有——这与 §2.3 标题「验证规则（`verify`，**纯离线**）」张力明显：旧链的根授权不在令牌里（实测 `token` 无 grant 字段），离线方必须另有渠道拿到该历史。

## 7. 我无法实现的部分（信息不足）

1. **A9** 使我无法从规格实现 `token_id` 的重算（缺 H 的定义与编码）。用参考的 H 才能通过，这不算独立实现。
2. **A10** 使我无法从规格实现 Link/RootGrant 的**验签**（缺被签名消息的规范化）。我用参考 `sign()` 反推后可以验通，但那是从参考得到的知识。
3. **A11** 使我无法离线验证**历史** epoch 的链（规格无 key_epoch→公钥的历史表；参考只有当前公钥，实测旧链在轮换后判定为签名无效）。
4. **A12** 使我无法确定「授权历史」的检索键与离线可得性（`RootGrant` 里没有链根字段；参考按 `(subject, root_token_id)` 检索权威内部历史）。

## 8. 未检验的范围（诚实声明）

只检验了 §2.3 verify/attenuate、§3.1、§3.2 步骤 1c、§2.3 链根这五处。§2.8 模式包含、§3.2 步骤 1/1b/2–4、§4 漂移、§8 粗化阶梯等**未做**独立实现或比对。
第 4 条的 `ts` 需要用「回拨接收方时钟 + 清空 `seen_nonces`」的方式构造（公开 API 无 `ts` 参数）；清空 nonce 是越过步骤 1b（重放检查先于时窗检查，实测同样成立），对 1c 区间的结论无影响。
