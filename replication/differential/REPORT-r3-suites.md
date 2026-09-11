# R3：四个 suite 的阶梯差分复现

复现者仍只读 `spec/spec.md`（含本轮钉死后的 §8）与 `data/agentdojo_bench.json`，未读
`results/`、`paper/`、`src/` 或任何其它 `.py`。

代码：`replication/staircase.py`（本轮改为可切换 L3 锚定方式）、
`replication/differential/run_all_suites.py`。运行：
`cd replication/differential && python3 run_all_suites.py`，逐 suite 明细落在
`replication/differential/all_suites.json`。

已按钉死版实现的三处：跳映射 **0-based**（`hop = i mod 4`）；L3 锚定参数名 = **提取后参数表中的
第一个**（`params[0].name`，无参数则无相邻项）；危害集合 = `extraction.harm_set_from_injection_ground_truth`
（基准注入任务 `ground_truth()` 的工具集，能力级）。

## 1. 每 suite 的选定任务与一致性

| suite | U | 选定任务 | 调用数 | 并列候选 | `M` 一致性检查 |
|---|---|---|---|---|---|
| banking | 11 | `UserTask15` | 5 | — | 通过 5/5 |
| slack | 11 | `UserTask10` | 8 | — | 通过 8/8 |
| travel | 28 | `UserTask19` | 18 | — | 通过 18/18 |
| workspace | 24 | `UserTask10` | 2 | `UserTask10/15/18/35`（并列取 id 最小） | 通过 2/2 |

四个 suite 的 `ground_truth` 调用全部落在本 suite 的 `TOOLS` 内，无跨 suite 调用。

`M` 逐跳（`hop0..hop3`）：

- **slack**：`M0={add_user_to_channel@*, get_channels@**, get_users_in_channel@**}`、
  `M1=M2={add_user_to_channel@*, get_users_in_channel@*}`、
  `M3={add_user_to_channel@Charlie, get_users_in_channel@private}`。
  （`M0` 的 `get_users_in_channel@**` 来自 idx4 那次无字符串实参的调用，§8.2 第 3 条第一项。）
- **travel**：`M0` 含 9 个能力（`get_all_car_rental_companies_in_city@*`、`get_all_hotels_in_city@*`、
  `get_all_restaurants_in_city@*`、`get_car_price_per_day@**`、`get_hotels_prices@**`、
  `get_price_for_restaurants@**`、`get_rating_reviews_for_{car_rental,hotels,restaurants}@**`）、
  `M1` 中三个 `get_all_*_in_city` 收窄为 `@Paris`/`@Paris`/`@*`、
  `M2` 为 `{get_all_car_rental_companies_in_city@Paris, get_all_hotels_in_city@Paris,
  get_all_restaurants_in_city@London, …}`、`M3` 只剩 4 条。
- **workspace**：`M0={get_current_day@**, get_day_calendar_events@**}`、
  `M1={get_day_calendar_events@**}`、**`M2=M3=∅`**（该任务只有 2 个调用，后两跳无需求）。

## 2. 五级 surplus 与危害数（L3 用钉死读法：锚定参数名 = 参数表第一个）

| suite | L0 surplus / harm | L1 | L2 | L3 | L4 | 各级任务成功率 |
|---|---|---|---|---|---|---|
| banking | 0 / 0 | 5 / 4 | 5 / 4 | **1 / 0** | 38 / 14 | 5/5 全部 |
| slack | 0 / 0 | 2 / 1 | 7 / 4 | **20 / 12** | 42 / 31 | 8/8 全部 |
| travel | 0 / 0 | 7 / 3 | 11 / 4 | **44 / 3** | 93 / 21 | 18/18 全部 |
| workspace | 0 / 0 | 0 / 0 | 0 / 0 | **0 / 0** | 93 / 20 | 2/2 全部 |

（表内为 `surplus 条数 / 落在基准危害集合内的条数`；surplus 按（跳, 条目）计数，四跳求和。）

平均可达半径（同一个 w 规则）：banking `[0, 2.200, 2.200, 1.000, 4.000]`、
slack `[0, 4.000, 4.000, 3.250, 4.000]`、travel `[0, 3.714, 3.727, 3.886, 4.000]`、
workspace `[0, 0, 0, 0, 4.000]`。

**banking 的 L3 数字与我第一轮报告的 8/4 不同**：第一轮用的是本轮被钉死为"备选读法"的
str-typed 锚定。按钉死读法重算得 **surplus 1 / harm 0**，与规格 §8.3 注释里写的
"banking 的 L3 surplus 从 1 变 8、危害从 0 变 4"逐字吻合——这是两份独立实现的相互印证。

## 3. 三个问题

### Q1：四个 suite 的 L1/L2/L3 危害排序是否一致？

危害向量 `(L1, L2, L3)`：

| suite | 向量 | 该 suite 内最危险的级别 |
|---|---|---|
| banking | (4, 4, 0) | L1 = L2（并列） |
| slack | (1, 4, 12) | L3 |
| travel | (3, 4, 3) | L2 |
| workspace | (0, 0, 0) | 无（三级都为 0，退化） |

**不一致。** 六对逐对比较，全部不同：

| 对 | 是否一致 | 不同之处 |
|---|---|---|
| banking vs slack | 否 | banking 顶端是 L1=L2、L3 垫底；slack 顶端是 L3、L1 垫底 |
| banking vs travel | 否 | banking L1=L2 并列顶；travel 只有 L2 独占顶，且 L1=L3 同为最低 |
| banking vs workspace | 否 | (4,4,0) vs (0,0,0) |
| slack vs travel | 否 | slack 顶 L3；travel 顶 L2（且 travel 的 L3=3 低于 L2=4，是唯一 L3 不随粗化升高的非退化 suite） |
| slack vs workspace | 否 | (1,4,12) vs (0,0,0) |
| travel vs workspace | 否 | (3,4,3) vs (0,0,0) |

即：**三个非退化 suite（banking / slack / travel）的 L1–L3 危害排序两两不同**；
workspace 的向量是退化值（全 0），不含排序信息，需单列而不能当作"与某一 suite 一致"。

补充（供选择性陈述的对照面）：级别内部也并非处处一致——travel 上 surplus 从 L2 的 11 涨到 L3 的 44
（四倍），但危害数反而从 4 降到 3，因为 L3 新增的条目全是 `get_all_*_in_city` 这类不在危害集合内的读能力。
banking 上同样出现"L3 危害低于 L1/L2"。

### Q2："最危险级别 = L4" 是否在四个 suite 上都成立？

**成立，四个 suite 都成立**，且是严格最大（危害数与 surplus 条数同时最大）：

| suite | L4 harm | 其余各级 harm 最大值 | L4 surplus | 其余各级 surplus 最大值 |
|---|---|---|---|---|
| banking | 14 | 4 | 38 | 5 |
| slack | 31 | 12 | 42 | 20 |
| travel | 21 | 4 | 93 | 44 |
| workspace | 20 | 0 | 93 | 0 |

但必须同时给出机制说明：`L4` 的逐跳范围就是 `R = U@**`，而其余各级都被 §8.3 的逐跳过滤
限定为 `⊆ R`，因此 `L4` 的 `S_i` 是其余各级 `S_i` 的超集；surplus 判据（"不被 `M_i` 包含"）
对集合单调，所以 **`L4` 危害数 ≥ 其余各级是定义蕴含，不是被测量出来的性质**（正是 spec §2.16
第 3 条所禁的"包络级必胜"）。有信息量的比较只在 L1/L2/L3 之间，见 Q1。
可佐证该结论不含装置信息的一点：四个 suite 的 L4 危害数**互不相同**（14/31/21/20），
说明数字本身因基底而变，只是"最大"这一位次不变。

### Q3：换成 str-typed 锚定（首个类型含 `str` 的参数），哪些 suite 会变？

| suite | L3 surplus（钉死 → str-typed） | L3 harm（钉死 → str-typed） | 结果是否变 |
|---|---|---|---|
| banking | 1 → **8** | 0 → **4** | **变** |
| slack | 20 → 20 | 12 → 12 | 不变 |
| travel | 44 → 44 | 3 → 3 | 不变 |
| workspace | 0 → 0 | 0 → 0 | 不变 |

只有 **banking** 变。逐个比较 surplus 条目集合（非只比条数）后：slack / travel / workspace 的
L1/L2/L3/L4 全部条目集合逐条相同；banking 的 str-typed 版本多出 7 条、无一条被移除
（`hop0:send_money@US133000000121212121212`、`hop0:schedule_transaction@…`、
`hop0:update_scheduled_transaction@GB29NWBK60161331926819` 及 hop1/hop2 的对应项）。

原因是锚定差异只在**进入 `M` 的能力**上才会传导：两读法参数表不同的能力共 8 个
（banking：`get_most_recent_transactions` `n`→无、`update_scheduled_transaction` `id`→`recipient`；
travel：`send_email` `recipients`→`subject`；workspace：`append_to_file`、`delete_email`、
`delete_file`、`get_file_by_id`、`send_email`），但其中只有 banking 的
`update_scheduled_transaction` 出现在 `M` 里且它的锚定名在两读法下不同
（`id` vs `recipient`）——前者的邻接集合只有它自己，后者的邻接集合是
`{send_money, schedule_transaction, update_scheduled_transaction}`，于是多出 3 个能力 × 对应 pat 的条目。
travel / workspace 的差异能力都不在各自 `M` 中，故不传导。

workspace 的 L3 之所以恒为 0：`M` 的两个能力里，`get_current_day` 参数表为空（钉死为"无相邻项"），
`get_day_calendar_events` 的锚定名是 `day`，而 workspace 的 24 个工具中没有第二个以 `day` 为锚定的
cap（实测分组结果只有一个成员），故 L3 相对 `M` 无任何新增条目。

## 4. 本轮新发现的规格不足（各自影响数字）

1. **`M_i` 为空跳时 `L4` 的行为未定义**（本轮由 workspace 触发：任务只有 2 个调用，
   `M_2=M_3=∅`）。§8.3 开头说"对 `M_i` 逐条施加"，而 `L4` 的算子是常量"`R` 的全部能力"——
   逐条施加在空集上得到空集，常量施加得到 `R`。我按常量读法（§8.3 `L4` 行与 §2.15 的单调性
   要求都指向它）实现，**该读法只影响 workspace**：`L4` surplus 93 / harm 20；
   若按逐条读法则为 surplus 45 / harm 10。其余三个 suite 两读法数字完全相同。
2. **§8.2 第 3 条第一项的判据未区分"工具无字符串参数"与"实参为空串"**。slack 的
   `get_users_in_channel` 既有 `('general')` 又有一次无参调用，我按"该能力的调用中不存在字符串实参"
   判定并取 `**`；若改按"工具元数据的参数表有无 str 类型参数"判定，结果相同，
   但对参数表为空的工具两者会分叉——本任务上未分叉，故不报。
3. **§8.4 的"可达半径"的 `w` 仍未规定**（沿用第一轮的合成见证规则；换用实资源不变，见首轮报告）。
4. **`L3` 的"锚定参数名"对 `params` 为空的 cap 已钉死为"无相邻项"，但对"有参数却与其他 cap 同名者
   跨越了哪些 cap"仍限定了范围**：§8.3 只说"`adj` 与 `cap` 的锚定参数名相同"，未说 `adj` 取自 `U`
   还是全部 91 个工具。我取 `U`（§8.1 定义 `U` = 本 suite 的 `TOOLS`）。若取全部 91 个工具，
   各 suite 的 L3 都会变大——本轮未跑该变体，报告为未确定项。
