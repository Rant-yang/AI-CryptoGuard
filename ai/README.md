> **2026-10-14：本轮共享契约已发布。** 请先阅读 [v0.2 接口与交接说明](../core/schema/CONTRACT_V0.2.md)。当前 v0.1 演示保持可用，新能力按 v0.2 开发。

# ai/ —— 讲人话

> **本轮任务（待实现）：B：读取前置量子风险评估，增强用途解释和具体整改。** 先读 [详细操作指南](../docs/本轮操作指南_2026-10-14.md) 和 [下一步计划](../docs/下一步计划.md)。现有用法继续有效，拟新增字段/参数以 C 的契约提交为准。

> **负责人：B**
> **一句话：把冷冰冰的扫描结果，变成一个人能看懂、能采取行动的结论。**

```
输入：findings.json               （统一格式，见 core/schema/）
      ↑ scanner 层已经填好了 remediation 占位符（source="none"）
  ↓
调用大模型（LLM）判「用途」
  ↓
拿用途去【查规则库】得到算法（不由 LLM 生成）
  ↓
输出：findings_ai.json            （原字段 + usage 复核 + explanation + 真 remediation）
```

> **注意**：`remediation` 字段**输入里就有**（scanner 给的占位符，`source="none"`）。
> ai/ 的活是把它**换成真的**（`source="rule-base"`），不是新增这个字段。
> 判断有没有增强过，看 `remediation.source`：
> `none` = 还没做，`rule-base` = 已增强。
> `python core/schema/validate.py` 最后一行打的就是这个分布，**那就是本层的进度条**。

---

## 第一版要做什么

**就一件事**：写一个程序，读 `findings.json`，调大模型，输出**带 `explanation` 和真 `remediation` 的**版本。

验收标准：

```bash
pip install -r ai/requirements.txt

# 1) 离线自检 —— 不装 SDK、不调 API、不花钱，先把逻辑跑通
python ai/selftest.py                                    # 必须退出码 0

# 2) 合规自查 —— 看看到底会把什么发到云端（不调用、不写文件）
python ai/enrich.py out\findings.json -o out\findings_ai.json --dry-run --limit 3

# 3) 真跑
python ai/enrich.py out\findings.json -o out\findings_ai.json
python core/schema/validate.py out\findings_ai.json      # 必须仍然退出码 0
```

**注意第 3 步最后那条**：AI 处理完之后**仍然必须通过 schema 校验**。

---

## 环境变量

程序从环境变量读配置，**不要把 key 写进代码或提交到仓库**。

| 变量 | 必须 | 说明 |
|---|---|---|
| `ANTHROPIC_AUTH_TOKEN` | 是 | API key |
| `ANTHROPIC_MODEL` | 是 | 模型名 |
| `ANTHROPIC_BASE_URL` | 否 | 兼容端点地址。**调 DeepSeek 时必须设置**，不设会打到 Anthropic 官方端点 |

> ⚠️ 代码里变量名带 `ANTHROPIC_` 前缀，但实际调的是 **DeepSeek**（走 Anthropic 兼容接口）。
> 这是 SDK 的命名，不是笔误 —— 用 `ANTHROPIC_BASE_URL` 指过去就行。

---

## 要回答的四个问题

```
1. 这里的 RSA/AES 是干什么用的？   → usage 字段
2. 这算不算真的风险？              → 复核 evidence，必要时调 severity
3. 为什么危险？（讲人话）           → explanation 字段
4. 应该怎么修？                    → remediation 字段
```

---

## 🔴 最重要的一条红线

### 你可以让 AI 判断「用途」，**绝对不能**让 AI 自由生成「换成哪个算法」

方案 §9.1 **明文禁止** `RSA → 固定某一种 PQC` 的映射。

如果你直接让大模型输出"RSA 应该换成 ML-KEM"，**它一定会这么写** —— 然后答辩时
评委问一句「那 RSA 用来签名也换 ML-KEM 吗？」就穿了。

### 正确做法：两段式

```
   第一段：LLM 只回答一个问题 ——
           「这个 RSA 是签名、加密、还是密钥交换？」
                    ↓
   第二段：拿着用途去【查规则库】，不由 LLM 生成
                    ↓
        signing        → ML-DSA (FIPS 204) / SLH-DSA (FIPS 205)
        encryption     → ML-KEM (FIPS 203)
        key_exchange   → ML-KEM (FIPS 203)
        unknown        → decided: false，明确说「暂不给出具体算法」
```

**「不知道」是合法且正确的输出。**

> ✅ 这个逻辑**已经写好并跑通了**，在 `core/rules/pqc_routing.py`。
> 直接调用，不用自己设计。`enrich.py` 里的 `enrich_finding()` 就是这么做的。

---

## 你需要知道的密码学（就这么多，不用多学）

**不要停下来系统学密码学。** 边做边学，碰到再查。但下面这几件开工前要清楚：

### 1. 签名 和 加密 是两回事，迁移路线不同

这是本模块唯一必须先建立的概念。看上面的红线部分就够了。

### 2. PQC 三个算法，记名字和用途就行

| 算法 | 标准 | 干什么 | 替代谁 |
|---|---|---|---|
| **ML-KEM** | FIPS 203 | 加密 / 密钥交换 | RSA 加密、ECDH |
| **ML-DSA** | FIPS 204 | 数字签名 | RSA 签名、ECDSA |
| **SLH-DSA** | FIPS 205 | 签名（保守备选） | 同上，更慢但假设更弱 |

### 3. 常见词（用到再查，不用背）

```
key   密钥      IV    初始向量（不该重复）     nonce  一次性随机数
hash  哈希      salt  加盐                    AEAD   带认证的加密
ECB/CBC/GCM   分组密码的工作模式（ECB 不安全，GCM 推荐）
```

---

## 发往云端的脱敏（方案 §19）

方案 §19：**用户原始代码默认本地。**

上游 `evidence[].raw` 里逐字保留着 CryptoScan 的原始记录，其中 `context` 是**真实的源码行**，
`file` 是**本机绝对路径**（`D:\code_competition\_smoke\...`）。
直接整包发出去，实测 91 条是 **120,596 字符**，源码和目录结构全部出网。

`ai/redact.py` 负责这件事。**它不在这里，是为了让你改不动它** —— 想让什么出网，
改 `redact.py`，不要在 `enrich.py` 里绕过去。

### 两种口径，用 `--context` 选

| | `--context shape` | `--context full`（**当前默认**） |
|---|---|---|
| 发什么 | 只发方法链 `KeyPairGenerator.getInstance` | 额外发命中的代码行 |
| 实测 payload | 53,490 字符 | 59,810 字符（+12%） |
| 源码出网 | 否 | **是**（但无路径、无密钥） |
| §19 口径 | 原样遵守 | **放宽，需在计划文档里记一笔** |

两种模式都会做这两件事，**它们对判用途零帮助，删掉不损失准确率**：

- 绝对路径 → 只留文件名
- 疑似密钥 / token / 长 base64 → `<REDACTED>`

> 要回到 §19 的严格口径：加 `--context shape`。

### 为什么 `full` 是默认

判用途最可靠的线索是**调用了哪个 API**，而有些关键信息在字符串字面量里：

```java
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                                    ↑ 方法链抽不出这个，但 GCM 和 ECB 是两回事
```

另外要清楚 **`full` 对一部分条目完全没有作用**：实测 28/91 条两种模式发的东西
**一模一样** —— 因为 cbom-scan 的证据里根本没有源码，`raw` 就只有
`{id, algo, prim, risk}` 四个字段。这些条目要靠 `upstream.prim`（`block-cipher` /
`hash` / `signature` / `kem`…）来判用途，那本身就是个不错的线索。

---

## 两条额外约束

### `explanation` 必须能对应到证据

方案 §8：AI 输出必须**结构化且带 `evidence_refs`**。

> ✅ **`evidence_refs` 已实现** —— `core/schema/finding.v0.1.json` 已定义该字段，
> `ai/enrich.py` 会校验引用编号的格式、范围与重复项，并将合法引用写回 Finding。
> `ai/selftest.py` 已覆盖正常引用、非法编号、越界、重复项及异常输入等情况。
> 当前离线自测已通过；真实模型输出的语义准确性仍需进一步集成验证。

别让模型自由发挥。**每句解释都要能指回 `evidence[]` 里的具体某条。**
写不出来的话，说明证据不足，那就照实说证据不足。

### 输出格式：为什么不用 tool use

`ai/README` 原先要求「用结构化输出（JSON mode / tool use），不要用自然语言让它自己拼 JSON」。

当前实现**没有走 tool use**：DeepSeek 的 Anthropic 兼容端点对 `tools` 的支持未经验证，
写一条跑不通的路径不如不写。替代方案是 `parse_llm_json()` —— 剥 ``` 围栏、
按花括号配对提取 JSON 对象、正确跳过字符串内的括号和转义。

**待办**：真跑一次确认端点支持 `tools` 后，可以换成 tool use 强制 schema。

---

## 出错和断点续跑

跑 91 次串行调用，中途撞上限流或网络抖动是**大概率事件**。所以：

- **单条失败不中断** —— 记下来跳过，其余照常跑完
- **每 10 条落一次盘**（`--checkpoint N` 可调）
- **失败的条目保持 `source="none"`** —— 于是进度条天然能数出失败了几条，
  `--resume` 也会自动重试它们（不需要额外的失败清单）

```bash
python ai/enrich.py out\findings.json -o out\findings_ai.json --resume
```

---

## 目录约定

```
ai/
├── README.md           本文件
├── enrich.py           主入口
├── redact.py           云请求前的脱敏（§19）+ 自检
├── selftest.py         离线自检：桩 LLM，不花钱
├── requirements.txt    依赖
└── prompts/            prompt 模板（暂无，prompt 现在写在 enrich.py 里）
```

**规则库不在这里。** 密码学确定事实放 `core/rules/`，两边共用。

### 自检怎么跑

```bash
python ai/redact.py      # 脱敏自检：既查泄露，也查「过度脱敏」
python ai/selftest.py    # 全流程：桩 LLM 跑 91 条
```

两个自检断言的都是**外部事实** —— 「过 schema」「源码没出网」「包围栏不崩」，
不是「代码就是这么写的」。**如果你改了实现而自检仍然全过，先怀疑自检。**
