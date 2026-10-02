# 统一 Finding 格式 v0.1

**这是所有人写代码的共同契约。动手前先看懂这一页。**

- 机器可读的定义：[`finding.v0.1.json`](finding.v0.1.json)（JSON Schema draft-07）
- 自检工具：[`validate.py`](validate.py)
- 示例：[`../samples/example_finding.json`](../samples/example_finding.json)

```bash
pip install jsonschema
python core/schema/validate.py out/findings.json
```

---

## 一、为什么要有这个东西

不是"为了规范而规范"。是因为**三个工具现在各说各话，连"一条问题"怎么数都不同**：

| 工具 | 原始结果 | 去重后 | 按什么去重 |
|---|---|---|---|
| cbom-scan | 171 处命中 | **14** | 按「算法」 |
| CryptoScan | 110 条 | **45** | 按「文件+算法」 |
| CrySentry | 8 条 | **3** | 按「类+敏感API」 |

最后要报"识别率 90%"，**分母是多少都说不清**，这个数字就是假的。

所以第一件事是把**计数单位定死**。

---

## 二、计数单位（最重要的一条）

> ### 一条 finding = 一个 (文件, 算法, 用途) 组合

同一文件里同一个算法的**多处命中，合并成一条**，行号全部收进 `evidence[].lines`。

拿实测数据举例：

```
cbom-scan 的 Ed25519/X25519：32 处命中
  → 分布在 4 个文件里
  → 在 crypto_samples.go 里生成 1 条 finding，evidence[0].lines = [19,63,65,66,69,70,71,74,...]
```

**为什么 `usage` 要进计数单位**：同一个文件里的 RSA 可能一处用来签名、一处用来加密。
它们**迁移路线完全不同**（签名→ML-DSA，加密→ML-KEM），所以**必须算两条**。
把它们合并成一条，就等于强迫我们给一个自相矛盾的建议。

### 合并时各字段取哪个值？（必须有明确规则）

同一分组内部的字段值**可能不一致**。实测 45 个分组里有 **6 个**的严重程度是混合的：

```
crypto_samples.go / MD5     严重程度 [4, 2]     ← 真实调用是「严重」，注释提及是「中」
crypto_samples.go / RSA     [3, 3, 3, 3, 1]
crypto_samples.go / ECC     [3×11, 1×2]
crypto_samples.py / RSA     [4, 3, 3, 3, 3, 3, 3]
```

原因很合理：**CryptoScan 会给注释 / 测试 / 文档里的命中降级**，
所以同一个算法的"真实调用"和"注释里提了一句"会落进同一个分组。

**v0.1 定死的规则：**

| 字段 | 合并时取 | 为什么 |
|---|---|---|
| `severity` | **最大值** | 真实使用不该被一条注释提及拉低 |
| `risk` | **最严重的那档** | 顺序：`shor`/`broken` > `grover` > `review` > `safe` |
| `confidence` | **最大值** | 只要有一个证据源是高置信，就值得人看一眼 |
| `usage` | —— | 用途不同**就是不同的 finding**，根本不会合并 |

> ⚠️ 取"分组里第一条"在实测数据上**碰巧也对**（6 个分组的第一条恰好都是最大值），
> 但那是**靠 JSON 里的顺序，不是靠规则** —— 顺序一变就会把严重程度报低。

---

## 三、三个设计要点

### 1. `evidence[]` 是数组，不是单个字段

```json
"evidence": [
  {"tool": "cbom-scan",  "kind": "pattern", "lines": [42, 55], "raw": {...}},
  {"tool": "cryptoscan", "kind": "pattern", "lines": [42],     "raw": {...}}
]
```

这是**我们区别于单个工具的地方**：一条问题可以挂着多个工具的证据。

- 满足方案 §8「AI 输出必须带 `evidence_refs`」
- 是方案「≥3 类证据」的落地方式
- `raw` 逐字保留上游原始记录 —— 答辩被问"你凭什么这么说"时，直接把原文摆出来

**自研模块也要如实填 `tool`**（如 `python-ast`、`credential-scan`），不要伪装成第三方。

### 2. `risk` 是我们自己的判定，不透传上游

```json
"risk": "shor" | "broken" | "grover" | "review" | "safe"
```

五档口径**对齐 cbom-scan**，因为它是三个工具里**唯一分类正确的**：

| 值 | 含义 |
|---|---|
| `shor` | 公钥密码，量子计算机成熟后可被完全攻破 |
| `broken` | **已被经典攻击攻破 —— 与量子无关** |
| `grover` | 对称密码，量子下强度大致减半 |
| `review` | 需人工确认 |
| `safe` | 安全 |

> ⚠️ **`broken` 这一档必须存在。** CryptoScan 会把 MD5 / SHA-1 / DES / 3DES / RSA-1024
> 全标成 `VULNERABLE`，等于说"MD5 受 Shor 算法威胁" —— 这是**错误的密码学结论**。
> 直接透传上游，报告就会出错。**必须由规则库覆盖**（见 `core/rules/`）。

### 3. `remediation.decided` 是方案 §9.1 的落地

```json
"remediation": {
  "decided": false,
  "action": "用途未能判定，暂不给出具体算法。需先确认……",
  "source": "rule-base"
}
```

方案 §9.1 **明文禁止** `RSA → 固定某一种 PQC` 的映射。所以：

```
LLM 只判断用途  →  规则库查表  →  得到算法
用途判不出来    →  decided: false，明确说"暂不给算法"，不许猜
```

`decided: false` **不是错误状态，是正确输出**。前端和报告**必须把它显示出来**，
不许静默填一个默认算法。

`source` 字段说明这条建议从哪来：
- `rule-base` —— 密码学确定事实，可信
- `ai` —— 大模型生成，**要打问号**
- `none` —— **尚未增强**（见下）

### 4. `remediation` 是**必填**，任何阶段都不许省略

> **2026-10-02 收紧。** 原文只写了"必须把它显示出来"，却没把 `remediation`
> 列进 `required`。结果 scanner 层产出的 91 条**一条都没带这个字段**，
> 而校验器全部放行 —— **规则要求"必须显示"，校验器却允许"完全省略"，
> 这条规矩当时是没有牙齿的。**

现在的约定：**字段永远在**。还没做就填**占位符**：

```json
"remediation": {
  "decided": false,
  "action": "尚未增强：用途需先经 ai/ 复核，再由 core/rules/pqc_routing.py 按用途分派算法。",
  "source": "none"
}
```

**为什么要占位符，而不是干脆省略：**

| | 字段在（填占位符） | 字段省略 |
|---|---|---|
| 区分「还没做」和「忘了做」 | ✅ 看 `source` | ❌ 两者长得一样 |
| 前端渲染 | 直接打出"待定" | 得写空值分支，容易静默跳过 |
| 度量 AI 层进度 | 数 `source=="none"` 的条数 | 数不出来 |

`validate.py` 会顺手打出这个分布 —— **那就是 ai/ 层的进度条**：

```
remediation.source: rule-base 0  none 91
```

**为什么 scanner 层只给占位符、不给真建议**：scanner 判出的 `usage` 还没经
ai/ 复核（实测 22 条挂着 `needs-usage-review`）。据未复核的用途去路由，会得到
**「建立在错误用途上的正确算法」** —— 那正是 §9.1 要避免的。所以本层如实说"还没做"。

> ⚠️ **计数不变**：`source=="none"` 的条目**照样算一条 finding**。
> "还没增强"不影响识别率的分母。

---

## 四、已知的上游表示法差异（转换时必须处理）

| 字段 | 上游给什么 | 我们要什么 |
|---|---|---|
| `file` | CryptoScan 给**绝对路径** | 项目内**相对路径**，正斜杠 |
| `severity` | CryptoScan 给**整数 0–4** | 字符串 `critical/high/medium/low/info` |
| `confidence` | CryptoScan 给**枚举** `HIGH/MEDIUM/LOW` | 浮点 0–1（HIGH=0.9, MEDIUM=0.6, LOW=0.3） |
| `usage` | CryptoScan 叫 `purpose`；cbom-scan 叫 `prim` | 统一 enum（见 schema） |
| `risk` | CryptoScan 叫 `quantumRisk`（**语义有误**）；cbom-scan 叫 `risk`（正确） | 五档 enum |

> ⚠️ **CryptoScan 一份 JSON 里有两套严重程度表示法**：
> `findings[].severity` 是**整数**，`summary.bySeverity` 的**键是字符串**。
> 写转换器时别混用。

---

## 五、版本管理

- 现在就是 **v0.1**，够用就行，**不要追求完美**
- 改字段：升 v0.2，并且**在 `docs/` 里记一笔为什么改**
- **不要偷偷加字段** —— Schema 开了 `additionalProperties: false`，
  加字段会让所有人的校验失败。这是故意的：让变更可见。

### 变更记录

| 日期 | 改了什么 | 谁 | 是否升版本 |
|---|---|---|---|
| 2026-09-28 | 首版 v0.1 | C | —— |
| 2026-09-28 | 写入分组内字段合并规则（severity 取 MAX 等） | C | 否 |
| **2026-10-02** | **`remediation` 由可选改为必填**，补占位符约定 | C | **否（见下）** |

> **为什么这次没升 v0.2**：**字段集合没变** —— 没有增删改任何字段名，
> 只是把一个已存在的字段从可选收紧为必填。升版本号会连带改
> `schema_version` 常量，而 producer（`scanner/merge.py`）里是硬编码的，
> 会引发一轮纯机械的改动，收益不抵成本。
>
> **但这是一次破坏性收紧**：任何产出 findings 的代码都必须补上这个字段。
> 当前 producer 只有 scanner 一处，已在同一次提交里补齐。**若之后还有别的
> producer 出现，这条记录就是它的迁移依据。**
