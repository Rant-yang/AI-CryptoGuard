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
- `none` —— 还没生成

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
