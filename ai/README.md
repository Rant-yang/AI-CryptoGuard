# ai/ —— 讲人话

> **负责人：B**
> **一句话：把冷冰冰的扫描结果，变成一个人能看懂、能采取行动的结论。**

```
输入：findings.json               （统一格式，见 core/schema/）
  ↓
调用大模型（LLM）
  ↓
输出：findings_ai.json            （原字段 + explanation + remediation）
```

---

## 第一版要做什么（3~4 天）

**就一件事**：写一个程序，读 `findings.json`，调大模型，输出**带 `explanation` 的**版本。

验收标准：

```bash
python ai/enrich.py out\findings.json -o out\findings_ai.json
python core/schema/validate.py out\findings_ai.json     # 必须仍然退出码 0
```

**注意最后那条**：AI 处理完之后**仍然必须通过 schema 校验**。
所以别让大模型自由发挥输出格式 —— **用结构化输出**（JSON mode / tool use），
不要用自然语言让它自己拼 JSON。

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
> 直接调用，不用自己设计。

### 为什么这条这么重要

因为它同时踩中两件事：
1. **方案硬性规定**（§9.1 禁止固定映射）
2. **它是失分点**（评委最容易抓、也最容易解释不清的地方）

而它其实**很容易做对** —— 只要把"生成算法"这一步从 LLM 手里拿走。

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

## 两条额外约束

### 云端 LLM 请求前必须 redaction

方案 §19：**用户原始代码默认本地**。

如果把代码片段发给云端模型，**先脱敏**：
- 去掉/替换疑似密钥、token、密码
- 只发必要的上下文，别整文件发

`evidence[].raw` 里可能有上游抓到的**明文凭据** —— **发出去之前一定要过一遍**。

### `explanation` 必须能对应到证据

方案 §8：AI 输出必须**结构化且带 `evidence_refs`**。

别让模型自由发挥。**每句解释都要能指回 `evidence[]` 里的具体某条。**
写不出来的话，说明证据不足，那就照实说证据不足。

---

## 目录约定

```
ai/
├── README.md          本文件
├── enrich.py          主入口（待写）
└── prompts/           prompt 模板
```

**规则库不在这里。** 密码学确定事实放 `core/rules/`，两边共用。
