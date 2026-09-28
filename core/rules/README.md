# core/rules/ —— 规则库：密码学确定事实

> **原则（方案 §8）：AI 不负责密码学确定事实，由规则库回答。**

---

## 为什么必须单独有这么一层

因为**上游工具的结论不能直接信**。实测证据：

> CryptoScan 把 MD5 / SHA-1 / DES / 3DES / RSA-1024 全标成 `VULNERABLE`
> （即"量子脆弱"）。
>
> 但**这些是被经典攻击攻破的，跟量子计算机无关**。Shor 算法对哈希和对称密码无效。
>
> 直接采信，报告就会写出「MD5 受 Shor 算法威胁」—— **一个错误的密码学结论**，
> 而且中文渲染之后它看起来更权威，危害更大。

所以确定性判定由规则库做，并**在报告里显式标出与上游的分歧**。

> 💡 这个分歧是**答辩素材** —— "上游工具不可信、必须经融合层复核"的现场实证。

---

## 已有的

### `pqc_routing.py` ✅

方案 §9.1「**禁止 `RSA → 固定某一种 PQC` 映射**」的落地实现。

```python
from core.rules.pqc_routing import route

route('RSA', 'signing')      # -> decided=True, ML-DSA (FIPS 204)
route('RSA', 'encryption')   # -> decided=True, ML-KEM (FIPS 203)
route('RSA', 'key_exchange') # -> decided=True, ML-KEM (FIPS 203)
route('RSA', 'unknown')      # -> decided=False，明确不给算法
```

**核心设计**：把"生成算法建议"这件事**从大模型手里拿走**。

```
LLM 只判断用途  →  本模块查表  →  得出算法
用途判不出来     →  decided=False，不许猜
```

纯标准库、无依赖、自带自检：

```bash
python core/rules/pqc_routing.py     # 退出码 0 = 全部断言通过
```

自检里最关键的几条断言：

- `RSA/签名` 的路线**不得出现 ML-KEM** —— 这是 §9.1 的核心
- 用途为 `unknown` / `None` / `''` / `general` 时，必须 `decided=False`
- `Ed25519` / `ed25519` / `Ed25519 / X25519` / `EDDSA` 四种写法归一后命中同一规则

---

## 待补的

### 1. 量子风险分类表

五档口径（见 `core/schema/README.md`）：

| 值 | 含义 | 典型 |
|---|---|---|
| `shor` | 量子可完全攻破 | RSA, ECC, ECDH, Ed25519 |
| `broken` | **已被经典攻击攻破，与量子无关** | MD5, SHA-1, DES, 3DES, RSA-1024 |
| `grover` | 量子下强度减半 | AES-128, SHA-256 |
| `review` | 需人工确认 | 密钥长度不明 |
| `safe` | 安全 | AES-256, SHA-3, ML-KEM, ML-DSA |

> smoke 阶段的 `zh_map.json` 里有初版（25 个 type 的完整映射），可以直接搬过来。

**`broken` 这一档必须存在** —— 它就是用来纠正 CryptoScan 那个错误的。

### 2. 算法归一化表

三个工具对同一算法的叫法不同：

```
'Ed25519'  /  'ed25519'  /  'Ed25519 / X25519'   →  ED25519
'RSA'      /  'RSA-1024' /  'RSA Algorithm'      →  RSA
```

不归一，去重和跨工具对齐都会失败。

### 3. 凭据检测规则

方案要求 **≥8 类凭据缺陷**。现有工具全部家当：

- CryptoScan：**9 条正则** —— 6 个 PEM 头 + 3 个按变量名匹配（`jwt_secret` / `aes_key` / `hmac_secret`）
- **没有熵检测**

**覆盖不到一半，这块基本要从零自研。**

---

## 约定

- **确定性的东西放这里，不确定的放 `ai/`。** 判断标准：
  「这条结论换了谁来问，答案都一样吗？」—— 是，就放规则库。
- **每条规则带标准依据**（FIPS / SP 800 / RFC），答辩时用得上。
- **规则库未覆盖时如实说不知道**，不要编 —— 见 `pqc_routing.route()` 的第 3 个分支。
