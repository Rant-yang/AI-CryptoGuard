# core/rules/ —— 规则库：密码学确定事实

`quantum_rules.json` 是扫描后、AI 前的量子风险评估规则注册表，提供稳定规则编号与版本；`core/quantum_assessment.py` 负责引用它。PQC 的具体迁移路线仍由 `pqc_routing.py` 按实际用途决定，不能由 AI 或该注册表直接猜测。

`core/quantum_timeline.py` 在同一确定性层计算量子危机时间窗口：用户提供 X（安全有效期）、Y（迁移准备期）、Z（量子威胁时间窗），程序按 `X + Y >= Z` 判断是否已经需要启动迁移，并独立标记 HNDL。它不预测 Q-Day，也不允许模型代填业务参数。

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

### `zh_map.json` ✅ —— 中文字段的**唯一**副本

从 smoke 阶段提升上来的中文词表：算法名、风险说明、用途、修复建议、
CrySentry 判定类型等的中英对照。

**它同时服务两个消费者：**

```
core/rules/zh_map.json
        ├──→ CLI 报告（report_cn.py）
        └──→ API / 前端（以后）
```

**刻意不保留第二份副本** —— 两份词表迟早会不一致，而"同一句话在两个地方不一样"
是这类项目最难查的 bug。

> ⚠️ 前端要中文，**不要用中文替换掉英文枚举**，而是加**平行的展示字段**：
>
> ```json
> { "severity": "high",              // 机器键：排序、筛选、统计靠它
>   "localized": { "severity": "高" } // 展示值：界面直接渲染
> }
> ```
>
> 详见 `core/schema/README.md`。

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

### Java 深度配置规则

`deep_java.py` 保存可定位的弱随机密钥流规则编号、展示名称和确定性整改文本。
`scanner/adapters/crysentry.py` 只在 CrySentry 的已核对来源模型与明确的
`SecretKeySpec` 汇点同时成立时使用；`ai/enrich_v02.py` 在本地解释并引用证据。
这条规则不是量子迁移规则，不允许因为有 `SecretKeySpec` 就猜测实际业务用途。


- **确定性的东西放这里，不确定的放 `ai/`。** 判断标准：
  「这条结论换了谁来问，答案都一样吗？」—— 是，就放规则库。
- **每条规则带标准依据**（FIPS / SP 800 / RFC），答辩时用得上。
- **规则库未覆盖时如实说不知道**，不要编 —— 见 `pqc_routing.route()` 的第 3 个分支。
