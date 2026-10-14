# core/ —— 统一格式 · 规则库 · 主流程

> **本轮任务（待实现）：C：共享契约、前置量子风险评估、调度和缓存引用约束。** 先读 [详细操作指南](../docs/本轮操作指南_2026-10-14.md) 和 [下一步计划](../docs/下一步计划.md)。现有用法继续有效，拟新增字段/参数以 C 的契约提交为准。

> **负责人：C**
> **一句话：把 scanner 和 ai 拼起来，并证明整个系统真的有效。**

```
scanner/findings.json
        ↓
   core/pipeline.py          ← 主流程（待写）
        ↓
ai/findings_ai.json
        ↓
   报告 + 指标（Precision / Recall）
```

---

## 这个目录放什么

```
core/
├── schema/         统一 Finding 格式 v0.1（所有人写代码的契约）
├── rules/          规则库：密码学确定事实（不由大模型回答）
├── pipeline.py     主流程，串起 scanner 和 ai（待写）
└── report.py       渲染报告（待写）
```

---

## 规则库为什么必须存在

方案 §8 的原则：**AI 不负责密码学确定事实，由规则库回答。**

原因很实在 —— 看实测的例子：

> CryptoScan 把 MD5 标成「量子脆弱（Shor 算法可破）」。
> 但 MD5 是哈希原语，**Shor 算法对它无效**，它是被**经典攻击**攻破的。

如果直接采信上游，报告就会写出**错误的密码学结论**。而中文渲染之后它看起来更权威，
危害更大。所以确定性判定必须由我们自己的规则库做，并且在报告里**显式标出与上游的分歧**。

> 💡 这个分歧本身就是**答辩素材** —— 它是"上游工具不可信、必须经融合层复核"的现场实证。

---

## 已有的东西

### `schema/` —— 统一格式 v0.1 ✅

- 定义：`schema/finding.v0.1.json`（JSON Schema draft-07）
- 自检：`python core/schema/validate.py <findings.json>`
- 说明：`schema/README.md` ← **动手前先读这个**

### `rules/pqc_routing.py` —— PQC 迁移路线判定 ✅

方案 §9.1「禁止 `RSA → 固定某一种 PQC` 映射」的落地实现。

```python
from core.rules.pqc_routing import route

route('RSA', 'signing')     # -> ML-DSA (FIPS 204)
route('RSA', 'encryption')  # -> ML-KEM (FIPS 203)
route('RSA', 'unknown')     # -> decided=False，明确不给算法
```

纯标准库、无依赖、自带自检：

```bash
python core/rules/pqc_routing.py     # 全部断言通过则退出码 0
```

**`ai/` 模块直接 import 它，不要自己再写一遍判定逻辑。**

---

## 待做的

### 1. `pipeline.py` —— 主流程

```bash
python core/pipeline.py <项目路径> -o out/report.md
```

依次调用 scanner → ai → 生成报告。

### 2. `rules/` 补齐

现在只有 `pqc_routing.py`。还需要：
- **量子风险分类表**（`shor` / `broken` / `grover` / `review` / `safe`）
  —— smoke 阶段的 `zh_map.json` 里有初版，可以直接搬过来
- **算法归一化表**（三个工具对同一算法的叫法不同）
- **凭据检测规则**（方案要 ≥8 类，现有工具覆盖不到一半）

### 3. `report.py` —— 报告渲染

smoke 阶段的 `report_cn.py` 是原型（已验证跑通），可以搬过来改造。
它落实了两条原则：规则库覆盖上游、公钥算法按用途分派。

---

## 两个硬约束（方案 §19）

- **扫描产物不入库** —— 含绝对路径（信息泄露），凭据类结果可能含明文
- **云端 LLM 请求前必须 redaction** —— `evidence[].raw` 里可能有明文凭据

`.gitignore` 已经挡了。**但 `git add -f` 能强行绕过，别那么干。**
