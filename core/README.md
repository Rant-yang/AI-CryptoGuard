# core/ —— 统一格式 · 规则库 · 主流程

> **2026-10-15：C0 契约、C1 前置量子评估、量子危机时间窗口及 C2 统一入口第一阶段已实现。** 先读 [详细操作指南](../docs/本轮操作指南_2026-10-14.md) 和 [下一步计划](../docs/下一步计划.md)。

> **负责人：C**
> **一句话：把 scanner 和 ai 拼起来，并证明整个系统真的有效。**

```
一个项目目录
        ↓
   core/pipeline.py          ← 快速扫描 + 任务状态
        ↓
findings_assessed.json       ← 量子评估在 AI 之前
        ↓
AI v0.2（等待 B 合入）+ Java 深度证据（等待 A 合入）
```

---

## 这个目录放什么

```
core/
├── schema/         v0.1 兼容契约 + 本轮 v0.2 阶段契约
├── rules/          PQC 路由 + 量子评估规则注册表
├── quantum_assessment.py  扫描后、AI 前的确定性评估
├── quantum_timeline.py    X/Y/Z 迁移窗口 + HNDL 评估
├── pipeline.py     C 线统一入口
├── selftest.py     离线入口与评估回归
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

### `schema/` —— v0.1 兼容 + v0.2 阶段契约 ✅

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

## C 线统一入口（已实现第一阶段）

完整快速扫描：

```cmd
python core\pipeline.py D:\待扫描项目 --tools-dir D:\code_competition\_smoke -o out\run
```

可选的量子危机时间窗口（X/Y/Z 必须一起给）：

```cmd
python core\pipeline.py D:\待扫描项目 --tools-dir D:\code_competition\_smoke -o out\run --data-lifetime-years 10 --migration-lead-years 3 --threat-horizon-years 8 --hndl-exposure yes
```

这里的 Z 是用户或组织采用的威胁时间窗，不是系统预测的 Q-Day。

只评估已有扫描结果：

```cmd
python core\pipeline.py --findings out\findings.json -o out\run
python core\schema\validate_v02.py out\run\findings_assessed.json
```

产出 `findings_assessed.json` 与 `task.json`。当前 A/B 的新接口尚未合入，
相应阶段明确标记 `skipped`，不会把未执行写成成功。`out/` 不入库。
离线自检：`python core\selftest.py`。

## 待做的

### 1. 接入 A/B v0.2 交付

### 2. `rules/` 补齐

现在只有 `pqc_routing.py`。还需要：
- **量子风险分类表**（`shor` / `broken` / `grover` / `review` / `safe`）
  —— smoke 阶段的 `zh_map.json` 里有初版，可以直接搬过来
- **算法归一化表**（三个工具对同一算法的叫法不同）
- **凭据检测规则**（方案要 ≥8 类，现有工具覆盖不到一半）

### 3. `report.py` —— 离线中文报告

现已按 v0.2 Finding 与 Task 渲染自包含 HTML，只取归一化字段、规则结果、
AI 解释、整改步骤和证据编号；`evidence.raw` 永不进入报告。
`python core/report.py out/run/findings_assessed.json -o out/run/report.html --task out/run/task.json`
仅生成待人工复核的审计报告，不表示候选补丁已部署或通过行为兼容性验证。

---

## 两个硬约束（方案 §19）

- **扫描产物不入库** —— 含绝对路径（信息泄露），凭据类结果可能含明文
- **云端 LLM 请求前必须 redaction** —— `evidence[].raw` 里可能有明文凭据

`.gitignore` 已经挡了。**但 `git add -f` 能强行绕过，别那么干。**
