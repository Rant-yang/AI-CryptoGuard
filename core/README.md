# core/ —— 统一格式 · 规则库 · 主流程

> **2026-10-18：统一入口已接通快速扫描、可选 CrySentry Java 深度证据、前置量子评估、可选 AI v0.2，以及离线 HTML 报告。** 当前能力与未完成项以[项目现状](../docs/项目现状.md)为准；[本轮操作指南](../docs/本轮操作指南_2026-10-14.md)保留当时的任务分工记录。

> **负责人：C**
> **一句话：把 scanner 和 ai 拼起来，并证明整个系统真的有效。**

```
一个项目目录
        ↓
   core/pipeline.py          ← 快速扫描 + 可选 Java 深扫 + 任务状态
        ↓
findings_assessed.json       ← 量子评估在 AI 之前；可显式开启 AI
        ↓
core/report.py              ← 自包含中文 HTML 审计报告
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
└── report.py       渲染自包含中文 HTML 报告
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

产出 `findings_assessed.json` 与 `task.json`。Java 深扫需要用户先提供同源码编译的
jar/classes、仓库外 CrySentry 和 JDK 17；AI 须显式传入 `--ai` 并配置模型端点。
未启用的阶段明确标记 `skipped`，失败也保留快速扫描结果，不能把未执行写成成功。
完整命令见 [CrySentry 集成验收](../docs/CrySentry集成验收_2026-10-18.md)和
[用户手册](../docs/用户手册.md)。`out/` 不入库。
离线自检：`python core\selftest.py`。

## 已接通的报告与仍需验收的边界

`core/report.py` 已按 v0.2 Finding 与 Task 渲染自包含 HTML，只取归一化字段、
规则结果、AI 解释、整改步骤和证据编号；`evidence.raw` 不进入报告：

```cmd
python core\report.py out\run\findings_assessed.json -o out\run\report.html --task out\run\task.json
```

报告是供人复核的建议，不能表示补丁已经部署或行为兼容性已经验证。
CrySentry 可提供额外 Java 证据，但固定 25 例同题对照的 P/R 未提升；污点链
只有来源与汇点位置时必须标为 `partial`。AI 输出通过 Schema 不等于语义正确，
当前公开样例的独立人工语义盲审仍未完成。具体边界见[项目现状](../docs/项目现状.md)。

---

## 两个硬约束（方案 §19）

- **扫描产物不入库** —— 含绝对路径（信息泄露），凭据类结果可能含明文
- **云端 LLM 请求前必须 redaction** —— `evidence[].raw` 里可能有明文凭据

`.gitignore` 已经挡了。**但 `git add -f` 能强行绕过，别那么干。**
