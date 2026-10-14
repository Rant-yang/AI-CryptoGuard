> **2026-10-14：本轮共享契约已发布。** 请先阅读 [v0.2 接口与交接说明](core/schema/CONTRACT_V0.2.md)。当前 v0.1 演示保持可用，新能力按 v0.2 开发。

# AI-CryptoGuard

> **本轮工作已确定（2026-10-14，新增功能待实现）：** Java 深度证据 → 量子风险评估 → AI 用途解释与具体整改。
> 三人按 [本轮操作指南](docs/本轮操作指南_2026-10-14.md) 开工，任务依赖与后续安排见 [下一步计划](docs/下一步计划.md)。

**基于多源证据融合与大模型推理的智能密码安全审计与抗量子迁移系统**

全国密码技术竞赛 · 复赛作品 · 三人团队
**提交截止 2026-10-23（10-22 内部冻结）**

---

> 🚪 **第一次来？先读 [`docs/项目现状.md`](docs/项目现状.md)。**
> 那篇是「从 0 同步」的入口：项目是什么、做到哪了、还差什么、几个口径的坑。
> **本篇讲的是项目本身和团队规矩；进度现状以那篇为准。**

---

## 这个项目做什么

给它一个代码项目，它会告诉你：

1. 代码里有哪些密码用法
2. 哪些有风险、为什么有风险（讲人话）
3. 应该怎么修
4. 如果要迁移到抗量子密码（PQC），应该换成什么

```
   一个代码项目
        ↓
   现成的开源扫描工具        ← 不是我们写的（见「第三方 vs 自研」）
        ↓
   我们做：统一整理           ← core/
        ↓
   我们做：AI 解读            ← ai/
        ↓
   报告 / 修复建议 / 迁移建议
```

**我们不自研密码扫描器。** 我们的作品是中间那两层：把三个各说各话的工具
对齐成统一的证据格式，再用 AI 把它解读成人能看懂、能执行的结论。

---

## 为什么需要中间这层（这不是多余的）

因为三个工具**互相打架**，实测数据：

| 工具 | 原始结果 | 去重后 | 按什么去重 |
|---|---|---|---|
| cbom-scan | 171 处命中 | **14** | 按「算法」 |
| CryptoScan | 110 条 | **45** | 按「文件+算法」 |
| CrySentry | 8 条 | **3** | 按「类+敏感API」 |

连"这算一条还是三条"三家都不一样 —— 不统一，识别率就是一笔糊涂账。

更严重的是**结论冲突**：CryptoScan 把 MD5 标成"量子脆弱"，
但 MD5 是被**经典攻击**攻破的，跟量子计算机无关。cbom-scan 分得对，CryptoScan 分错了。

> **上游工具的结论不能直接信** —— 这就是融合层存在的理由。

---

## 三个人怎么分工

按**软件流水线**分，不按密码专业方向分（三个工具已经把密码学封装掉了）。

| 人 | 角色 | 输入 → 输出 | 主目录 |
|---|---|---|---|
| **A** | 找问题 | 一个项目文件夹 → `findings.json` | `scanner/` |
| **B** | 讲人话 | `findings.json` → 带 AI 解读的版本 | `ai/` |
| **C** | 集成 + 验收 | 把 A 和 B 串起来 → 报告 + 准确率 | `core/` `benchmark/` `docs/` |

**第一版只做 cbom-scan + CryptoScan。**
CrySentry 是独立的第二阶段（它要 JDK 17 + 目标项目**先编译成功**，不是"输入路径就能跑"）。

---

## 仓库结构

```
AI-CryptoGuard/
├── core/                  ← 统一格式 + 串流程 + 报告
│   ├── schema/            统一 Finding 格式（v0.1）
│   └── samples/           格式示例
├── scanner/               ← A：调用扫描工具，产出统一格式
├── ai/                    ← B：LLM 解读，产出解释与建议
├── web/                   ← C：结果查看器（单文件，可离线）
├── repair/                ← 3 类 Python Repair → Verify（临时副本 + 重扫）
├── benchmark/             ← C：算准确率用。五个模块 + 1411 条公开 benchmark 标签
│   ├── scope.py           裁定表：benchmark 的类别 → 我方轴（范围内/部分/范围外）
│   ├── meta.py            从 benchmark 自带元数据逐文件读真值（算法清单不许手写）
│   ├── anonymize.py       跑分前匿名化（文件名+目录名+源码内容，否则答案会喂给大模型）
│   ├── adapters.py        四家 benchmark 标签 → 统一格式
│   └── eval.py            算 Precision / Recall / F1
├── setup/                 ← 三个工具怎么装（工具本体不入库）
└── docs/                  ← 会议纪要、进度文档
```

> `benchmark/` 的数据（`labels/`、`_anon/`）**不入库** —— 它们是从第三方
> benchmark 派生的。仓库里只留我们自己的适配代码，数据靠
> `python -m benchmark.adapters` 重新生成（需先把 benchmark 下到 `../_benchmarks/`）。

---

## 快速开始

```bash
git clone https://github.com/Rant-yang/AI-CryptoGuard.git
cd AI-CryptoGuard
```

**先把工具装好** —— 见 [`setup/README.md`](setup/README.md)。三个工具都不入库，要自己下。

**然后读统一格式** —— 见 [`core/schema/README.md`](core/schema/README.md)。
这是所有人写代码的共同契约，**动手前先看懂它**。

**想看效果** —— 端到端跑一遍（scanner → ai → 界面）：

```bash
pip install -r ai/requirements.txt

python scanner/scan.py <要扫描的目录> -o out/findings.json     # A：找问题
python ai/enrich.py out/findings.json -o out/findings_ai.json   # B：讲人话
python web/serve.py                                             # C：看结果
```

每一步都有自检，改完代码先跑一遍：

```bash
python scanner/selftest.py       # A
python ai/selftest.py            # B（桩 LLM，不花钱）
node   web/selftest.js           # C
python core/schema/validate.py out/findings_ai.json
```

---

## 三条红线

这三条踩了会出事，改代码前先确认没违反：

### 1. 禁止让 AI 自由生成「该换成什么算法」

方案 §9.1 明文禁止 `RSA → 固定某一种 PQC` 的映射。正确做法是两段式：

```
LLM 只判断用途（签名？加密？密钥交换？）
        ↓
规则库查表给算法
        ↓
签名 → ML-DSA / SLH-DSA      加密、密钥交换 → ML-KEM
判不出来 → 明确说「暂不给出具体算法」，不许猜
```

`core/schema` 里的 `remediation.decided` 字段就是为这条设计的。

### 2. 第三方能力不表述为自研

方案 §19 要求第三方代码与自研代码严格分离。**答辩时必须能说清哪些是调用、哪些是我们写的。**

| 能力 | 来源 |
|---|---|
| 源码级密码模式扫描 | 第三方（cbom-scan / CryptoScan） |
| Java 字节码数据流分析 | 第三方（CrySentry，**LGPL-3.0**） |
| 统一证据格式与融合裁决 | **自研** |
| 规则库（密码学确定事实） | **自研** |
| 凭据检测 | **自研**（现有工具覆盖不到一半） |
| Python AST 分析 | **自研** |
| AI 语义解读层 | **自研** |

### 3. `workspace/` 和 `.env` 永不入库；扫描产物不入库

扫描产物含**绝对路径**（信息泄露），凭据类结果可能含**明文凭据**。
`.gitignore` 已经挡了，但 `git add -f` 能强行绕过 —— **别那么干**。

---

## 团队协作

### 分支已经建好了，直接切过去

```
main                ← 随时能跑。**只有 C 能往这里合**
 ↑
 ├── feat/scanner   ← A 在这里写
 └── feat/ai        ← B 在这里写
```

| 谁 | 分支 | 只动这个目录 |
|---|---|---|
| **A** | `feat/scanner` | `scanner/` |
| **B** | `feat/ai` | `ai/` |
| **C** | `main` | `core/` `benchmark/` `docs/` |

### A 和 B 的开场动作

```bash
git clone https://github.com/Rant-yang/AI-CryptoGuard.git
cd AI-CryptoGuard
git checkout feat/scanner        # B 换成 feat/ai
```

之后就是普通的：写代码 → `git add scanner/` → `git commit -m "..."` → `git push`。

**每次开工前先 `git pull`。** 这一条能避免绝大多数冲突。

### 🔴 三条不能破的规矩

**1. 永远不要往 `main` 推。**

你推上去的半成品，别人 pull 下来一跑就崩 —— 而 `main` 是 10-22 之后要拿去演示的版本。

**2. 不要用 GitHub 网页版的「新建文件 / 上传文件」按钮。**

网页版建的文件**直接进 main，绕过分支**，这是最容易犯的错。
（2026-09-29 已经有两位同学这么干过，建了两个空文件。）

**3. `core/` 和 `docs/` 顶层只有 C 能改。**

`core/schema/` 是三个人共同的契约，而且刻意开了 `additionalProperties: false` ——
**谁偷偷加一个字段，所有人的校验全部失败。**

觉得字段不够用 → 告诉 C → **由 C 改**。

> 这一条不定死，分支开再多也没用：冲突会全部集中爆发在 `core/`。

**不搞 PR、不搞 review、不搞 CI/CD。** 这个阶段流程越轻越好。
C 定期把两条分支合回 `main`，合并前跑一遍 `core/schema/validate.py`
和 `core/rules/pqc_routing.py`（后者自带自检，退出码 0 = 通过）。

---

## 当前状态（2026-10-14）

> ⚠️ **本节是内部进度，不是对外文案。**
> 10-21~10-22 准备最终材料时要按方案 §20 / §21 重写。

> ⭐ 完整同步入口：[`docs/项目现状.md`](docs/项目现状.md)。
> 接手核查与执行顺序：[`docs/接手记录_2026-10-14.md`](docs/接手记录_2026-10-14.md)。

### 一、能跑的（全部已合并 `main`）

- ✅ 三个工具 smoke test 通过（`setup/README.md`）
- ✅ 统一 Finding 格式 v0.1（`core/schema/`）
- ✅ **scanner**（A）—— 调工具 → 统一格式
- ✅ **scanner 增强**—— 合并名拆词、本地常量传播、多语言补充、问题/线索分层
- ✅ **ai**（B）—— LLM 解读、云请求前脱敏、`evidence_refs`
- ✅ **规则库**（C）—— PQC 用途分派（`core/rules/`，自带自检）
- ✅ **结果查看器**（C）—— `web/`，显示 E1/E2 引用与证据卡片
- ✅ **端到端跑通**：扫描 → AI → 界面

### 二、当前可信基线（2026-10-14）

按显式扫描清单、范围对称、严格算法匹配重新计算；三个已扫描语料合计：

| 指标 | 当前 | 方案目标 |
|---|---:|---:|
| Precision | **68.1%**（TP 599 / FP 281） | ≥85% |
| Recall | **79.9%**（TP 599 / FN 151） | ≥90% |
| F1 | **73.5%** | — |

`cryptoapi-bench` 为 79.5% / 91.8%，`cambench-cap` 为 92.9% / 92.9%，
`llmcmt` 为 65.6% / 77.5%。凭据专项为 P=69.3%、R=74.3%、F1=71.7%；safe 资产留在 CBOM，无算法线索进入 leads；
仅落在范围外正样本上的检出从 P/R 两边对称排除。完整口径见 `benchmark/README.md`。

### 三、对照方案硬指标

| 方案要求 | 现状 | |
|---|---|---|
| 标注样本 ≥ 120（§2.2） | 1411 条派生标签记录；独立样本需去重后确认 | ⚠️ |
| ≥ 15 类密码安全问题（§2.2） | scope 映射约 30 类；实际可检出类别待正式统计 | ⚠️ |
| **凭据管理类 ≥ 8 类**（§2.2） | 8 类规则已接入 scanner；公开语料专项 P=69.3%、R=74.3% | ⚠️ **已实现，仍需留出集** |
| Recall ≥ 90%（§2.3） | 79.9%（算法 + 凭据新口径） | ❌ |
| Precision ≥ 85%（§2.3） | 68.1%（算法 + 凭据新口径） | ❌ |
| `evidence_refs`（§7 / §8.4） | 已实现、集成并在前端显示；真模型语义质量待抽样 | ⚠️ |
| ≥ 3 类 Repair → Verify（§10） | MD5、弱随机、硬编码口令已完成合成闭环；真实项目待验证 | ⚠️ |

### 四、下一步

本轮任务入口：[详细操作指南](docs/本轮操作指南_2026-10-14.md)；
持续看板：[下一步计划](docs/下一步计划.md)。以下均为待实现事项。

| 人员 | 本轮任务 | 交付 |
|---|---|---|
| A | Java CrySentry 深度调用、证据适配、同题对照 | 深度模式、失败状态、Java P/R 与耗时报告 |
| B | 结合前置量子评估解释实际用途、生成具体整改 | 结构化步骤、有效引用、30 条语义抽样 |
| C | 先发布契约，再做量子评估、统一调度、Web | 扫描 → 评估 → AI → 报告完整闭环 |

先由 C 发布 Schema 和夹具；A/B 并行实现，C 验收后合并。凭据留出集、真实
Repair→Verify、部署及比赛材料继续保留在后续计划中。

### 五、怎么自己验一遍

```bash
python benchmark/scope.py            # 裁定表自检（会交叉问规则库，不是复述自己）
python benchmark/scope.py --gaps     # 规则库缺口清单（那 9 条）
python benchmark/scope.py --report   # 范围外 636 条是怎么来的，逐条列出
python benchmark/anonymize.py        # 匿名化自检（泄漏清零 + 字面量未被改动）
python benchmark/eval.py out/verify/_all3.json --scanned cryptoapi-bench,cambench-cap,llmcmt
python benchmark/eval.py --selftest             # 口径回归
python scanner/credential_selftest.py            # 8 类凭据 + 零明文泄露
python repair/selftest.py                        # 3 类临时修复 + 重新验证
```
