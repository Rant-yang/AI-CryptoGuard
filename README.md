# AI-CryptoGuard

**基于多源证据融合与大模型推理的智能密码安全审计与抗量子迁移系统**

全国密码技术竞赛 · 复赛作品 · 三人团队
**提交截止 2026-10-23（10-22 内部冻结）**

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

## 当前状态（2026-10-08）

> ⚠️ **本节是内部进度，不是对外文案。**
> 10-21~10-22 准备最终材料时要按方案 §20 / §21 重写。

> 📋 **下一步干什么 → [`docs/任务清单_2026-10-08.md`](docs/任务清单_2026-10-08.md)**
> 五个任务，逐条写清了「是什么 / 为什么 / 改哪里 / 怎么验收」。

### 一、能跑的（全部已合并 `main`）

- ✅ 三个工具 smoke test 通过（`setup/README.md`）
- ✅ 统一 Finding 格式 v0.1（`core/schema/`）
- ✅ **scanner**（A）—— 调工具 → 统一格式
- ✅ **ai**（B）—— LLM 解读 + 云请求前脱敏（§19）
- ✅ **规则库**（C）—— PQC 用途分派（`core/rules/`，自带自检）
- ✅ **结果查看器**（C）—— `web/`
- ✅ **端到端跑通**：扫描 → AI → 界面

### 二、实测的准确率（2026-10-08）

**在这之前，"准不准"这个数根本算不出来** —— 没有标注样本就没法算。
10-04 起有了（4 个公开 benchmark，1411 条标签），第一次跑出真实数字：

| 指标 | 10-04（首测） | **10-08（现在）** | 方案 §2.3 要求 |
|---|---|---|---|
| Recall | 37.9% | **40.5%** | ≥ 90% |
| Precision | 24.8% | **26.3%** | ≥ 85% |

> 10-08 的上升来自修掉 benchmark 标签里的一个 bug（类别级手写算法清单 → 从
> benchmark 自带元数据逐文件读）。**那次 bug 的教训**：`brokencrypto` 声明的是
> `(DES, 3DES)`，实际目录里有 DES / Blowfish / RC2 / RC4 / RC5 五种 ——
> 一次**正确的** Blowfish 检出会被**同时**记成漏报和误报，一笔扣两次。

**差距是结构性的，不是调参能解决的。** 漏掉的用例里，
算法名经**变量跨文件传入**：

```java
String crypto = "DES";                        // 文件 A
Cipher.getInstance(String.valueOf(crypto));   // 文件 B —— 这里只看到变量名
```

正则扫描**在结构上就看不见**。文献对照：专用研究工具 Cryptolation
在同一类 benchmark 上也只有 **47.4% Recall**。

> **所以这个数字是论据，不是污点** —— 它正是「为什么需要
> 多源融合 + 数据流分析 + 大模型」的实证。只做正则就宣称 90%，才是不诚实的。

### 三、对照方案硬指标

| 方案要求 | 现状 | |
|---|---|---|
| 标注样本 ≥ 120（§2.2） | **1411 条** | ✅ 超额 |
| ≥ 15 类密码安全问题（§2.2） | 范围内约 **30 类** | ✅ |
| **凭据管理类 ≥ 8 类**（§2.2） | **0 类** | ❌ **完全没开工** |
| Recall ≥ 90%（§2.3） | 40.5% | ❌ |
| Precision ≥ 85%（§2.3） | 26.3% | ❌ |
| `evidence_refs`（§7 / §8.4） | 已实现引用校验、去重、越界检查与写回；离线自测通过 | ✅ 代码完成，待集成验收 |
| ≥ 3 类 Repair → Verify（§10） | 未开始 | ❌ |

### 四、待办（2026-10-08 重排）

| # | 事项 | 归属 | 收益 |
|---|---|---|---|
| 1 | **合并名拆词** —— cbom-scan 给的是 `Legacy cipher (Blowfish/CAST5/IDEA/SEED)`，<br>归一后压成一坨，永远匹配不上单算法 | **A** | **94 条**误报 |
| 2 | **`type` 不许当算法** —— `scanner/adapters/cryptoscan.py:122` 在<br>`algorithm` 为空时退化成用 `type` 填，于是报告里出现「算法：Mutual TLS (mTLS)」 | **A** | **45 条**误报 |
| 3 | ~~**`evidence_refs`** —— 方案 §7 硬指标，AI 每条结论要带 `["E1","E3"]` 引用~~ —— 已实现校验、去重、越界检查与写回，离线自测通过 | **B** | ✅ 代码完成，待集成验收 |
| 4 | **8 类凭据检测** —— 方案唯一 0 进度的硬指标；<br>做完能把 **232 条**样本从「范围外」搬进「范围内」 | **C** | 最大单项 |
| 5 | **口径对称** —— Recall 分母剔了范围外，Precision 却把它们算成误报 | **C** | 191 条归位 |
| — | ~~补规则库 9 条缺口~~ | C | ✅ **10-08 已完成** |
| — | ~~查清 611 条误报构成~~ | C | ✅ **10-08 已完成**（见任务清单 §3） |

**每一条的「是什么 / 为什么 / 改哪里 / 怎么验收」，
见 [`docs/任务清单_2026-10-08.md`](docs/任务清单_2026-10-08.md)。**

**A 的两项加起来 139 条，是现在最划算的一步。**

> ⚠️ 误报构成里有 **165 条（118 干净文件 + 47 报错东西）还没逐条核实**，
> 先别动 —— 上一次就是在没核完的时候下了结论，结果连着推翻自己两次。

### 五、怎么自己验一遍

```bash
python benchmark/scope.py            # 裁定表自检（会交叉问规则库，不是复述自己）
python benchmark/scope.py --gaps     # 规则库缺口清单（那 9 条）
python benchmark/scope.py --report   # 范围外 636 条是怎么来的，逐条列出
python benchmark/anonymize.py        # 匿名化自检（泄漏清零 + 字面量未被改动）
python benchmark/eval.py out/bench/_all.json   # 算准确率
```
