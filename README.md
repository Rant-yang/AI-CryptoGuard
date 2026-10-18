> **2026-10-18：共享契约、Java 深度调用、前置量子评估及可选 v0.2 AI 已接通。** 请先阅读 [项目现状](docs/项目现状.md) 与 [下一步计划](docs/下一步计划.md)；Java 同题对照见 [验收记录](docs/Java深度同题对照_2026-10-18.md)，真实第三方模块运行见 [Apache 验收](docs/Java深度真实项目验收_2026-10-18.md)。新环境先运行 [部署预检](setup/README.md#新环境先做只读预检)，第三方能力与分发边界见[来源说明](docs/第三方来源与分发边界.md)。
>
> **新增 Python 独立专项诊断：** OWASP Benchmark Python 151 个弱哈希文件首轮 P=100.0% / R=52.1%；针对漏检修复后的**同集回归**为 100.0% / 100.0%。文件级专项不能代替全系统同口径留出集，详见[预注册与记录](docs/Python弱哈希独立留出预注册_2026-10-18.md)。

首次使用请看[用户手册](docs/用户手册.md)；初期方案的硬指标与交付门槛见[方案要点](docs/方案要点.md)。评审各组指标时请同时看[性能与评测口径](docs/性能与评测口径.md)，避免把开发、独立诊断及回归数字混用。[作品说明书候选版](docs/作品说明书_候选版_2026-10-18.md)和[10 页答辩 PPTX 候选稿](docs/AI-CryptoGuard-答辩候选版.pptx)已汇集架构、原创边界、实测与未完成的验收项，供团队彩排和修改；两者都还不是最终版。PPTX 可用 `python docs/build_pitch_deck.py` 重新生成（需 `python-pptx`）。

比赛展示的三段公开样例、Windows cmd 命令与尚待完成的两次彩排记录见[演示脚本](docs/演示脚本与彩排记录_2026-10-18.md)。

快速扫描 Web 的 [Docker Compose 方案](setup/README.md#docker-compose快速扫描-web本机容器已验收) 已完成本机镜像构建、容器健康检查与公开样例真实扫描；异机完整部署仍待验证。第三方扫描器须在仓库外准备 Linux 可执行文件并只读挂载。

# AI-CryptoGuard

> **本轮工作（2026-10-18）：** Java 深度证据 → 量子风险评估（含危机时间窗口）→ 可选 AI 用途解释与具体整改。可定位的 `Random.nextBytes → SecretKeySpec` 现作为独立配置 Finding 展示，证据只有首尾位置，完整传播路径仍缺；安全随机源对照未触发该规则。首轮 25 例 Java 对照的历史基线未观察到 P/R 提升，后续结果见[对照记录](docs/Java深度同题对照_2026-10-18.md)。[公开 Java 深度样例](examples/java_deep_demo/README.md)可复现跨盘调用。AI 新提示词已对固定 30 条公开样本完整真调用：30/30 explained、0 Schema 错误；**独立人工语义审阅仍为 0/30**，见[验收记录](docs/AI语义验收_2026-10-18.md)。
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

本轮统一入口支持“快速扫描 → 可选 Java 深度证据 → 前置量子风险评估/时间窗口 → 可选 v0.2 AI”；
未启用的阶段如实记录 `skipped`：

```bash
python core/pipeline.py <要扫描的目录> --tools-dir <第三方工具目录> -o out/run
# 需要时间窗口时再加：--data-lifetime-years X --migration-lead-years Y --threat-horizon-years Z --hndl-exposure yes
python core/schema/validate_v02.py out/run/findings_assessed.json
python core/report.py out/run/findings_assessed.json -o out/run/report.html --task out/run/task.json
python web/serve.py
```

也可以只运行 `python web/serve.py`，在页面顶部把项目文件夹拖进本地审计入口；
扫描进度和结果会在同一页面连续展示。拖入内容只进入本机临时工作区，不发送到云端。
扫描完成后可从页眉下载自包含中文 HTML 报告。导入已有 JSON 只负责查看；
命令行入口可用上面的 `core/report.py` 单独导出。

下面是兼容旧 v0.1 演示的手动链路：

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

## 当前状态（2026-10-18）

独立 Juliet Java 留出的[预登记](docs/Juliet独立留出预登记_2026-10-18.md)和[首次诊断](docs/Juliet首次独立诊断_2026-10-18.md)已记录：85 个弱算法正单位首轮 TP/FP/FN = **85/0/0**，但没有独立干净文件负例；同轮扫描还暴露 98 条 `SecretKeySpec` 算法名被误报为硬编码 Token，已单独修复并复扫为 0。**这不是项目整体 P/R 达标的证明。**

> ⚠️ **本节是内部进度，不是对外文案。**
> 10-21~10-22 准备最终材料时要按方案 §20 / §21 重写。

> ⭐ 完整同步入口：[`docs/项目现状.md`](docs/项目现状.md)。
> 接手核查与执行顺序：[`docs/接手记录_2026-10-14.md`](docs/接手记录_2026-10-14.md)。
> 最新分支验收：[`docs/集成验收_2026-10-18.md`](docs/集成验收_2026-10-18.md)；AI 真实调用与证据复核：[`docs/AI语义验收_2026-10-18.md`](docs/AI语义验收_2026-10-18.md)；独立人工复核步骤：[AI 语义人工复核操作](docs/AI语义人工复核操作_2026-10-18.md)，可用离线页面 [`web/semantic_review.html`](web/semantic_review.html) 填写盲审包（当前人工审阅仍为 0/30）。

### 一、能跑的（全部已合并 `main`）

- ✅ 三个工具 smoke test 通过（`setup/README.md`）
- ✅ 统一 Finding 格式 v0.1（`core/schema/`）
- ✅ **scanner**（A）—— 调工具 → 统一格式
- ✅ **scanner 增强**—— 合并名拆词、本地常量传播、多语言补充、问题/线索分层
- ✅ **ai**（B）—— LLM 解读、云请求前脱敏、`evidence_refs`
- ✅ **规则库**（C）—— PQC 用途分派（`core/rules/`，自带自检）
- ✅ **结果查看器**（C）—— `web/`，显示 E1/E2 引用与证据卡片
- ✅ **端到端跑通**：扫描 → AI → 界面

### 二、当前可信基线（2026-10-18）

按显式扫描清单、范围对称、严格算法匹配重新计算；三个已扫描语料合计：

| 指标 | 当前 | 方案目标 |
|---|---:|---:|
| Precision | **87.7%**（TP 619 / FP 87） | ≥85% |
| Recall | **90.8%**（TP 619 / FN 63） | ≥90% |
| F1 | **89.2%** | — |

`cryptoapi-bench` 为 87.7% / 90.9%，`cambench-cap` 为 92.9% / 92.9%，
`llmcmt` 为 87.5% / 90.7%。safe 资产留在 CBOM，无算法线索进入 leads；
仅落在范围外正样本上的检出从 P/R 两边对称排除。凭据有 108 条被宽泛标签覆盖但
未逐条验证，不能用总分替代八个子类的独立留出集。完整口径见 `benchmark/README.md`。

### 三、对照方案硬指标

| 方案要求 | 现状 | |
|---|---|---|
| 标注样本 ≥ 120（§2.2） | 1411 条派生标签记录；独立样本需去重后确认 | ⚠️ |
| ≥ 15 类密码安全问题（§2.2） | scope 映射约 30 类；实际可检出类别待正式统计 | ⚠️ |
| **凭据管理类 ≥ 8 类**（§2.2） | 8 类规则已接入 scanner；公开语料专项 P=69.3%、R=74.3% | ⚠️ **已实现，仍需留出集** |
| Recall ≥ 90%（§2.3） | 90.8%（冻结口径，含凭据文件级标签） | ✅ |
| Precision ≥ 85%（§2.3） | 87.7%（冻结口径，含凭据文件级标签） | ✅ |
| `evidence_refs`（§7 / §8.4） | 已实现、集成并在前端显示；真实模型 30 条输出结构合规，语义复核发现证据不足案例并已对 6 条真调用回归，仍需独立人工评审 | ⚠️ |
| ≥ 3 类 Repair → Verify（§10） | 三类模板在临时副本通过语法检查和正式 scanner 复扫；自建演示项目 3/3 测试前后通过、旧 MD5 协议反例被拦下；[第三方 Chimera nonce 正例](docs/第三方正向修复验证_2026-10-18.md)的上游模块 45 条测试前后均通过，尚非全项目或真实网络兼容证明 | ⚠️ |

### 四、下一步

本轮任务入口：[详细操作指南](docs/本轮操作指南_2026-10-14.md)；
持续看板：[下一步计划](docs/下一步计划.md)。以下均为待实现事项。

| 人员 | 本轮任务 | 交付 |
|---|---|---|
| A/C | Java CrySentry 深度调用、证据适配、同题对照 | **已接通**；25 例首轮同题对照 P/R 不变，16 条 pattern 证据已挂载；仍需真实 Java 项目和更有区分度的固定样本 |
| B/C | 结合前置量子评估解释实际用途、生成具体整改 | **v0.2 AI 可选阶段已接入**；30 条真实输出与 6 条针对性回归完成，仍需独立人工语义评审和证据归属修复 |
| C | 共享契约、量子评估、统一调度、Web | 扫描 → 评估 → 可选 AI → 报告；离线闭环、30 条模型调用及 6 条回归通过结构验收 |

共享 Schema、CrySentry runner、前置量子评估和可选 v0.2 AI 阶段已经接通；
具体边界与验收见 [AI v0.2 集成记录](docs/AI-v0.2集成验收_2026-10-18.md)和[语义验收记录](docs/AI语义验收_2026-10-18.md)。
凭据留出集、更广的真实项目 Repair→Verify、部署及比赛材料继续保留在后续计划中。

### 五、怎么自己验一遍

```bash
python benchmark/scope.py            # 裁定表自检（会交叉问规则库，不是复述自己）
python benchmark/scope.py --gaps     # 规则库缺口清单（那 9 条）
python benchmark/scope.py --report   # 范围外 636 条是怎么来的，逐条列出
python benchmark/anonymize.py        # 匿名化自检（泄漏清零 + 字面量未被改动）
python benchmark/eval.py out/verify/_all3.json --scanned cryptoapi-bench,cambench-cap,llmcmt
python benchmark/eval.py --selftest             # 口径回归
python scanner/credential_selftest.py            # 8 类凭据 + 零明文泄露
python scanner/selftest_crysentry.py              # CrySentry 配置/适配/契约（离线）
python ai/selftest_v02.py                           # AI v0.2 引用、脱敏、缓存与规则路线（离线）
python core/pipeline_ai_selftest.py                 # 扫描结果→评估→AI 的离线全链路
python repair/selftest.py                        # 3 类临时修复 + 重新验证
```
