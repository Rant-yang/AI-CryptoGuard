# ProwlBench 代码片段凭据诊断：扫描前预登记（2026-10-18）

**状态：只检查了上游结构、标签分布和许可证；尚未运行本项目凭据检测器。** 本文件与 `benchmark/prowlbench_credential.py` 必须先提交，再准备输入并进行首次扫描；首次数字高低均保留，不据此重选片段或调评分口径。

## 数据与冻结选择

- 来源：[Lercas/prowlbench](https://github.com/Lercas/prowlbench)，本机固定 Git 提交 `53d6fc1e2006185c0fadd5cd761af3f1aacfd025`，`prowlbench.jsonl` 的 SHA-256 为 `5d6bbed9cc7d26815024cc2e99bf13f61c9c94f0059b4f874a407af39a26b735`。上游许可文件为 PolyForm Noncommercial 1.0.0；语料和生成的代码副本只保存在仓库外，不随竞赛源码包分发。
- **选全部 `source == "code"` 行**，共 9,732 个片段：6,693 正、3,039 负。不按检测结果、类别、难度、语言或来源再筛选。非代码的 wiki/Jira/Slack/log 片段属于另一产品场景，此轮预先排除。
- 每行变成一个 `case_000001.py` 这样的中性文件，文本原样保留。标签、类型、难度、来源及冻结清单只存于扫描目录的**外面**；检测器只看到中性文件和源码文本。所有输入与输出在本地，不发云模型，不上传真实项目源码。
- 上游 `label=1` 表示**片段含秘密**，`0` 表示不含。一个文件只要有至少一条 `finding_kind=credential`，就预测为正。按片段文件计算 TP/FP/FN/TN、Precision/Recall/F1 和负例误报率。单文件多个规则命中只算一次预测；不按 token 字符串或 `span` 做精确匹配。
- 本任务是**秘密存在性**检测的外部诊断，**不是**八类凭据管理缺陷各自的真值，也不评价密码算法、Java 深扫或 AI 能力。代码片段可能包含自然语言或合成载体，因此结果不能与三套开发语料的文件+算法成绩相加。

## 冻结与反驳机制

`prepare` 仅在全新仓库外目录生成 `src/`、`labels.json` 和 `FROZEN_MANIFEST.json`；拒绝覆盖。清单记录上游提交和数据哈希、准备/评分代码哈希、凭据检测器代码哈希、标签哈希、所有中性文件的组合哈希及 9,732/6,693/3,039 计数。`score` 先逐项核对，再调用本地 `credential_scan.scan(src)`；代码、数据或数量有变化就拒绝将它称为本次冻结首次结果。评分器只打印汇总计数和规则 ID 分布，不打印片段、凭据、指纹、匹配值或 Finding 原文。

扫描前已用四条**合成标签**验证评分口径：1 TP、1 FP、1 FN、1 TN；空预测仍保留两个 FN；把标签文件当输入会报错。此自检没有使用上游秘密片段。

## 预先声明的解释边界

上游[README](https://github.com/Lercas/prowlbench#readme)披露了其训练型模型与基准共享部分合成基底的风险；本项目本轮使用**确定性本地规则**，没有拿这些片段训练模型，但不因此声称真实项目泛化已经证明。上游基准以片段级“有没有秘密”为标签，不能据此声称对每个具体 `CRED-...` 规则或真实凭据是否仍有效做了验证。任何低 Recall 或高 FP 都要报告，并在修正代码后另列同集回归；首次结果不回写。

## 首次执行命令（提交本页之后）

```cmd
python benchmark\prowlbench_credential.py selftest
python benchmark\prowlbench_credential.py prepare C:\path\to\prowlbench C:\path\to\new-private-holdout
python benchmark\prowlbench_credential.py score C:\path\to\new-private-holdout
```

真实私有目录、标签和中性代码副本不要放进 `AI-CryptoGuard` 仓库或匿名支撑包。扫描后另建结果文档，保留本预登记原文。
