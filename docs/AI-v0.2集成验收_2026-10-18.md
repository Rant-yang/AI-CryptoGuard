# AI v0.2 解释阶段集成验收（2026-10-18）

## 当前能力与边界

统一入口现支持显式 `--ai`：快速扫描 → 可选 CrySentry Java 深度证据 → 前置量子评估 → AI 用途解释与整改步骤。默认不开启云端 AI。Web 扫描入口有相同的显式选项；未启用或模型服务失败时，仍展示本地扫描和量子评估结果，任务阶段明确写 `skipped` 或 `failed`。

`ai/enrich_v02.py` 只让模型判断用途、解释证据并提出需要核查的操作；风险事实和迁移算法由 C 的本地规则在用途变化后重新计算。AI 给出的证据编号必须存在，PQC 算法不能由模型在步骤中擅自选定，步骤位置来自扫描证据，执行状态固定为 `not_run`。凭据发现仅在本地处理，不调用云端。所有报告通过 v0.2 Schema 与跨字段校验。

默认 `full` 模式发送脱敏代码上下文、调用形状和前置评估摘要，适用于自有或公开项目；`--ai-context shape` 只发送调用形状，适用于敏感或第三方项目。两种模式都必须移除真实密钥/token 和绝对路径，且只有显式 `--ai` 才调用云端。

## 命令（Windows cmd）

```cmd
cd /d D:\code_competition\AI-CryptoGuard
python ai\selftest_v02.py
python core\pipeline_ai_selftest.py
python core\pipeline.py D:\your\project --tools-dir D:\code_competition\_smoke --ai -o out\run
python core\schema\validate_v02.py out\run\findings_explained.json
python core\schema\validate_v02.py out\run\task.json
```

真实调用要求在当前进程环境中设置 `ANTHROPIC_AUTH_TOKEN`、`ANTHROPIC_MODEL`；使用兼容服务时还需正确的 `ANTHROPIC_BASE_URL`。绝不将值写进仓库或演示日志。已有 assessed 文件可单独执行 `python ai\enrich_v02.py out\run\findings_assessed.json -o out\run\findings_explained.json --resume`。

## 本次验收证据

| 检查 | 结果 |
|---|---|
| 离线 AI v0.2：用途改写后重算签名路线、未知用途不猜、越界引用拒绝、凭据本地处理、脱敏、缓存失效 | 通过 |
| 统一入口离线端到端：2 条 Finding → 2 条 explained，缺少模型配置时 assessed 保留且 AI=failed | 通过 |
| Web 查看器 v0.2 步骤与引用渲染、凭据原文不显示 | 通过 |
| 本地 Web API：真实扫描、临时任务、静态文件拒绝访问、结果 API 移除原始证据 | 通过 |
| 受限环境中的两条真实调用 | APIConnectionError；任务中 AI=failed，2 条 assessed 保留。此结果受网络沙箱影响 |
| 允许联网环境中的单条真实调用 | **explained、v0.2 契约错误 0、用途 unknown、整改步骤 3 条**；还不能证明 30 条语义质量 |
| 合成 RSA Finding 的真实统一入口全链路 | `--findings … --ai` 退出码 0，AI=completed；explained Finding 与 task.json 各 0 个契约错误。模型保守输出 `usage=unknown`，未擅选 PQC 路线 |

Web 静态服务只允许 `/web/index.html`，不会直接公开 `out/`、`workspace/`、`.env` 或仓库源码。导入已有报告需使用页面右上角的“导入已有报告”。

## 尚需完成

1. 用至少 30 条跨风险/语言/证据类型样本做真模型语义抽样；逐条核查用途、证据支持关系、整改可执行性和不确定性，不只看 Schema 通过率。
2. 固定有标签 Java 子集，对 fast 与 deep-java 同题跑 P/R/F1、耗时、完成率；CrySentry 的 smoke 只证明接口和证据链可运行。
3. 凭据留出集、真实项目 Repair→Verify、部署/演示与第三方许可证材料按总计划完成。
