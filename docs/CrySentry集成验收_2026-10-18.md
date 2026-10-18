# CrySentry Java 深度证据集成验收（2026-10-18）

## 1. 结论

C 在 A 尚未交付 runner 的情况下完成兜底集成。当前正式流水线支持：

```text
快速扫描
  ->（可选）CrySentry Java 字节码深度分析
  -> pattern / taint 证据适配与保守融合
  -> 前置量子风险评估
  -> AI（仍待 B 的 v0.2 实现）
```

CrySentry 是第三方 LGPL-3.0 工具。仓库只提交调用器与适配器，不提交
CrySentry 源码、40MB fatJar、444MB 工作目录、JDK 或目标项目编译产物。

## 2. 新增入口

```cmd
python core\pipeline.py D:\demo\project --mode deep-java ^
  --java-artifact D:\demo\project\target\app.jar ^
  --java-classpath D:\demo\project\lib\dependency.jar ^
  --crysentry-home D:\code_competition\_smoke\CrySentry ^
  --crysentry-java D:\code_competition\_smoke\jdk17\jdk-17.0.20.1+1\bin\java.exe ^
  --deep-timeout 900 --deep-memory-mb 4096 ^
  -o out\deep-demo
```

约束：目标项目必须先由用户编译。runner 不会自动执行 Maven/Gradle，也不会运行
任意第三方构建脚本。依赖通过可重复的 `--java-classpath` 显式传入。

## 3. 真实验收

输入：CrySentry 自带 activemq `original-classes.jar`；JDK 17；已构建的
`tai-e-all-0.5.1-SNAPSHOT.jar`。

结果：

| 项目 | 实测 |
|---|---:|
| CrySentry 原始记录 | 8 |
| 运行耗时 | 约 15 秒 |
| 融合后 Finding | 2 |
| 保留 evidence | 8 |
| 其中 taint | 4 |
| 未定位记录 | 0（本次用固定源码映射夹具） |
| v0.2 契约 | 2/2 Finding、task.json 全通过 |
| 默认原始输出清理 | 通过 |

8 条记录收口为 2 条 Finding 是冻结计数口径的结果：同一文件、算法、用途的
不同调用点进入 `evidence[].lines`，不按命中次数虚增问题数。

## 4. 已覆盖的失败语义

- 没有 Java 源码：`deep_java=skipped`，快速结果保留。
- 没有 `--java-artifact`：`skipped`，不会自行构建。
- 未配置 CrySentry：`skipped`，原因写进 task.json。
- JDK 不是 17、工具 jar 缺失、进程失败：`failed`，快速结果保留。
- 超时：`timeout`，快速结果保留。
- 调用点无法映射源码：进入 `unresolved_deep_evidence`，不伪造第 1 行。
- `sourceStmt` 缺失：flow 标为 `source_missing`；有语句但没有完整传播路径则为
  `partial`。若 CrySentry 的语句自带 `@L` 行号，只提取位置，不保存源语句原文。
- 默认不保留 CrySentry 原始 JSON；`--keep-raw` 仅供本地调试。

## 5. 安全与正确性处理

- `sourceStmt` 不写入统一 evidence.raw，避免口令、密钥或源码原文进入报告。
- `Predictable Source` 中的字符串不当作算法；只有 `Pattern Match` 的算法常量
  才能建立算法锚点。
- CrySentry 输出顺序不稳定：融合采用“先算法锚点、后无算法 taint”两阶段，
  已用 taint 在前的回归夹具验证。
- 深度工具没有报告某问题，不作为快速扫描误报的反证，也不自动删除快速发现。
- 新算法 Finding 的风险调用 `core/rules/algorithm_risk.py`，不在 adapter 手抄规则。

## 6. 尚未完成

本次 smoke 证明的是“runner 和证据链真实可运行”，没有证明指标提升。
后续 [25 例同题对照](Java深度同题对照_2026-10-18.md) 已完成：
CrySentry 实际产出 23 条原始记录、16 条可挂载 pattern 证据，但快速/深度
P/R 完全相同。普通 jar 零可达方法的问题也已修复。仍需 A/C：

1. 选择固定、可编译且有标签的 Java 子集。
2. 同一清单分别跑 fast 与 deep-java。
3. 报告 P/R/F1、工具完成率、超时/失败清单和耗时。
4. 区分新增真阳性、重复证据、新增误报。
5. 用至少一个真实 Maven/Gradle 项目的**用户已编译产物**验证 classpath。

可选 v0.2 AI 已接入统一入口，默认不开启；启用后也不能把 1 条真实模型调用
当作 30 条语义验收或完整 AI 报告质量证明。

## 7. 自检

```cmd
python scanner\selftest_crysentry.py
python core\rules\algorithm_risk.py
python core\schema\validate_v02.py out\deep-demo\findings_assessed.json
python core\schema\validate_v02.py out\deep-demo\task.json
```
