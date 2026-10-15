# 本轮共享契约 v0.2（2026-10-14）

本文件及相邻 JSON Schema 是本轮 A/B/C 的正式接口。契约已发布；深度扫描、量子评估和新版 AI 的功能实现仍按工作包推进。旧演示继续用 v0.1，不能直接把旧数据的版本号改为 0.2。

## 1. 开工与交接

先保存自己分支的修改，然后 `git fetch origin`、`git merge origin/main`。不要强制覆盖。A/B 在自己的分支开发，不直接推 main。

```cmd
python core/schema/selftest_v02.py
python core/schema/validate_v02.py core/samples/v0.2/java_complete.json
python core/schema/validate_v02.py core/samples/v0.2/task.json
python core/schema/validate.py core/samples/example_finding.json
```

新输出使用 `validate_v02.py 输出文件`；旧 v0.1 保持 `validate.py`。依赖为 jsonschema。退出码 0 合规，1 数据不合规，2 输入错误。不要只用普通 JSON Schema 校验替代新校验器：引用范围、缓存摘要等还要进行跨字段检查。

## 2. 阶段与所有权

|阶段 stage|产出方|必须交付|下一位怎么用|
|---|---|---|---|
|scanned|A|v0.2 基础 Finding、finding_kind、usage、evidence、占位 remediation|C 据证据评估风险|
|assessed|C|原记录加 quantum_assessment|B 据事实与规则解释|
|explained|B，经 C 程序校验|usage_assessment、explanation、evidence_refs、remediation_steps、analysis_provenance|C 验收并展示|

每阶段保持 finding_id 不变。用途改变后需要重新归并时由 C 单独处理并保留对应关系。A 不写 AI 结论，B 不改扫描证据、quantum_assessment 或风险事实。C 在接受 B 结果后按实际用途重新调用规则路由，不能让 LLM 自由决定迁移算法。`source=rule-base` 不代表 AI 已完成，完成状态以 stage 为准。

## 3. A：Java 深度证据

正式字段见 finding.v0.2.json。`tool=crysentry, kind=taint` 必须有 `flow`，内含 source、sink、path、completeness。位置对象固定为 file/line/method；未知值用 null，不编造。sourceStmt 缺失时 source=null、completeness=source_missing，不能称完整污点链。path 只写工具实际提供的节点，不自行补中间节点。

Finding 顶层必须有项目相对 file 和有效 line。无法可靠定位的深度结果放 task.json 的 unresolved_deep_evidence，不拿第 1 行兜底。任务状态见 task.v0.2.json：pending/running/completed/skipped/failed/timeout；后三种必须说明 reason。失败、跳过均不等于无问题。Python 项目 deep_java 为 skipped，保留快速扫描输出。

## 4. C：前置量子风险评估

quantum_assessment 包含 status、quantum_effect、classical_issues、rule_version、rule_refs、evidence_refs、unknowns、migration_candidates。风险事实先于 AI 解释。未知用途允许提供带 usage/route_id/rule_refs/conditions 的条件候选，不直接选定迁移算法。

quantum_effect 区分 shor、quantum_search、no_known_quantum_break、unknown、not_applicable；它不替代经典风险字段。凭据发现必须是 not_applicable，候选列表为空，不能把换密码解释为 PQC 迁移。insufficient_evidence 必须列出缺少的信息。assessed 必须引用规则和扫描证据。

rule_refs 是规则标识，evidence_refs 是扫描证据标识，两者不能混用。C1 将维护实际规则注册表；当前夹具中的 fixture.* 只为接口测试，不能当正式规则。注册表存在后还需检查规则真实存在和版本一致。

### 4.1 量子危机时间窗口（2026-10-15 新增，可选）

`quantum_assessment.quantum_timeline` 由 C 的确定性规则生成。输入是任务级 X/Y/Z：数据或安全有效期 X、迁移准备期 Y、组织采用的量子威胁时间窗 Z。`X + Y >= Z` 时 urgency 为 `immediate`；否则给出 `years_until_action = Z-X-Y`。系统不预测 Q-Day，不允许 AI 代填 X/Y/Z。

HNDL（先收集后解密）另用 `hndl_exposure` 和 `hndl_status` 表示。签名用途不按密文 HNDL 评估；用途未知时保持 unknown。未填写完整 X/Y/Z 时 status=`not_configured`，不能用默认年份冒充结论。该字段为可选扩展，因此 A/B 已在开发中的 v0.2 输出不会因缺少它而失效；C 调度器产出的 assessed 记录会带上它。

## 5. B：解释与整改

usage_assessment 给出 usage/reason/evidence_refs/unknowns，并与最终 usage 一致。explanation 用中文讲清楚发现、用途、影响和不确定性。每个整改步骤都包含 action、target、evidence_refs、rule_refs、prerequisites、verification、execution_status。没有可靠位置时 target=null；尚未执行的步骤必须标 not_run。没有可支持的整改时 steps 可以为空，必须在解释和 unknowns 中说明原因。

每个步骤的规则引用只能来自 C 提供的 quantum_assessment.rule_refs；纯定位核查可用空规则引用。规则相关建议还必须由程序核验迁移路线，单纯引用合法不代表建议正确。先使用 assessed 夹具开发，不必等待 CrySentry 接通。

## 6. 引用与缓存

E1 表示本条 Finding 的 evidence[0]，E2 表示 evidence[1]，不是跨 Finding 的全局编号。A/C 合并证据后固定顺序，B 不得重新排列。校验器拒绝越界编号；引用是否真正支持该句话仍需要语义抽样。

analysis_provenance 必填 input_digest/rule_version/prompt_version/model_id/redaction_version。input_digest 统一调用 validate_v02.input_digest(finding)，不要自己实现另一套。摘要覆盖身份、位置、算法、风险、严重度、置信度、证据及前置评估，采用排序键的紧凑 UTF-8 JSON + SHA256。完整字段清单是该模块 DIGEST_FIELDS。

最终 usage 和 AI 派生文本不进入摘要；原始用途线索必须保留在 evidence 中。若未来增加模型输入字段，C 必须同时升级摘要约定。复用缓存还必须逐项比较规则、提示词、模型配置标识和脱敏版本；模型参数改变时更新 model_id 的配置标识。摘要相同仅说明输入一致，不证明解释正确。凭据原文、API 密钥不能进入这些标识或日志。

## 7. 四组夹具与兼容性

core/samples/v0.2/ 中 java_complete、java_source_missing、usage_unknown、credential 各有 scanned/assessed/explained 三条合成记录；另有 task.json。均非实测能力或准确率证明。缺失源、未知用途和凭据不适用量子迁移必须保留，不能只测成功路径。

v0.1 Schema 与校验入口保持不变，当前 scanner/AI/Web 不会自动升级。本轮由 C 调度器接入 v0.2；新版 UI 同时兼容旧展示。A/B 交付时提供新输出、校验记录、失败/跳过用例和已知限制。需要新增字段时先修改共享契约与夹具，通过回归后再依赖它。
