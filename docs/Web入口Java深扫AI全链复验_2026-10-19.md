# Web 入口：公开 Java 样例深扫与真实 AI 全链复验（2026-10-19）

本次从开发 checkout `dd8cfdb` 发起，通过与浏览器相同的本机 HTTP 任务接口上传
`examples/java_deep_demo/Demo.java` 以及该源码对应的编译 JAR，并启用
`deep-java` 与 `ai_enabled=true`。CrySentry 引擎、JDK 17、编译 JAR 和扫描工具均在仓库外；
模型凭据仅从本机环境变量读取，未写入仓库、命令参数或本记录。

运行入口：

```cmd
cd /d D:\code_competition\AI-CryptoGuard
set ACG_TOOLS_DIR=D:\code_competition\_smoke
set ACG_CRYSENTRY_HOME=D:\code_competition\_smoke\CrySentry
set ACG_CRYSENTRY_JAVA=D:\code_competition\_smoke\jdk17\jdk-17.0.20.1+1\bin\java.exe
python web\server_selftest.py --deep-integration --ai-integration
```

实测为 `PASS: local web task API + real CrySentry integration + real AI integration`。
测试从 `POST /api/tasks` 建任务、上传源码和 JAR、启动任务、轮询状态，最后读取
`/result` 与 `/report`，覆盖了浏览器背后的同一组 API。`scan`、`deep_java`、
`quantum_assessment`、`ai` 阶段均完成；结果中存在 CrySentry `taint` 证据，
所有返回的 Finding 为 `explained`，HTML 报告显示 AI 与 Java 深扫已完成。
这个公开样例的深度证据只是部分源／汇点信息，不能表述为完整传播路径。

`/result` 返回的是**浏览器脱敏展示副本**：证据的 `raw` 已移除，原始完整结果
仍保留在 Git 忽略的本机私有任务目录中。移除 `raw` 会改变 v0.2 的
`analysis_provenance.input_digest` 输入，因此浏览器副本不能用于摘要校验、
AI 断点续跑或正式复评。接口现在以 `X-ACG-Projection: browser-redacted`
明确标记这一边界；基础 Web 自检覆盖了这个响应头。正式 Schema 校验应针对
本机 `out/findings_explained.json`，不能针对脱敏展示副本。

这证明了**同一台 Windows 机器、公开样例、Web 任务 API** 的真实深扫与 AI
闭环；不是浏览器像素／交互验收，也不是异机、真实用户项目或独立准确率测试。
当前 v7 的 29 条模型解释仍是 **0/29 人工语义审阅**；真实作品编号、审批签字盖章、
两次团队彩排和最终上传回执仍待人工完成。
