# 干净 Linux Java 深扫验收（2026-10-19）

固定项目提交 `07269088ff79257060f3142590a3fe3ec907656c`；[GitHub Actions 手动运行记录](https://github.com/Rant-yang/AI-CryptoGuard/actions/runs/39148274234)中，`Verify Java deep scan on clean Linux` 所有步骤成功。本记录只证明新的 Ubuntu 24.04 runner 上的**公开 Java 样例**可以从源码与外部工具重新构建并完成深扫；不包含真实用户项目、云端 AI 或完整团队彩排。

## 固定第三方来源与执行

- 快速工具与[前一轮干净 Linux 快扫](干净Linux快扫与Web闭环_2026-10-19.md)相同：CryptoScan v1.4.0 Linux amd64 官方压缩包校验 SHA-256 `49aa043bd3f46927efa8ee89a2344d30f2ec351ae9e0cf2791ac8206b45be19d`，cbom-scan 固定 `bcf71292816aa64d5890207466b5dff1f5ef9cf7`。均位于 runner 临时目录。
- 在仓库外浅克隆 [CrySentry](https://github.com/pascal-lab/CrySentry) 并核对 `HEAD=dfe0b74f3b1583d0fced44dd7e166d38e1b59be7`；Temurin JDK 17 下运行原始 `./gradlew fatJar --no-daemon`，`BUILD SUCCESSFUL in 1m 45s`，得到 `build/tai-e-all-0.5.1-SNAPSHOT.jar`。本次没有修改其 `settings.gradle.kts`，也没有把其源码、fatJar 或 JDK 放进我方仓库或匿名源码包。CrySentry/Tai-e 的分析能力属于第三方，许可证与分发边界见[第三方来源说明](第三方来源与分发边界.md)。
- 同一项目提交的 `examples/java_deep_demo/Demo.java` 用 `javac -g` 编译为临时 JAR；`setup/preflight.py` 的 15 项检查失败数为 0。统一入口以 `--mode deep-java` 指向外部工具、同版字节码与 JDK 17，产出任务状态和 Finding。没有启用云端 AI。

## 实际结果与边界

`scan`、`deep_java`、`quantum_assessment` 均为 `completed`；最终 **2 条 Finding**，v0.2 Schema **2/2 有效**。检查器确认至少 2 项 CrySentry 证据、且存在 `taint` 类型。该 `taint` 是已有文档定义的**来源与汇点部分证据**，不是完整传播路径；不能因此声称全程序污点链已逐边验证。

本次证明：仓库外第三方引擎能够在新的 Linux 环境构建，Java 编译产物与公开源码能够对齐，并能经我方 runner/adapter 进入统一报告。它不证明 Docker 容器内运行 CrySentry；当前容器仍只支持快速模式。它也不证明任意第三方 Java 项目的 classpath、可达性或数据流都正确，更不证明 Java 深扫提升了全系统 P/R；这项公开夹具不能作为独立留出集。

队友机器、真实项目深扫与真实云 AI 在同一异机上的全链路部署仍未验证；比赛展示仍需按[演示脚本](演示脚本与彩排记录_2026-10-18.md)完成两次团队彩排并保留失败/耗时记录。
