# AI-CryptoGuard 源码与复现入口

本提交源码包包含团队实现的扫描器调用/归一化与融合、凭据与局部源码规则、量子风险评估、AI 证据约束、Repair→Verify、评测脚本和 Web 界面。CryptoScan、cbom-scan、CrySentry/Tai-e 属于各自原作者，**不包含在本包中，也不表述为团队自研扫描引擎**。版本、许可与使用边界见 [`docs/第三方来源与分发边界.md`](docs/第三方来源与分发边界.md)。

## 启动

1. 解压本包，安装 Python 及所需依赖；准备仓库外的 CryptoScan、cbom-scan。详细步骤见 [`setup/README.md`](setup/README.md) 和 [`docs/用户手册.md`](docs/用户手册.md)。
2. 在包根目录运行 `python setup/preflight.py --tools-dir <外部工具目录> --target examples/repair_demo --mode fast`，确认第三方工具可用。
3. 运行 `python core/pipeline.py examples/repair_demo --tools-dir <外部工具目录> -o out/demo`，或按用户手册启动 Web。
4. Java 深度模式还需先编译目标项目，并单独提供 JDK 17、CrySentry 目录及目标 jar/classes；默认快扫不会运行 CrySentry。

本包不含真实用户项目、密钥、原始扫描输出、外部 benchmark、可逆匿名映射、第三方工具二进制。AI 云调用需用户显式开启，并在出网前进行脱敏。样本、指标与适用范围见 [`docs/性能与评测口径.md`](docs/性能与评测口径.md)；开发集或同集回归不能代替独立留出结论。

本 README 不含团队成员、单位或私有仓库地址，以便用于匿名网络评审。正式提交前仍须由团队逐项检查整个压缩包及平台上传内容。
