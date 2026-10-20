# AI-CryptoGuard

**本地优先的密码安全审计与抗量子迁移辅助系统。**

对源码项目进行密码资产发现、凭据与配置检查，将多种扫描结果整理为可追溯的证据，结合规则评估和可选的 AI 解释，形成项目行动清单与中文审计报告。

[用户手册](docs/用户手册.md) · [部署指南](setup/README.md) · [Web 使用说明](web/README.md) · [评测方法与边界](docs/性能与评测口径.md) · [第三方来源](docs/第三方来源与分发边界.md)

## 功能

| 能力 | 说明 |
|---|---|
| 多源扫描与融合 | 集成 CryptoScan、cbom-scan，统一算法名称、位置、用途及证据，区分问题、资产与待核查线索 |
| 本地补充检测 | 凭据检测、部分 Python AST 检查与常量传播规则 |
| Java 深度证据 | 可选调用 CrySentry 分析编译产物，将可定位的深度证据关联到源码发现 |
| 量子风险评估 | 区分经典密码风险与量子威胁，结合用途提供条件化迁移路线 |
| 迁移时间窗口 | 根据用户提供的保密期限、迁移准备期和威胁情景评估紧迫度，不预测 Q-Day |
| AI 辅助解释 | 解释用途、风险与整改步骤，引用已有证据；证据不足时保留待确认项 |
| 行动清单与报告 | 汇总优先复核事项，显示建议、理由和证据链接，下载自包含中文 HTML 报告 |
| 修复与复扫 | 对三类受支持的 Python 场景在临时副本生成候选补丁，执行检查及扫描对比 |

## 工作流程

```text
源码项目
  → 快速扫描与本地补充检测
  → 可选 Java 深度分析（需要对应编译产物）
  → 证据融合与规则评估
  → 可选 AI 用途解释与整改建议
  → 项目总览、行动清单、审计报告
```

扫描与确定性规则评估在本机执行。启用云端 AI 后，程序按所选模式发送脱敏上下文；凭据类发现保持本地处理。AI 不自由决定替换算法，迁移路线由规则库结合用途约束。

## 快速开始

### 1. 准备环境

需要 Python、Node.js，以及仓库外的 CryptoScan 和 cbom-scan。Java 深度模式另需 CrySentry、JDK 17 和目标项目的编译产物。第三方工具、模型密钥和扫描数据不包含在仓库中。

```cmd
git clone https://github.com/Rant-yang/AI-CryptoGuard.git
cd AI-CryptoGuard
python -m pip install -r ai/requirements.txt
```

按[部署指南](setup/README.md)下载外部工具。以下 Windows cmd 示例假设工具在 `D:\acg-tools`，请替换为实际目录：

```text
D:\acg-tools\
├── cryptoscan\cryptoscan.exe
└── cbom-scan\cbom.js
```

cbom-scan 应保留原仓库所需文件，不要只复制单个脚本。Linux 使用对应平台的 CryptoScan 可执行文件。

### 2. 启动 Web 界面

在仓库根目录运行：

```cmd
set "ACG_TOOLS_DIR=D:\acg-tools"
python setup\preflight.py --tools-dir D:\acg-tools --target examples\repair_demo --mode fast
python web\serve.py
```

访问终端打印的地址，默认是 `http://127.0.0.1:8000/web/index.html`。端口占用时可能自动递增，以终端输出为准。

选择或拖入源码文件夹，查看阶段进度。完成后先看行动清单，再进入单项证据详情；页眉可下载报告。“导入已有报告”只查看 JSON，不会重新扫描。

### 3. 体验公开示例

| 项目 | 用途 |
|---|---|
| [examples/repair_demo](examples/repair_demo) | 凭据、弱算法及候选修复 |
| [examples/pqc_demo](examples/pqc_demo) | RSA 签名与 ECDH 密钥交换的用途及迁移路线 |
| [examples/java_deep_demo](examples/java_deep_demo) | Java 快扫与深度证据；深扫前须按示例说明编译 |

### 4. 可选 AI 与 Java 深扫

AI 默认关闭。启用前在本机配置 `ANTHROPIC_AUTH_TOKEN`、`ANTHROPIC_MODEL`；兼容服务另需 `ANTHROPIC_BASE_URL`。密钥不要写入仓库。`full` 模式发送脱敏代码上下文，`shape` 仅发送调用形状。AI 失败时保留本地结果，并可仅重试解释。

Java 深扫需在服务启动前配置 `ACG_CRYSENTRY_HOME` 和 `ACG_CRYSENTRY_JAVA`，在网页提供源码及同一份源码编译的 jar。详细步骤见 [Web 指南](web/README.md)。

## 命令行使用

```cmd
python core\pipeline.py examples\repair_demo --tools-dir D:\acg-tools -o out\demo
python core\schema\validate_v02.py out\demo\findings_assessed.json
python core\report.py out\demo\findings_assessed.json -o out\demo\report.html --task out\demo\task.json
```

配置模型后追加 `--ai` 可生成 `findings_explained.json`。Java 深扫、时间窗口及候选补丁参数见[用户手册](docs/用户手册.md)。Docker Compose 目前提供快速扫描 Web，外部工具挂载见[部署指南](setup/README.md)。

## 使用边界与数据处理

- 发现是待复核的审计线索，风险等级不等同于已验证可利用漏洞。
- `E1`、`E2` 只指向同一发现内的证据。未知用途不会强行映射为某个 PQC 算法。
- Java 深扫不适用于 Python；部分数据流证据不代表完整传播路径或分支可达性。
- 候选补丁只针对受支持场景，测试通过或发现消失不能代替业务与协议兼容性验证。
- Web 面向本机使用，不是多租户平台。任务状态在内存中，服务重启后需重新建立扫描任务。
- 源码上传到本机临时目录；启用云端 AI 前须确认项目允许发送所选脱敏上下文。凭据结果不保存原文，报告不展示原始凭据。
- `workspace/`、`out/`、`.env` 和测试数据不入库。关闭浏览器不会立即删除任务文件，清理方式见用户手册。
- 评测按数据集、检测范围及计数单位解释，开发集回归成绩不能替代独立泛化能力。详见[性能与评测口径](docs/性能与评测口径.md)。

## 目录

```text
AI-CryptoGuard/
├── scanner/     工具适配、证据融合与本地检测
├── core/        统一入口、v0.2 契约、风险规则、总览与报告
├── ai/          受证据约束的解释、脱敏与续跑
├── web/         本地网页与任务 API
├── repair/      候选补丁与复扫验证
├── benchmark/   公开基准适配、匿名化与评测
├── examples/    演示源码
├── setup/       环境预检与部署工具
└── docs/        使用、设计与评测文档
```

## 开发验证

以下检查不需要云端模型调用：

```cmd
python scanner/selftest.py
python core/schema/selftest_v02.py
python ai/selftest_v02.py
python web/server_selftest.py
python web/product_selftest.py
node web/selftest.js
node web/product_selftest.js
node web/upload_selftest.js
```

第三方工具实际运行、Java 编译环境和云端连接需分别验证。

## 第三方与实现范围

CryptoScan、cbom-scan 和 CrySentry/Tai-e 的扫描与程序分析引擎属于各自原作者。本项目实现工具调用与证据融合、本地补充规则、量子评估、受约束 AI 解释、评测与产品界面。外部工具不随本仓库分发，具体来源及许可说明见[第三方来源与分发边界](docs/第三方来源与分发边界.md)。
