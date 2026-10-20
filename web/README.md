# Web 审计入口

本地网页支持选择源码项目、查看扫描进度、浏览证据与 AI 解释、生成行动清单及下载中文 HTML 报告。页面不依赖 CDN 或前端构建工具；扫描需要本机服务。

## 启动

先按[部署指南](../setup/README.md)准备工具，在仓库根目录运行以下 Windows cmd 命令，路径按本机实际配置替换：

```cmd
set "ACG_TOOLS_DIR=D:\acg-tools"
python web\serve.py
```

访问终端打印的地址，默认端口 8000。`ACG_WEB_PORT` 指定起始端口，`ACG_WEB_STRICT_PORT=1` 表示占用时报错而不递增。默认只监听 `127.0.0.1`。容器使用方式见部署指南。

## 扫描与结果

1. 选择或拖入源码文件夹，首次可用 `examples/repair_demo` 或 `examples/pqc_demo`。
2. 选择快速扫描或 Java 深度模式，按需启用 AI、填写量子时间窗口。
3. 查看上传、扫描、深度证据、量子评估和解释的实际状态。
4. 先看项目行动清单，点击进入对应发现，核对位置及 E 编号证据。
5. 页眉“下载中文报告”导出包含完整清单的自包含 HTML。

网页优先显示前五项行动，按现有严重程度与条件性标记初排；建议仍需复核、执行和验证。“导入已有报告”仅查看 JSON，不提供任务级总览或下载按钮，可用 `core/report.py` 生成报告。

## Java 深度模式

服务启动前设置外部引擎与 JDK 17：

```cmd
set "ACG_CRYSENTRY_HOME=D:\acg-tools\CrySentry"
set "ACG_CRYSENTRY_JAVA=D:\jdk-17\bin\java.exe"
python web\serve.py
```

提供包含 Java 源码的文件夹和同一份源码编译出的 jar。服务不自动执行项目构建脚本。网页暂不支持额外 classpath，有依赖的项目请使用[命令行入口](../docs/用户手册.md)。深扫失败或跳过仍保留快扫结果，不能把未执行阶段当成检测通过。

## AI 与迁移时间窗口

AI 默认关闭。开启前设置 `ANTHROPIC_AUTH_TOKEN`、`ANTHROPIC_MODEL`，兼容端点另设 `ANTHROPIC_BASE_URL`。`full` 发送脱敏代码上下文，`shape` 仅发送调用形状，凭据发现保持本地处理。

解释失败时显示连接、超时、认证或校验等原因，并保留扫描结果。“仅重试 AI”不会重跑扫描或量子评估，只复用通过一致性校验的解释。缺少模型配置时需配置并重启服务；重启后需重新建立任务。

时间参数由用户提供：X 为保密期限，Y 为迁移准备期，Z 为组织采用的威胁情景时间窗。三项须同时填写，不确定时可留空，系统不预测 Q-Day；具体路线仍受用途与暴露条件约束。

## 数据与限制

- 上传写入本机 `workspace/web_tasks/`，只有显式启用 AI 才按所选模式向云端发送脱敏上下文。
- 源码单文件上限 8 MiB，总计 64 MiB，最多 4000 个文件；深扫 jar 上限 128 MiB。
- 上传失败显示最终错误，单次 API 请求超过 60 秒提示超时。运行中禁止重复开始或删除任务。
- 服务启动时清理超过 24 小时的任务目录；关闭网页不会立即删除文件。
- 静态服务只提供页面，不公开 `out/`、`workspace/`、`.env` 或任意仓库文件。
- 结果 API 是脱敏展示副本，移除了 `evidence.raw` 等字段，不可用作原始输入摘要校验或 AI 续跑。正式契约校验应使用本机原始结果。
- 本服务面向本机单用户使用，不提供多租户鉴权和项目权限隔离。

## API

| 接口 | 用途 |
|---|---|
| `POST /api/tasks` | 建立任务 |
| `POST /api/tasks/<id>/files?path=<相对路径>` | 上传源码 |
| `POST /api/tasks/<id>/artifact` | 上传深扫 jar |
| `POST /api/tasks/<id>/start` | 启动扫描 |
| `GET /api/tasks/<id>` | 查询状态 |
| `GET /api/tasks/<id>/result` | 脱敏发现列表 |
| `GET /api/tasks/<id>/summary` | 行动清单 |
| `GET /api/tasks/<id>/report` | 下载 HTML 报告 |
| `POST /api/tasks/<id>/retry-ai` | 对符合条件的失败任务仅重试 AI |
| `DELETE /api/tasks/<id>` | 删除未运行的任务 |

## 开发检查

```cmd
python web/server_selftest.py
python web/product_selftest.py
node web/selftest.js
node web/product_selftest.js
node web/upload_selftest.js
```

`python web/server_selftest.py --integration` 额外调用真实快速工具。离线检查不等同于真实模型语义准确率或完整深度分析验证。
