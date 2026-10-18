# Repair → Verify

当前 v1 在**临时副本**中支持 3 类 Python 修复：

1. `hashlib.md5(...)` → `hashlib.sha256(...)`
2. 安全用途变量直接接收 `random.Random(...).randbytes(...)` 时，将该构造器改为 `random.SystemRandom(...)`
3. 硬编码口令 → `os.environ["变量名"]`

候选编辑按 Python AST 定位，只改真实调用/赋值表达式，不替换注释或字符串中的同名文本。
显式 `hashlib.md5(..., usedforsecurity=False)` 可能是协议规定的摘要（例如 HTTP Digest），
自动替换会破坏互操作，因此跳过并在报告中计入 `skipped_protocol_md5`；
明显用于口令处理的 MD5 也不自动替换：SHA-256 仍是快速摘要，不能代替口令 KDF，
而已有口令摘要还需要兼容验证与渐进迁移。这类调用计入 `skipped_password_md5`，
须由人工设计口令 KDF（如 Argon2id）和迁移/回滚方案；
没有可应用补丁时报告 `NO_APPLICABLE_PATCH`，CLI 返回非零。跳过不代表安全。
语法检查使用 `compile(..., 'exec')`，会拦住导入顺序等 `ast.parse` 不检查的错误；
环境变量模板新增的 `import os` 放在模块文档字符串和 `from __future__` 导入之后。

```cmd
python repair\verify.py path\to\demo.py --tools-dir D:\code_competition\_smoke -o out\repair_report.json
python repair\verify.py examples\repair_demo\app.py --project-root examples\repair_demo --tools-dir D:\code_competition\_smoke -o out\repair_project_report.json
python repair\selftest.py
python repair\selftest.py --tools-dir D:\code_competition\_smoke
```

执行顺序：Before 检测 → 临时副本 → 应用模板 → 编译级语法检查（不执行）→
重新检测 → 输出结构化报告。提供 `--tools-dir` 时，另用**正式 scanner**
分别扫描修复前后的隔离副本；不提供时只做模板与语法检查，CLI 退出码非零。
原文件不改；口令原文不进入报告或日志。

`random.Random().randbytes(...)` 现在有保守的 Python AST 扫描规则：仅当结果直接赋给
nonce/IV/salt/key 等安全用途变量时报告。三类模板均可在合成夹具上由正式 scanner
独立复扫为 `ELIMINATED`；这仍不等于真实项目测试或行为兼容性已验证。
修复模板现在也只触及这一受限形态：同文件中供模拟/测试使用的 `random.Random(7)`、
赋给普通变量的 `randbytes` 均保持不变；若 `random` 名称在文件内被重绑定，也不自动
改写。不要把此模板理解成全文件替换 `Random`。
安全用途变量上的条件表达式也可被 AST 检出。修复器只对一种两侧均弱随机的明确形态
给出临时补丁：`random.Random().randbytes(n) if hasattr(random.Random, "randbytes")
else bytes(random.randint(0,255) for _ in range(n))`，整体改为 `secrets.token_bytes(n)`。
长度、备用分支或命名稍有不同则只报告、不自动改；测试仍需验证协议行为。
报告的 `new_high_findings` 只有扫描成功时才给数字，否则为 null。
CLI 退出码 0 仅表示**语法 + 扫描结构验证**；所有报告仍标注
`behavioral_compatibility: NOT_VERIFIED` / `manual_review_required: true`。

`--project-root` 是**显式选择执行可信项目代码**：工具在两份临时项目副本上运行
`python -m unittest discover -s tests`，只保存前后 PASS/FAIL、测试数量与超时状态，
不保存测试 stdout/stderr。测试失败时 CLI 返回非零。副本拒绝符号链接、超过
1000 文件或 20 MiB 的项目，跳过 `.git`、`.env*`、`workspace` 等目录；
**临时副本不是操作系统沙箱**，不要对不可信项目开启此选项。
演示项目 `examples/repair_demo` 的三项测试在补丁前后都通过，三类正式复扫均消失；
反例测试故意断言旧 MD5 输出长度，补丁后测试会失败。两者都是自建演示/自检，
不是独立第三方项目的兼容性证明。

当前限制：这是可验证的 Python 首批模板，不声称自动修复任意语言或任意上下文；
没有项目自带测试时，报告明确写 `tests: NOT_RUN`。例如 MD5 摘要长度从
16 字节变为 32 字节，可能影响协议或存储格式；正式应用必须跑项目测试并人工复核。

第三方正向案例见 [Chimera Telegram nonce 验证](../docs/第三方正向修复验证_2026-10-18.md)：条件表达式弱随机 nonce 已检出、临时改为 `secrets.token_bytes(16)`、正式扫描复扫消除，上游模块 45 条原版测试在补丁前后均通过。该项目全量测试和真实网络协议兼容性没有验证；报告仍要求人工复核。

## 第三方项目反例：Requests HTTP Digest（2026-10-18）

使用上游 [Requests](https://github.com/psf/requests) 的源码（本地 checkout
`611c6162`）核对 `src/requests/auth.py`：HTTP Digest 的 MD5 分支明确调用
`hashlib.md5(x, usedforsecurity=False)`。本工具对该文件的 AST 检查结果为
`skipped_protocol_md5=1`、`patch_applied=False`、源码逐字不变。Requests 自带的
`tests/test_requests.py::TestRequests::test_DIGEST_HTTP_200_OK_GET` 在隔离虚拟环境中
通过（1 passed）。这证明该协议调用受到保护；**没有证明任何自动补丁在第三方项目中通过测试**。
上游源码和测试依赖均保留在仓库外，不打包为本项目自研内容。

## 第三方口令哈希反例：Bandit 教程（2026-10-18）

在 [Bandit tutorial 的公开示例](https://github.com/mkathiari/bandit-tutorial/blob/a963e79746a8ad8dbd90390cee10bc93d2c543b5/examples/3bad_crypto.py)
（上游提交 `a963e79746a8ad8dbd90390cee10bc93d2c543b5`）中，
`hashlib.md5(password.encode())` 用于口令哈希。把 MD5 自动替换成 SHA-256
仍是快速摘要，无法完成安全的口令存储迁移；修复器因此返回
`skipped_password_md5=1`、`NO_APPLICABLE_PATCH`、退出码 1，正式 scanner
如实标记 MD5 仍在。调用 `input("Enter your password: ")` 的提示文案曾被
凭据扫描器误报为硬编码口令；已修复，复扫为 `NOT_DETECTED_BEFORE`。
该教程没有可运行的项目自带 `tests/`，所以这**不是第三方正向补丁或行为兼容性验收**。
对真正的口令数据库应人工设计 Argon2id 等口令 KDF、现存摘要的渐进迁移及回滚方案。

## 第三方项目反例：口令文件名不是口令（2026-10-19）

在仓库外的 Chimera checkout `147508ae454a720735a61d2ffc7a00ae2df922fc` 中，
`chimera/modules/fptn_packages.py:57` 定义了 `_FPTN_PASSWD_FILENAME`：其字面量是
**文件名**，不是口令。旧版凭据检测器会在这一行误报硬编码口令，修复模板还会把
文件名改成 `os.environ[...]`，破坏安装路径。现在两者共享同一个保守判断：
以 `_FILENAME`、`_FILE`、`_PATH`、`_HASH` 等元数据后缀结尾的口令命名
不按口令材料自动修复。对该原始模块的独立复验：修复器无编辑，正式凭据检测器
在第 57 行无 Finding；合成真实 `password = ...` 仍可检出并生成模板。
本例是**避免错误补丁**的负向验证，不是正向修复成功或全项目无误报证明。
