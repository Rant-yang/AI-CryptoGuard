# 抗量子迁移用途分派公开样例

本目录是本项目原创的**无持久密钥**演示源码。`SigningDemo.java` 调用 RSA 签名；
`KeyExchangeDemo.java` 调用 ECDH 密钥协商。两个文件都只在运行时生成临时密钥，
不含真实凭据或用户项目代码。样例是为了展示**先看实际用途，再给迁移路线**，
不是生产级密钥管理实现，也不是评测集。

在 Windows cmd 中从仓库根目录运行（第三方工具仍在仓库外）：

```cmd
cd /d D:\code_competition\AI-CryptoGuard
python core\pipeline.py examples\pqc_demo --tools-dir D:\code_competition\_smoke --data-lifetime-years 5 --migration-lead-years 2 --threat-horizon-years 4 --hndl-exposure yes -o out\pqc_demo
python core\schema\validate_v02.py out\pqc_demo\findings_assessed.json
python core\report.py out\pqc_demo\findings_assessed.json -o out\pqc_demo_report.html --task out\pqc_demo\task.json
```

本机首次实扫：cbom-scan 2 个原始组、CryptoScan 4 个原始组，融合后 3 条
`shor` Finding：`RSA / signing`、`ECDH / key_exchange`、`ECC / unknown`。
前两条各只有与用途相符的一条迁移候选；`ECC / unknown` 保留多条**带条件**的
候选，不能选定单一算法。示例 X=5、Y=2、Z=4 年使三条时间评估成为
`immediate`；这些年数是**演示假设**，不是对量子计算出现时间的预测。
网页还可在未启用 AI 的情况下展示扫描与本地量子评估；AI 默认关闭时，
整改解释应显示为未生成，不能把它说成模型给出的结论。

可选 AI 解释使用 `--ai` 或网页勾选。只扫描这份公开代码时可以启用；
真实项目需先确认允许发往云模型，凭据 Finding 始终本地处理。
演示前检查 `task.json` 中每个阶段状态，不能把 `skipped` 说成成功运行。

### AI 证据边界的实测

最初版本仅把 RSA 的 `KeyPairGenerator.getInstance` 与 ECDH 的算法名交给 AI，
模型有理由将具体用途退回 `unknown`。现由 `core/usage_evidence.py` 在**同文件、
同算法、20 行内、用途不冲突**的现有 Finding 上追加 Java JCA 消费证据；只有
同一局部变量的 `initSign → sign` 或 `init → doPhase → generateSecret` 确实出现在
同一有界代码块内，才附上消费调用。证据只存 API 名称与行号，不保存源码文本，
也不新增漏洞 Finding 或重写上游扫描器。

本机单条真实模型回归：有 `Signature.sign` 证据的 RSA 条目返回 `signing`，
有 `KeyAgreement.generateSecret` 证据的 ECDH 条目返回 `key_exchange`，两条均通过
v0.2 Schema。**这是公开演示样例的功能回归，不是用途识别准确率**；AI 输出
仍需人工复核。当前同一行的通用 `ECC` 与具体 `ECDH` 可能分别形成 Finding，
后续需按源调用归属收敛，不能声称已完全消重。
