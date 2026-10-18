# Repair → Verify

当前 v1 在**临时副本**中支持 3 类 Python 修复：

1. `hashlib.md5(...)` → `hashlib.sha256(...)`
2. `random.Random(...)` → `random.SystemRandom(...)`
3. 硬编码口令 → `os.environ["变量名"]`

```cmd
python repair\verify.py path\to\demo.py --tools-dir D:\code_competition\_smoke -o out\repair_report.json
python repair\selftest.py
python repair\selftest.py --tools-dir D:\code_competition\_smoke
```

执行顺序：Before 检测 → 临时副本 → 应用模板 → `ast.parse` 语法检查 →
重新检测 → 输出结构化报告。提供 `--tools-dir` 时，另用**正式 scanner**
分别扫描修复前后的隔离副本；不提供时只做模板与语法检查，CLI 退出码非零。
原文件不改；口令原文不进入报告或日志。

`random.Random().randbytes(...)` 现在有保守的 Python AST 扫描规则：仅当结果直接赋给
nonce/IV/salt/key 等安全用途变量时报告。三类模板均可在合成夹具上由正式 scanner
独立复扫为 `ELIMINATED`；这仍不等于真实项目测试或行为兼容性已验证。
报告的 `new_high_findings` 只有扫描成功时才给数字，否则为 null。
CLI 退出码 0 仅表示**语法 + 扫描结构验证**；所有报告仍标注
`behavioral_compatibility: NOT_VERIFIED` / `manual_review_required: true`。

当前限制：这是可验证的 Python 首批模板，不声称自动修复任意语言或任意上下文；
没有项目自带测试时，报告明确写 `tests: NOT_RUN`。例如 MD5 摘要长度从
16 字节变为 32 字节，可能影响协议或存储格式；正式应用必须跑项目测试并人工复核。
