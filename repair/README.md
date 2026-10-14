# Repair → Verify

当前 v1 在**临时副本**中支持 3 类 Python 修复：

1. `hashlib.md5(...)` → `hashlib.sha256(...)`
2. `random.Random(...)` → `random.SystemRandom(...)`
3. 硬编码口令 → `os.environ["变量名"]`

```cmd
python repair\verify.py path\to\demo.py -o out\repair_report.json
python repair\selftest.py
```

执行顺序：Before 检测 → 临时副本 → 应用模板 → `ast.parse` 语法检查 →
重新检测 → 输出结构化报告。原文件不改；口令原文不进入报告或日志。

当前限制：这是可验证的 Python 首批模板，不声称自动修复任意语言或任意上下文；
没有项目自带测试时，报告明确写 `tests: NOT_RUN`。正式自动应用仍需人工确认。
