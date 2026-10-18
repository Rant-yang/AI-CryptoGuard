"""CrySentry runner/adapter 离线自检；不启动 Java、不依赖第三方仓库。"""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner.adapters.crysentry import adapt, fuse
from scanner.runners.crysentry import build_options
from core.quantum_assessment import assess_all
from core.schema.validate_v02 import errors


def check(name, value):
    if not value:
        raise AssertionError(name)
    print("[PASS] " + name)


def main():
    with tempfile.TemporaryDirectory(prefix="acg-crysentry-test-") as td:
        root = Path(td)
        src = root / "module-a" / "src" / "main" / "java" / "org" / "demo" / "Sample.java"
        src.parent.mkdir(parents=True)
        src.write_text("class Sample {}\n", encoding="utf-8")
        cfg = root / "crypto-config.yml"
        cfg.write_text("rules: []\n", encoding="utf-8")
        artifact = root / "app.jar"
        artifact.write_bytes(b"fixture")
        options = build_options(artifact, [], root / "result.json",
                                root / "analysis", cfg)
        check("配置指向隔离结果文件", (root / "result.json").resolve().as_posix() in options)
        check("配置包含用户编译产物", artifact.resolve().as_posix() in options)
        check("空 classpath 是合法 YAML 形式", "classPath: []" in options)

        call = ("<org.demo.Sample: void encrypt()>[6@L42] "
                "cipher = invokestatic javax.crypto.Cipher.getInstance($-c1)")
        data = [
            # 故意让无算法 taint 排在 pattern 前：真实 CrySentry 输出就是这种顺序。
            {"judgeType": "Predictable Source", "message": "predictable", "callSite": call,
             "sourceStmt": '$x = "real-secret-must-not-become-algorithm"',
             "sourceMethod": "<org.demo.Sample: void encrypt()>", "var": "$-v1", "calleeMethod":
             "<javax.crypto.spec.SecretKeySpec: void <init>(byte[],java.lang.String)>"},
            {"judgeType": "Pattern Match", "message": "insecure", "callSite": call,
             "sourceStmt": '$-c1 = "Blowfish"', "sourceMethod": "<org.demo.Sample: void encrypt()>",
             "constantValue": "Blowfish", "calleeMethod":
             "<javax.crypto.Cipher: javax.crypto.Cipher getInstance(java.lang.String)>"},
            {"judgeType": "Predictable Source", "message": "unmapped",
             "callSite": "<missing.Clazz: void x()>[1@L9] invokespecial x", "sourceStmt": ""},
        ]
        located, unresolved = adapt(data, root)
        check("两条可定位记录进入深度证据", len(located) == 2)
        check("无法定位的 taint 进入 unresolved", len(unresolved) == 1)
        taints = [r for r in located if r["evidence"]["kind"] == "taint"]
        check("有 sourceStmt 但无行号时明确记 partial",
              taints[0]["evidence"]["flow"]["completeness"] == "partial")
        check("Predictable Source 的字符串不冒充算法",
              taints[0]["algorithm"] == "")
        check("raw 不保存 sourceStmt 原文",
              all("sourceStmt" not in r["evidence"]["raw"] for r in located))

        fused, ambiguous = fuse([], located)
        check("测试数据没有融合歧义", not ambiguous)
        check("同文件同算法同用途按冻结计数单位收口", len(fused) == 1)
        assessed = assess_all(fused)
        bad = [errors(row) for row in assessed if errors(row)]
        check("新增深度 Finding 通过 v0.2 契约", not bad)
        check("至少一条 taint 证据保留下来",
              any(e["kind"] == "taint" for f in assessed for e in f["evidence"]))
    print("CrySentry 离线自检完成。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
