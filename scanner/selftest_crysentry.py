"""CrySentry runner/adapter 离线自检；不启动 Java、不依赖第三方仓库。"""
import json
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner.adapters.crysentry import adapt, fuse
from scanner.runners.crysentry import build_options, stage_artifact, stage_classpath
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
        with zipfile.ZipFile(artifact, "w") as zf:
            zf.writestr("org/demo/Sample.class", b"fixture")
        options = build_options(artifact, [], root / "result.json",
                                root / "analysis", cfg)
        check("配置指向隔离结果文件", (root / "result.json").resolve().as_posix() in options)
        check("配置包含用户编译产物", artifact.resolve().as_posix() in options)
        check("空 classpath 是合法 YAML 形式", "classPath: []" in options)
        same_drive_cp = stage_classpath([artifact], root / "same-drive-task")
        check("同盘 classpath 保留原路径，不无故复制",
              same_drive_cp == [artifact.resolve()])
        stage_dir = root / "staged"
        stage_dir.mkdir()
        staged = stage_artifact(artifact, stage_dir)
        check("任意 jar 会被隔离改名为 CrySentry 可识别的 test.jar",
              staged.name == "test.jar" and staged.read_bytes() == artifact.read_bytes())
        traversal = root / "traversal.jar"
        with zipfile.ZipFile(traversal, "w") as zf:
            zf.writestr("../outside.class", b"fixture")
        try:
            stage_artifact(traversal, stage_dir)
        except Exception as exc:
            check("拒绝可越界解压的 jar 条目", "越界路径" in str(exc))
        else:
            raise AssertionError("未拒绝越界 jar 条目")
        classes = root / "classes" / "org" / "demo"
        classes.mkdir(parents=True)
        (classes / "Sample.class").write_bytes(b"class-fixture")
        with zipfile.ZipFile(stage_artifact(root / "classes", stage_dir)) as zf:
            check("classes 目录能封装为可识别的应用 jar",
                  "org/demo/Sample.class" in zf.namelist())

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
        with_line = dict(data[0], sourceStmt=(
            "<org.demo.Sample: void encrypt()>[3@L18] "
            "invokevirtual $-v1.nextBytes($-v2)"))
        located_line, _ = adapt([with_line], root)
        flow_line = located_line[0]["evidence"]["flow"]
        check("sourceStmt 自带真实行号时只提取位置，不保存源语句",
              flow_line["source"]["file"] == src.relative_to(root).as_posix() and
              flow_line["source"]["line"] == 18 and
              flow_line["completeness"] == "partial" and
              "sourceStmt" not in located_line[0]["evidence"]["raw"])
        check("Predictable Source 的字符串不冒充算法",
              taints[0]["algorithm"] == "")
        check("raw 不保存 sourceStmt 原文",
              all("sourceStmt" not in r["evidence"]["raw"] for r in located))

        transform = dict(data[1], constantValue="AES/ECB/PKCS5Padding")
        normalized, _ = adapt([transform], root)
        check("JCE 变换串归一到 AES/ECB，原字面量留在证据",
              normalized[0]["algorithm"] == "AES/ECB" and
              normalized[0]["evidence"]["raw"]["algorithm_constant"] ==
              "AES/ECB/PKCS5Padding")
        keygen = dict(data[1], constantValue="DES", calleeMethod=
                      "<javax.crypto.KeyGenerator: javax.crypto.KeyGenerator getInstance(java.lang.String)>")
        keygen_record, _ = adapt([keygen], root)
        check("KeyGenerator 算法证据归属 encryption 用途，避免重复 Finding",
              keygen_record[0]["usage"] == "encryption")

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
