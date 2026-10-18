"""Pre-registered CCA-Droid weak-PRNG-key Java fast/deep comparison.

The seven labels and their source checksums were frozen in
docs/CCA-Droid弱随机密钥独立对照预注册_2026-10-18.md before any scan.
Upstream sources, reversible names, bytecode and results stay outside Git.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.pipeline import run as pipeline_run  # noqa: E402

PREFIX = "UnsafePRNGForKey"
RULE_ID = "JAVA-WEAK-PRNG-KEY"
CASES = (
    ("ABICase1", True, "cb1faea6c0026d4e60dce0f6ebde67f9cc4cea7505d8217bb5512cb21c49b236"),
    ("ABICase2", True, "39e7c00787f86a8dc8018da59c1468b0174bfe38e48449c5acd8a6d53a8eda5e"),
    ("ABICase3", True, "8ffa7d96154d02e791d16a0fabfae9aac21af5d6776606d5fbb7d47ad07a7e3a"),
    ("ABPSCase1", False, "619d2a4f1f73096e81501c77d86d047b4f2640cbb70de77c826f3b395ff94b26"),
    ("ABSCase1", True, "2e8dbb646f8334101f0409786f07fcda33fbfd61d051b4180dff8c95d15a44d8"),
    ("BBCase1", True, "a8f82e796ecaac810138c978129db5226c867094f035cf8c108930c0d9b52f30"),
    ("Corrected1", False, "eefeaf197e5472a7bf586433d98d5ea6865f43dc8c5169ab749bc9a4430ee18e"),
)
PACKAGE = re.compile(r"\bpackage\s+[\w.]+\s*;")
CASE_IDENT = re.compile(r"\bUnsafePRNGForKey[A-Za-z0-9_]*\b")
PUBLIC = re.compile(r"\bpublic\s+class\s+(\w+)")
LEAK = re.compile(r"UnsafePRNGForKey|untrustedprngkey|ABPS|Corrected", re.I)


def _anonymous(text, number, original_class):
    """Rename identifiers and package, preserving JCA calls and literals."""
    public = "C%03d" % number
    helper_names = {}

    def rename(match):
        name = match.group(0)
        if name == original_class:
            return public
        if name not in helper_names:
            helper_names[name] = "H%03d_%02d" % (number, len(helper_names) + 1)
        return helper_names[name]

    result, n_pkg = PACKAGE.subn("package holdout.c%03d;" % number, text, count=1)
    if n_pkg != 1:
        raise ValueError("样本缺少唯一 package 声明")
    result = CASE_IDENT.sub(rename, result)
    public_match = PUBLIC.search(result)
    if not public_match or public_match.group(1) != public:
        raise ValueError("匿名化没有保留 public class 与文件名的对应")
    if LEAK.search(result):
        raise ValueError("匿名化源码仍含类别或标签词")
    return result, public


def prepare(source_dir, work, javac):
    source_dir, work, javac = Path(source_dir), Path(work), Path(javac)
    if work.exists():
        raise FileExistsError("输出目录已存在，拒绝覆盖冻结样本: %s" % work)
    if not javac.is_file():
        raise FileNotFoundError("找不到 javac: %s" % javac)
    # Verify every source before writing any anonymized sample.
    originals = []
    for suffix, positive, expected in CASES:
        source = source_dir / (PREFIX + suffix + ".java")
        data = source.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise ValueError("来源样本 SHA-256 不符: %s" % source.name)
        originals.append((source, data.decode("utf-8-sig"), positive))

    src, classes = work / "src", work / "classes"
    src.mkdir(parents=True)
    classes.mkdir()
    labels, private_map, sources = [], {}, []
    for number, (source, text, positive) in enumerate(originals, start=1):
        anonymous, public = _anonymous(text, number, source.stem)
        rel = Path("holdout") / ("c%03d" % number) / (public + ".java")
        target = src / rel
        target.parent.mkdir(parents=True)
        target.write_text(anonymous, encoding="utf-8")
        sources.append(target)
        labels.append({"file": rel.as_posix(), "positive": positive})
        private_map[source.name] = rel.as_posix()

    (work / "labels.json").write_text(
        json.dumps(labels, ensure_ascii=False, indent=2), encoding="utf-8")
    (work / "private-map.json").write_text(
        json.dumps(private_map, ensure_ascii=False, indent=2), encoding="utf-8")
    command = [str(javac), "-proc:none", "-g", "--release", "8", "-d",
               str(classes), *map(str, sources)]
    compiled = subprocess.run(command, text=True, capture_output=True,
                              encoding="utf-8", errors="replace", timeout=120)
    if compiled.returncode:
        raise RuntimeError("匿名样本编译失败 (javac exit=%d): %s" %
                           (compiled.returncode, compiled.stderr[-2000:]))
    jar = javac.with_name("jar.exe")
    if not jar.is_file():
        raise FileNotFoundError("找不到同一 JDK 的 jar.exe")
    artifact = work / "cohort.jar"
    packed = subprocess.run([str(jar), "--create", "--file", str(artifact),
                             "-C", str(classes), "."], text=True,
                            capture_output=True, timeout=60)
    if packed.returncode:
        raise RuntimeError("jar 打包失败: %s" % packed.stderr[-1000:])
    print("准备完成：%d 个匿名 Java 文件，%d 正/%d 负，jar=%s" %
          (len(labels), sum(r["positive"] for r in labels),
           sum(not r["positive"] for r in labels), artifact))
    return work


def _score(labels, rows):
    expected = {r["file"]: r["positive"] for r in labels}
    predicted = {r["file"]: False for r in labels}
    for finding in rows:
        if finding.get("rule_id") == RULE_ID and finding.get("file") in predicted:
            predicted[finding["file"]] = True
    tp = sum(expected[f] and hit for f, hit in predicted.items())
    fp = sum(not expected[f] and hit for f, hit in predicted.items())
    fn = sum(expected[f] and not hit for f, hit in predicted.items())
    tn = sum(not expected[f] and not hit for f, hit in predicted.items())
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and
          precision + recall else None)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4) if precision is not None else None,
            "recall": round(recall, 4) if recall is not None else None,
            "f1": round(f1, 4) if f1 is not None else None,
            "predicted_files": sorted(f for f, hit in predicted.items() if hit)}


def compare(work, tools_dir, crysentry_home, java, timeout=180):
    work = Path(work).resolve()
    src, artifact = work / "src", work / "cohort.jar"
    labels = json.loads((work / "labels.json").read_text(encoding="utf-8"))
    if len(labels) != len(CASES) or not src.is_dir() or not artifact.is_file():
        raise ValueError("固定 cohort 不完整，先执行 prepare")
    fast, fast_task, _, _ = pipeline_run(
        target=src, output_dir=work / "fast", tools_dir=str(tools_dir),
        mode="fast", keep_raw=False)
    deep, deep_task, _, _ = pipeline_run(
        target=src, output_dir=work / "deep", tools_dir=str(tools_dir),
        mode="deep-java", java_artifact=artifact,
        crysentry_home=str(crysentry_home), crysentry_java=str(java),
        deep_timeout=timeout, keep_raw=False)
    stage = next(s for s in deep_task["stages"] if s["name"] == "deep_java")
    if stage["status"] != "completed":
        raise RuntimeError("CrySentry 未完成，不能报告深扫指标: %s %s" %
                           (stage["status"], stage.get("reason")))
    fast_score, deep_score = _score(labels, fast), _score(labels, deep)
    evidence = [e for f in deep for e in f.get("evidence", [])
                if e.get("tool") == "crysentry"]
    report = {
        "cohort": "cca-droid-weak-prng-key-7-v1",
        "scope": "7 pre-frozen file-level weak-PRNG-key cases; not whole-system P/R",
        "fast": fast_score, "deep_java": deep_score,
        "crysentry_evidence": {
            "pattern": sum(e.get("kind") == "pattern" for e in evidence),
            "taint": sum(e.get("kind") == "taint" for e in evidence)},
        "new_findings": sum(RULE_ID == f.get("rule_id") for f in deep),
        "unresolved_deep_evidence": len(deep_task["unresolved_deep_evidence"]),
        "deep_stage_status": stage["status"], "deep_seconds": stage["seconds"],
    }
    (work / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return report


def _selftest():
    labels = [{"file": "a.java", "positive": True},
              {"file": "b.java", "positive": False}]
    assert _score(labels, [])["precision"] is None
    assert _score(labels, [])["fn"] == 1
    sample = _score(labels, [{"file": "a.java", "rule_id": RULE_ID},
                             {"file": "b.java", "rule_id": RULE_ID}])
    assert (sample["tp"], sample["fp"], sample["fn"], sample["tn"]) == (1, 1, 0, 0)
    original = "package org.unsafe.untrustedprngkey; public class UnsafePRNGForKeyABICase1 { Random r; }"
    anonymous, cls = _anonymous(original, 1, "UnsafePRNGForKeyABICase1")
    assert cls == "C001" and "Random r" in anonymous and not LEAK.search(anonymous)
    print("CCA weak-key paired selftest PASS")


def main(argv=None):
    parser = argparse.ArgumentParser(description="预冻结 CCA-Droid 弱随机密钥快/深同题对照")
    parser.add_argument("phase", choices=["selftest", "prepare", "compare"])
    parser.add_argument("--source-dir", help="上游未匿名 Java 文件目录（仓库外）")
    parser.add_argument("--work", help="匿名数据及结果目录（仓库外）")
    parser.add_argument("--javac", help="JDK 17 javac.exe")
    parser.add_argument("--java", help="JDK 17 java.exe")
    parser.add_argument("--tools-dir", default=str(ROOT.parent / "_smoke"))
    parser.add_argument("--crysentry-home", default=str(ROOT.parent / "_smoke" / "CrySentry"))
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args(argv)
    if args.phase == "selftest":
        _selftest()
    elif args.phase == "prepare":
        if not all((args.source_dir, args.work, args.javac)):
            parser.error("prepare 需要 --source-dir、--work 和 --javac")
        prepare(args.source_dir, args.work, args.javac)
    else:
        if not all((args.work, args.java)):
            parser.error("compare 需要 --work 和 --java")
        compare(args.work, args.tools_dir, args.crysentry_home,
                args.java, args.timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
