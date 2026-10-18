"""Reproducible, compile-compatible anonymized Java fast/deep comparison.

This is an exploratory *fixed cohort*, not the project's full benchmark score.
Original source and the reversible map stay outside the Git repository.
"""
import argparse
import copy
import importlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmark.anonymize import AnonMap, _sanitize_source, leak_check  # noqa: E402
from core.pipeline import run as pipeline_run  # noqa: E402

BENCH = ROOT.parent / "_benchmarks" / "CryptoAPI-Bench"
LABELS = ROOT / "benchmark" / "labels" / "cryptoapi-bench.json"
# ABPS negative cases retain vulnerable literals in an unreachable branch:
# useful for testing whether deeper analysis rejects shallow false alarms.
# Several upstream *Corrected.java files call a missing BBCase1 class from main;
# excluding those is a compile-dependency decision made before scoring.
CASES = {
    "brokencrypto": ["BrokenCryptoABICase1", "BrokenCryptoABICase2",
                     "BrokenCryptoABICase10", "BrokenCryptoABICase12",
                     "BrokenCryptoABPSCase1"],
    "brokenhash": ["BrokenHashABICase1", "BrokenHashABICase2",
                   "BrokenHashABICase3", "BrokenHashABMC1", "BrokenHashABPSCase1"],
    "ecbcrypto": ["EcbInSymmCryptoABICase1", "EcbInSymmCryptoABICase2",
                  "EcbInSymmCryptoABICase3", "EcbInSymmCryptoABMC1",
                  "EcbInSymmCryptoABPSCase1"],
    "insecureasymmetriccrypto": ["InsecureAsymmetricCipherABICase1",
                                  "InsecureAsymmetricCipherABICase2",
                                  "InsecureAsymmetricCipherABICase3",
                                  "InsecureAsymmetricCipherABMC1",
                                  "InsecureAsymmetricCipherABPSCase1"],
    "predictableseeds": ["PredictableSeedsABICase1", "PredictableSeedsABICase2",
                         "PredictableSeedsABICase3", "PredictableSeedsABMC1",
                         "PredictableSeedsCorrected"],
}
PACKAGE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.M)
PUBLIC_CLASS = re.compile(r"\bpublic\s+(?:(?:final|abstract)\s+)?class\s+(\w+)")


def _selected(rows):
    wanted = {(category, stem) for category, stems in CASES.items() for stem in stems}
    chosen = {(r["category"], Path(r["orig_file"]).stem): r for r in rows
              if (r["category"], Path(r["orig_file"]).stem) in wanted}
    missing = wanted - chosen.keys()
    if missing:
        raise ValueError("固定样本缺失: %s" % sorted(missing))
    return [chosen[key] for key in sorted(wanted)]


def prepare(work, javac):
    work = Path(work).resolve()
    if work.exists():
        raise FileExistsError("工作目录已存在，请指定新路径以保留上次结果: %s" % work)
    src, classes = work / "src", work / "classes"
    src.mkdir(parents=True)
    classes.mkdir()
    rows = _selected(json.loads(LABELS.read_text(encoding="utf-8")))
    amap = AnonMap("cryptoapi-java-paired")
    labels, sources = [], []
    for label in rows:
        original = BENCH / label["orig_file"]
        original_text = original.read_text(encoding="utf-8")
        original_class = PUBLIC_CLASS.search(original_text)
        if not original_class:
            raise ValueError("样本没有可解析的 public class: %s" % original)
        # Every class gets an opaque name, including names without a keyword
        # in LEAK_WORDS (e.g. EcbInSymmCryptoABPSCase1). The ABPS/Corrected
        # suffix itself exposes the negative label to a downstream LLM.
        amap.tokens[original_class.group(1)] = "C%04d" % (len(sources) + 1)
        text = _sanitize_source(original_text, amap)
        pkg = PACKAGE.search(text)
        cls = PUBLIC_CLASS.search(text)
        if not pkg or not cls:
            raise ValueError("样本没有可解析的 package/public class: %s" % original)
        rel = Path(*pkg.group(1).split(".")) / (cls.group(1) + ".java")
        if leak_check(text) or leak_check(str(rel)):
            raise ValueError("匿名化后仍包含答案词: %s" % original)
        target = src / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        sources.append(target)
        clean = copy.deepcopy(label)
        clean["file"] = rel.as_posix()
        clean.pop("orig_file", None)
        labels.append(clean)
        amap.files[label["orig_file"]] = rel.as_posix()
    (work / "labels.json").write_text(
        json.dumps(labels, ensure_ascii=False, indent=2), encoding="utf-8")
    (work / "private-map.json").write_text(
        json.dumps(amap.to_json(), ensure_ascii=False, indent=2), encoding="utf-8")
    # -proc:none prevents annotation processors from executing at compile time.
    command = [str(javac), "-proc:none", "-g", "--release", "8", "-d",
               str(classes), *map(str, sources)]
    compiled = subprocess.run(command, text=True, capture_output=True,
                              encoding="utf-8", errors="replace", timeout=120)
    if compiled.returncode:
        raise RuntimeError("匿名 Java 样本编译失败 (javac exit=%d); 详见编译诊断。\n%s" %
                           (compiled.returncode, compiled.stderr[-2000:]))
    jar = Path(javac).with_name("jar.exe")
    if not jar.is_file():
        raise FileNotFoundError("找不到同一 JDK 的 jar.exe: %s" % jar)
    artifact = work / "cohort.jar"
    packed = subprocess.run([str(jar), "--create", "--file", str(artifact),
                             "-C", str(classes), "."], capture_output=True,
                            text=True, timeout=60)
    if packed.returncode:
        raise RuntimeError("jar 打包失败: %s" % packed.stderr[-1000:])
    count = len(list(classes.rglob("*.class")))
    if count < len(rows):
        raise AssertionError("编译类数少于样本数")
    print("匿名 Java cohort: %d 文件、%d class、%d 标签；输出 %s" %
          (len(sources), count, len(labels), work))
    return work


def _score(labels, rows):
    scoring = importlib.import_module("benchmark.eval")
    found = scoring.match(labels, rows)
    precision, recall, f1 = scoring.prf(found["tp"], found["fp"], found["fn"])
    return {"tp": found["tp"], "fp": found["fp"], "fn": found["fn"],
            "precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4), "reported": found["n_reported"],
            "out_of_scope": found["n_pos_out_of_scope"],
            "negatives": found["n_negative"]}


def compare(work, tools_dir, crysentry_home, java, timeout=180):
    work = Path(work).resolve()
    if work.anchor.lower() != Path(crysentry_home).resolve().anchor.lower():
        raise ValueError("Windows 上 CrySentry/Tai-e 要求工作目录与工具同盘；"
                         "请在 %s 盘准备匿名 cohort。" %
                         Path(crysentry_home).resolve().anchor)
    src, artifact = work / "src", work / "cohort.jar"
    labels = json.loads((work / "labels.json").read_text(encoding="utf-8"))
    if not src.is_dir() or not artifact.is_file() or not labels:
        raise ValueError("先执行 prepare，确认匿名源码、jar、标签全部存在")
    fast, fast_task, _, _ = pipeline_run(
        target=src, output_dir=work / "fast", tools_dir=tools_dir,
        mode="fast", keep_raw=False)
    deep, deep_task, _, _ = pipeline_run(
        target=src, output_dir=work / "deep", tools_dir=tools_dir,
        mode="deep-java", java_artifact=artifact,
        crysentry_home=crysentry_home, crysentry_java=java,
        deep_timeout=timeout, keep_raw=False)
    deep_stage = next(s for s in deep_task["stages"] if s["name"] == "deep_java")
    fast_stage = next(s for s in fast_task["stages"] if s["name"] == "scan")
    deep_scan_stage = next(s for s in deep_task["stages"] if s["name"] == "scan")
    if deep_stage["status"] != "completed":
        raise RuntimeError("深度工具未完成（%s）；不能计算声称为 deep 的指标。" %
                           deep_stage["status"])
    baseline, augmented = _score(labels, fast), _score(labels, deep)
    evidence = [e for f in deep for e in f.get("evidence", [])
                if e.get("tool") == "crysentry"]
    report = {"cohort": "cryptoapi-java-paired-v2",
              "scope": "25 preselected compile-compatible files; exploratory, not full benchmark",
              "n_labels": len(labels), "fast": baseline, "deep_java": augmented,
              "crysentry_evidence": {
                  "pattern": sum(e.get("kind") == "pattern" for e in evidence),
                  "taint": sum(e.get("kind") == "taint" for e in evidence),
              },
              "new_findings": sum("deep-java-new" in f.get("tags", []) for f in deep),
              "unresolved_deep_evidence": len(deep_task["unresolved_deep_evidence"]),
              "stage_seconds": {"fast_scan": fast_stage["seconds"],
                                "deep_scan": deep_scan_stage["seconds"],
                                "crysentry": deep_stage["seconds"]},
              "deep_status": deep_stage["status"]}
    (work / "report.json").write_text(json.dumps(report, ensure_ascii=False,
                                                  indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="固定匿名 Java 样本的 fast/deep 同题对照")
    parser.add_argument("phase", choices=["prepare", "compare"])
    parser.add_argument("--work", required=True, help="仓库外输出目录；prepare 要求尚不存在")
    parser.add_argument("--javac", help="JDK 17 javac.exe（prepare）")
    parser.add_argument("--java", help="JDK 17 java.exe（compare）")
    parser.add_argument("--tools-dir", default=str(ROOT.parent / "_smoke"))
    parser.add_argument("--crysentry-home", default=str(ROOT.parent / "_smoke" / "CrySentry"))
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args(argv)
    if args.phase == "prepare":
        if not args.javac:
            parser.error("prepare 需要 --javac")
        prepare(args.work, args.javac)
    else:
        if not args.java:
            parser.error("compare 需要 --java")
        compare(args.work, args.tools_dir, args.crysentry_home,
                args.java, args.timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
