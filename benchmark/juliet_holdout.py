"""Prepare a *new* Juliet Java diagnostic cohort before looking at results.

The upstream RVSec JulietBench checkout is external. This script copies only
the 85 CWE-327/328 cases whose weak primitive is an algorithm Finding in our
scope. Each file also contains a good() branch, so this is **not** 170
independent file-level examples. The cohort is a same-unit diagnostic, not
proof of the competition's full 120-sample / eight-credential-class targets.

The output, original-to-anonymous map and labels must remain outside Git.
Nothing in this module runs a scanner. Commit/review the preparation code and
freeze the generated manifest before running one against the cohort.
"""
import argparse
import hashlib
import importlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmark.anonymize import AnonMap, _sanitize_source  # noqa: E402

GROUPS = (
    ("CWE327_Use_Broken_Crypto", "DES", "DES", "encryption"),
    ("CWE327_Use_Broken_Crypto", "3DES", "DES", "encryption"),
    ("CWE328_Reversible_One_Way_Hash", "MD2", "MD2", "hashing"),
    ("CWE328_Reversible_One_Way_Hash", "MD5", "MD5", "hashing"),
    ("CWE328_Reversible_One_Way_Hash", "SHA1", "SHA1", "hashing"),
)
EXPECTED_LITERALS = {"DES": '"DES"', "3DES": '"DESede"',
                     "MD2": '"MD2"', "MD5": '"MD5"',
                     "SHA1": '"SHA1"'}
CASE_RE = re.compile(r"^(CWE\d+_[A-Za-z_]+__([A-Za-z0-9]+)_(\d\d))\.java$")
LEAK_RE = re.compile(
    r"CWE\d+|\b(?:FLAW|FIX|BadSink|GoodSink)\b|Use_Broken|Reversible_One_Way",
    re.I)


def _code_hash(path):
    normalized = Path(path).read_text(encoding="utf-8").replace("\r\n", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _without_comments(source):
    """Blank comments but preserve newlines, code and quoted Java literals."""
    out, i, n = [], 0, len(source)
    while i < n:
        if source.startswith("//", i):
            j = source.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif source.startswith("/*", i):
            j = source.find("*/", i + 2)
            if j < 0:
                raise ValueError("未闭合的 Java 块注释")
            j += 2
            out.append("".join("\n" if ch == "\n" else " " for ch in source[i:j]))
            i = j
        elif source[i] in ('"', "'"):
            quote, j = source[i], i + 1
            while j < n:
                if source[j] == "\\":
                    j += 2
                elif source[j] == quote:
                    j += 1
                    break
                else:
                    j += 1
            else:
                raise ValueError("未闭合的 Java 字面量")
            out.append(source[i:j])
            i = j
        else:
            out.append(source[i])
            i += 1
    return "".join(out)


def _collect(source_root):
    base = source_root / "JulietBench" / "benchmark" / "src" / "testcases"
    cases = []
    for category, token, algorithm, usage in GROUPS:
        files = sorted((base / category).glob(f"{category}__{token}_*.java"))
        if len(files) != 17:
            raise ValueError(f"{category}/{token}: 期望 17 例，实际 {len(files)}")
        for path in files:
            match = CASE_RE.fullmatch(path.name)
            if not match or match.group(2) != token or not 1 <= int(match.group(3)) <= 17:
                raise ValueError(f"非预期样本名: {path.name}")
            cases.append((path, token, algorithm, usage))
    if len(cases) != 85 or len({c[0] for c in cases}) != 85:
        raise AssertionError("Juliet 85 例冻结清单不完整或重复")
    return cases


def prepare(source_root, output):
    source_root, output = Path(source_root).resolve(), Path(output).resolve()
    if output.exists():
        raise FileExistsError(f"输出已存在，拒绝覆盖冻结语料: {output}")
    cases = _collect(source_root)
    records = []
    amap = AnonMap("juliet-rvsec-holdout")
    staged = []
    for index, (path, token, algorithm, usage) in enumerate(cases, 1):
        original = path.read_text(encoding="utf-8-sig")
        stripped = _without_comments(original)
        if stripped.count("\n") != original.count("\n"):
            raise AssertionError("注释清理改变了行数")
        if not re.search(r"\bvoid\s+bad\s*\(", stripped) or not re.search(
                r"\bvoid\s+good\s*\(", stripped):
            raise ValueError(f"未找到 bad()/good(): {path.name}")
        if EXPECTED_LITERALS[token] not in stripped:
            raise ValueError(f"源代码未包含预期弱算法字面量: {path.name}")
        stem = path.stem
        amap.tokens[stem] = f"Case{index:04d}"
        text = _sanitize_source(stripped, amap)
        text, count = re.subn(r"\bpackage\s+[\w.]+\s*;", "package holdout;", text, count=1)
        if count != 1 or LEAK_RE.search(text) or stem in text:
            raise ValueError(f"匿名化残留标签或 package: {path.name}")
        name = f"Case{index:04d}.java"
        rel = path.relative_to(source_root).as_posix()
        amap.files[rel] = name
        staged.append((name, text))
        records.append({"benchmark": "juliet-rvsec-2026-10-18",
                        "file": name, "algorithm": algorithm,
                        "algorithms": [algorithm], "usage": usage,
                        "category": "brokencrypto" if usage == "encryption" else "brokenhash",
                        "verdict": "in", "expect_misuse": True,
                        "label_origin_sha256": hashlib.sha256(original.encode()).hexdigest()})
    output.mkdir(parents=True)
    (output / "src").mkdir()
    for name, text in staged:
        (output / "src" / name).write_bytes(text.encode("utf-8"))
    labels = json.dumps(records, sort_keys=True, indent=2) + "\n"
    (output / "labels.json").write_bytes(labels.encode("utf-8"))
    (output / "private-map.json").write_bytes(
        (json.dumps(amap.to_json(), sort_keys=True, indent=2) + "\n").encode("utf-8"))
    manifest = {"upstream": "PAMunb/RVSec-replication-package/JulietBench",
                "upstream_commit": _git_head(source_root),
                "preparer_sha256": _code_hash(__file__),
                "scorer_sha256": _code_hash(ROOT / "benchmark" / "eval.py"),
                "scope": "CWE-327/328, five primitive groups, all 17 files per group",
                "unit": "file+normalized-algorithm; good() shares each file",
                "source_files": 85, "positive_units": 85,
                "labels_sha256": hashlib.sha256(labels.encode()).hexdigest(),
                "anonymous_sources": {name: hashlib.sha256(text.encode()).hexdigest()
                                      for name, text in staged}}
    (output / "FROZEN_MANIFEST.json").write_bytes(
        (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    return manifest


def _git_head(path):
    import subprocess
    proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=path,
                          capture_output=True, text=True, check=True)
    return proc.stdout.strip()


def _selftest():
    source = '/* FLAW "MD5" */\nclass Foo { String x="/* MD5 */"; // FIX\n}'
    result = _without_comments(source)
    assert result.count("\n") == source.count("\n")
    assert 'FLAW' not in result and 'FIX' not in result
    assert '"/* MD5 */"' in result
    scorer = importlib.import_module("benchmark.eval")
    labels = [{"file": "Case0001.java", "algorithms": ["MD5"],
               "verdict": "in", "expect_misuse": True}]
    right = [{"file": "Case0001.java", "algorithm": "MD5", "risk": "broken"}]
    wrong = [{"file": "Case0001.java", "algorithm": "MD5", "risk": "shor"}]
    assert _score_rows(labels, right, scorer)["tp"] == 1
    assert _score_rows(labels, wrong, scorer)["tp"] == 0
    assert _score_rows(labels, wrong, scorer)["fp"] == 1
    assert _score_rows(labels, wrong, scorer)["fn"] == 1
    print("Juliet comment stripping selftest: PASS")


def _score_rows(labels, findings, scorer):
    """Predeclared metric: weak-algorithm alerts must also call the risk broken.

    `review` and `safe` are inventory/uncertain output, not an asserted
    vulnerability. Actionable wrong-risk alerts count as both FP and FN.
    Credential/configuration findings are a different task and are excluded.
    """
    relevant = []
    for finding in findings:
        if finding.get("finding_kind") in ("credential", "configuration"):
            continue
        risk = finding.get("risk")
        if risk not in ("broken", "shor", "grover"):
            continue
        item = dict(finding)
        if risk != "broken":
            item["algorithm_normalized"] = "WRONGRISK"
            item["algorithm"] = "WRONGRISK"
        relevant.append(item)
    raw = scorer.match(labels, relevant)
    p, r, f1 = scorer.prf(raw["tp"], raw["fp"], raw["fn"])
    return {"tp": raw["tp"], "fp": raw["fp"], "fn": raw["fn"],
            "precision": round(p, 4), "recall": round(r, 4),
            "f1": round(f1, 4), "actionable": len(relevant),
            "wrong_risk": sum(row.get("risk") in ("shor", "grover")
                              for row in findings)}


def score(output, findings_path):
    output = Path(output).resolve()
    manifest = json.loads((output / "FROZEN_MANIFEST.json").read_text(encoding="utf-8"))
    if manifest["preparer_sha256"] != _code_hash(__file__) or manifest[
            "scorer_sha256"] != _code_hash(ROOT / "benchmark" / "eval.py"):
        raise ValueError("预登记脚本或计分器已改变；不能沿用本次冻结口径")
    label_bytes = (output / "labels.json").read_bytes()
    if hashlib.sha256(label_bytes).hexdigest() != manifest["labels_sha256"]:
        raise ValueError("冻结标签哈希不符；拒绝评分")
    for name, expected in manifest["anonymous_sources"].items():
        actual = hashlib.sha256((output / "src" / name).read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"匿名源码哈希不符: {name}")
    labels = json.loads(label_bytes)
    if len(labels) != 85 or manifest["positive_units"] != 85:
        raise ValueError("冻结标签数变化；拒绝评分")
    findings = json.loads(Path(findings_path).read_text(encoding="utf-8-sig"))
    if not isinstance(findings, list):
        raise ValueError("Finding 输出必须是 JSON 数组")
    scorer = importlib.import_module("benchmark.eval")
    result = _score_rows(labels, findings, scorer)
    result.update({"cohort": "RVSec JulietBench CWE-327/328",
                   "upstream_commit": manifest["upstream_commit"],
                   "positive_units": 85,
                   "scope": "actionable weak-algorithm Findings; broken risk required",
                   "limitations": "good() shares positive files; no separate file-level negatives; "
                                  "not a 120-case full-system holdout"})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", nargs="?", help="prepare: 仓库外 RVSec checkout；score: 冻结目录")
    parser.add_argument("output", nargs="?", help="prepare: 全新冻结目录；score: Finding JSON")
    parser.add_argument("--score", action="store_true", help="按预先锁定的口径评分")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.selftest:
        _selftest()
        return 0
    if not args.source or not args.output:
        parser.error("需要两个路径参数")
    if args.score:
        print(json.dumps(score(args.source, args.output), ensure_ascii=False, indent=2))
        return 0
    manifest = prepare(args.source, args.output)
    print(json.dumps({k: v for k, v in manifest.items()
                      if k != "anonymous_sources"}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
