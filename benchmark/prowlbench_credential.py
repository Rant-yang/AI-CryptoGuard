"""Freeze and score ProwlBench's complete code slice for credential detection.

Source snippets and labels stay outside Git. No snippet text, secret, masked
value, fingerprint or raw Finding is printed or saved by this program.
This is a binary snippet-level secret-presence task, *not* validation of the
project's eight credential-management defect subtypes.
"""
import argparse
import collections
import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner.adapters import credential_scan  # noqa: E402

EXPECTED_TOTAL = 9732
EXPECTED_POSITIVE = 6693
EXPECTED_NEGATIVE = 3039
SOURCE = "code"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def code_digest(path):
    normalized = Path(path).read_text(encoding="utf-8").replace("\r\n", "\n")
    return digest(normalized.encode("utf-8"))


def tree_digest(root, count):
    h = hashlib.sha256()
    for i in range(1, count + 1):
        name = f"case_{i:06d}.py"
        path = root / name
        h.update(name.encode("ascii") + b"\0")
        h.update(path.read_bytes())
        h.update(b"\0")
    if len(list(root.glob("*.py"))) != count:
        raise ValueError("匿名代码文件数变化；拒绝沿用冻结结果")
    return h.hexdigest()


def _source_head(repo):
    proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo,
                          check=True, capture_output=True, text=True)
    return proc.stdout.strip()


def prepare(repo, output):
    repo, output = Path(repo).resolve(), Path(output).resolve()
    source = repo / "prowlbench.jsonl"
    if output.exists():
        raise FileExistsError("冻结目录已存在；拒绝覆盖")
    if not source.is_file():
        raise FileNotFoundError("缺少上游 prowlbench.jsonl")

    rows = []
    snippets = []
    seen_ids = set()
    with source.open(encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if row.get("source") != SOURCE:
                continue
            case_id, label, content = row.get("id"), row.get("label"), row.get("text")
            if (not isinstance(case_id, str) or case_id in seen_ids or
                    type(label) is not int or label not in (0, 1) or
                    not isinstance(content, str)):
                raise ValueError("上游代码片段的 ID、标签或内容无效")
            seen_ids.add(case_id)
            name = f"case_{len(rows) + 1:06d}.py"
            rows.append({"file": name, "label": label,
                         "type": str(row.get("type") or "unknown"),
                         "tier": str(row.get("tier") or "unknown"),
                         "origin": str(row.get("origin") or "unknown")})
            snippets.append((name, content))
    positives = sum(r["label"] for r in rows)
    if (len(rows), positives, len(rows)-positives) != (
            EXPECTED_TOTAL, EXPECTED_POSITIVE, EXPECTED_NEGATIVE):
        raise ValueError("上游数据大小或正负分布改变；不得沿用本次口径")

    output.mkdir(parents=True)
    code_root = output / "src"
    code_root.mkdir()
    for name, content in snippets:
        (code_root / name).write_text(content, encoding="utf-8")
    label_bytes = (json.dumps(rows, ensure_ascii=False, sort_keys=True,
                              indent=2) + "\n").encode("utf-8")
    (output / "labels.json").write_bytes(label_bytes)
    manifest = {
        "source_repo": "https://github.com/Lercas/prowlbench",
        "source_commit": _source_head(repo),
        "dataset_sha256": digest(source.read_bytes()),
        "prepare_score_sha256": code_digest(__file__),
        "detector_sha256": code_digest(ROOT / "scanner" / "adapters" / "credential_scan.py"),
        "labels_sha256": digest(label_bytes),
        "anonymous_src_sha256": tree_digest(code_root, len(rows)),
        "selection": "all source=code rows, in upstream order; no outcome-based exclusion",
        "file_extension": ".py",
        "unit": "one snippet file; any credential Finding means predicted positive",
        "total": len(rows), "positive": positives,
        "negative": len(rows)-positives,
        "limitations": "binary secret presence, not eight defect classes or span accuracy",
    }
    (output / "FROZEN_MANIFEST.json").write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8")
    return manifest


def metrics(labels, predicted):
    expected = {r["file"]: r["label"] for r in labels}
    if len(expected) != len(labels) or not predicted <= expected.keys():
        raise ValueError("标签重复或检测输出来自非冻结文件")
    tp = sum(expected[name] == 1 for name in predicted)
    fp = sum(expected[name] == 0 for name in predicted)
    fn = sum(value == 1 and name not in predicted for name, value in expected.items())
    tn = sum(value == 0 and name not in predicted for name, value in expected.items())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(p, 4), "recall": round(r, 4),
            "f1": round(2*p*r/(p+r) if p+r else 0.0, 4),
            "negative_fpr": round(fp/(fp+tn) if fp+tn else 0.0, 4)}


def score(output):
    output = Path(output).resolve()
    manifest = json.loads((output / "FROZEN_MANIFEST.json").read_text(encoding="utf-8"))
    if (manifest["prepare_score_sha256"] != code_digest(__file__) or
            manifest["detector_sha256"] != code_digest(ROOT / "scanner" / "adapters" / "credential_scan.py")):
        raise ValueError("评分或检测代码已变化；当前结果不能作为本次冻结首次成绩")
    label_bytes = (output / "labels.json").read_bytes()
    if digest(label_bytes) != manifest["labels_sha256"]:
        raise ValueError("标签哈希改变；拒绝评分")
    labels = json.loads(label_bytes)
    if (len(labels) != manifest["total"] or
            sum(r["label"] for r in labels) != manifest["positive"] or
            tree_digest(output / "src", manifest["total"]) != manifest["anonymous_src_sha256"]):
        raise ValueError("冻结语料内容或数量变化；拒绝评分")

    # Only the neutral .py files are scanned. Labels/manifest remain outside src.
    findings = credential_scan.scan(output / "src")
    predicted = {Path(f["file"]).name for f in findings}
    result = metrics(labels, predicted)
    result.update({"cohort": "ProwlBench code-only v2.0",
                   "source_commit": manifest["source_commit"],
                   "files": manifest["total"], "positive": manifest["positive"],
                   "negative": manifest["negative"],
                   "findings": len(findings),
                   "unique_positive_predictions": len(predicted),
                   "rules": dict(sorted(collections.Counter(
                       f.get("rule_id", "unknown") for f in findings).items())),
                   "boundary": manifest["limitations"]})
    return result


def selftest():
    labels = [{"file": "a.py", "label": 1}, {"file": "b.py", "label": 0},
              {"file": "c.py", "label": 1}, {"file": "d.py", "label": 0}]
    assert metrics(labels, {"a.py", "b.py"}) == {
        "tp": 1, "fp": 1, "fn": 1, "tn": 1,
        "precision": 0.5, "recall": 0.5, "f1": 0.5, "negative_fpr": 0.5}
    assert metrics(labels, set())["fn"] == 2
    try:
        metrics(labels, {"labels.json"})
    except ValueError:
        pass
    else:
        raise AssertionError("必须拒绝把标签文件当成扫描输出")
    print("ProwlBench code-only metric selftest: PASS")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    pre = sub.add_parser("prepare")
    pre.add_argument("repo")
    pre.add_argument("output")
    score_cmd = sub.add_parser("score")
    score_cmd.add_argument("output")
    sub.add_parser("selftest")
    args = parser.parse_args()
    if args.action == "selftest":
        selftest()
    elif args.action == "prepare":
        manifest = prepare(args.repo, args.output)
        print(json.dumps({k: manifest[k] for k in (
            "source_commit", "dataset_sha256", "labels_sha256",
            "anonymous_src_sha256", "total", "positive", "negative")},
            ensure_ascii=False, indent=2))
    else:
        print(json.dumps(score(args.output), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
