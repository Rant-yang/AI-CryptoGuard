"""Frozen, file-level weak-hash holdout from OWASP Benchmark Python v0.1.

Official CSV labels and source stay outside this repository. The entire hash
category is used: no case may be selected or removed after seeing scanner output.
This diagnostic has a different counting unit from the project-wide
(file, algorithm, usage) benchmark, so its P/R must never be pooled with it.
"""

import argparse
import collections
import csv
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path


UPSTREAM_COMMIT = "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"
OFFICIAL_CSV_SHA256 = "0c5ae0f9a8cdcb49549c459a25651cc058c7b17d621fc064ade2bd942dad80b8"
COHORT_SIZE = 151
POSITIVES = 71
NEGATIVES = 80
WEAK_HASHES = frozenset({"MD2", "MD4", "MD5", "SHA1"})


def labels_for(repo):
    path = repo / "expectedresults-0.1.csv"
    actual_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual_sha != OFFICIAL_CSV_SHA256:
        raise ValueError("Official labels differ from the pre-registered CSV hash")
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo,
                              capture_output=True, text=True, check=True).stdout.strip()
    if revision != UPSTREAM_COMMIT:
        raise ValueError("Upstream revision differs from frozen commit: " + revision)
    with path.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.reader(stream))
    labels = {}
    for row in rows[1:]:
        if len(row) < 3 or row[1].strip() != "hash":
            continue
        truth = row[2].strip().lower()
        if truth not in ("true", "false"):
            raise ValueError("Unexpected official truth: %r" % truth)
        name = row[0].strip() + ".py"
        if not re.fullmatch(r"BenchmarkTest\d{5}\.py", name):
            raise ValueError("Unexpected official test name: %r" % name)
        if name in labels:
            raise ValueError("Duplicate official test: " + name)
        labels[name] = truth == "true"
    counts = collections.Counter(labels.values())
    if len(labels) != COHORT_SIZE or counts[True] != POSITIVES or counts[False] != NEGATIVES:
        raise ValueError("Official hash cohort changed: %r" % counts)
    missing = [name for name in labels if not (repo / "testcode" / name).is_file()]
    if missing:
        raise FileNotFoundError("Missing labeled source: " + missing[0])
    return labels


def prepare(repo, dest):
    labels = labels_for(repo)
    if dest.exists():
        raise FileExistsError("Destination must be new: " + str(dest))
    dest.mkdir(parents=True)
    for name in sorted(labels):
        shutil.copy2(repo / "testcode" / name, dest / name)
    manifest = {
        "source": "OWASP-Benchmark/BenchmarkPython",
        "upstream_commit": UPSTREAM_COMMIT,
        "official_csv_sha256": hashlib.sha256(
            (repo / "expectedresults-0.1.csv").read_bytes()).hexdigest(),
        "unit": "file: one weak-hash claim per official test file",
        "category": "hash",
        "positives": POSITIVES,
        "negatives": NEGATIVES,
        "files": {name: hashlib.sha256((dest / name).read_bytes()).hexdigest()
                  for name in sorted(labels)},
    }
    (dest.parent / (dest.name + ".manifest.json")).write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("Prepared %d opaque-named Python files: %d positive / %d negative."
          % (len(labels), POSITIVES, NEGATIVES))
    print("Manifest: " + str(dest.parent / (dest.name + ".manifest.json")))


def _weak_hash_finding(item):
    if item.get("risk") != "broken":
        return False
    raw = item.get("algorithm_normalized") or item.get("algorithm") or ""
    normalized = re.sub(r"[^A-Z0-9]", "", str(raw).upper())
    return normalized in WEAK_HASHES


def score(repo, source, findings_path):
    labels = labels_for(repo)
    actual = {p.name for p in source.glob("*.py")}
    if actual != set(labels):
        raise ValueError("Scan tree differs from frozen cohort: missing=%d extra=%d" %
                         (len(set(labels) - actual), len(actual - set(labels))))
    manifest_path = source.parent / (source.name + ".manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("upstream_commit") != UPSTREAM_COMMIT or manifest.get("category") != "hash":
        raise ValueError("Unexpected cohort manifest")
    if manifest.get("official_csv_sha256") != hashlib.sha256(
            (repo / "expectedresults-0.1.csv").read_bytes()).hexdigest():
        raise ValueError("Official labels changed since preparation")
    for name in labels:
        if manifest["files"].get(name) != hashlib.sha256((source / name).read_bytes()).hexdigest():
            raise ValueError("Staged source changed: " + name)
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    if not isinstance(findings, list):
        raise ValueError("Expected a findings JSON array")
    found = set()
    ignored = 0
    for item in findings:
        name = Path(str(item.get("file", "")).replace("\\", "/")).name
        if name not in labels:
            raise ValueError("Finding outside frozen cohort: " + name)
        if _weak_hash_finding(item):
            found.add(name)
        else:
            ignored += 1
    tp = sum(labels[name] for name in found)
    fp = sum(not labels[name] for name in found)
    fn = POSITIVES - tp
    tn = NEGATIVES - fp
    return {"cohort": COHORT_SIZE, "positive": POSITIVES, "negative": NEGATIVES,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(tp / (tp + fp), 4) if tp + fp else None,
            "recall": round(tp / (tp + fn), 4),
            "ignored_other_findings": ignored,
            "unit": "file-level weak hash; not project-wide finding unit"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("upstream", type=Path)
    prep.add_argument("destination", type=Path)
    eval_cmd = sub.add_parser("score")
    eval_cmd.add_argument("upstream", type=Path)
    eval_cmd.add_argument("source", type=Path)
    eval_cmd.add_argument("findings", type=Path)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.upstream, args.destination)
    else:
        print(json.dumps(score(args.upstream, args.source, args.findings),
                         ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
