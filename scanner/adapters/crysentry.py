"""CrySentry JSON -> v0.2 深度证据，并与快速 Finding 保守融合。"""
import copy
import hashlib
import re
from pathlib import Path

from core.rules.algorithm_risk import risk_for
from scanner.normalize import canon_algorithm

TOOL_NAME = "crysentry"
_SITE_RE = re.compile(r"^<(?P<class>[^:>]+):\s*(?P<method>[^>]+)>\[[^]]*@L(?P<line>\d+)\]")
_METHOD_RE = re.compile(r"^<(?P<class>[^:>]+):\s*(?P<method>[^>]+)>")
_QUOTED_RE = re.compile(r'["\']([^"\']+)["\']')


def _source_index(root):
    index = {"__all__": []}
    for path in Path(root).resolve().rglob("*.java"):
        rel = path.relative_to(Path(root).resolve()).as_posix()
        index["__all__"].append(rel)
        index.setdefault(path.name.lower(), []).append(rel)
        index.setdefault(rel.lower(), []).append(rel)
    return index


def _class_file(class_name, index):
    if not class_name:
        return None
    base = class_name.split("$")[0]
    suffix = (base.replace(".", "/") + ".java").lower()
    exact = index.get(suffix, [])
    if len(exact) == 1:
        return exact[0]
    by_suffix = [rel for rel in index.get("__all__", [])
                 if rel.lower().endswith("/" + suffix) or rel.lower() == suffix]
    if len(by_suffix) == 1:
        return by_suffix[0]
    by_name = index.get((base.rsplit(".", 1)[-1] + ".java").lower(), [])
    return by_name[0] if len(by_name) == 1 else None


def _site(value, index):
    match = _SITE_RE.search(value or "")
    if not match:
        return None
    return {"file": _class_file(match.group("class"), index),
            "line": int(match.group("line")), "method": match.group("method")}


def _method(value, index):
    match = _METHOD_RE.search(value or "")
    if not match:
        return None
    return {"file": _class_file(match.group("class"), index),
            "line": None, "method": match.group("method")}


def _algorithm_constant(record):
    # 只有 Pattern Match 的常量才具有“算法名”语义。Predictable Source 的
    # sourceStmt 可能是口令/密钥值，绝不能抽出来当算法或写入 raw。
    if record.get("judgeType") == "Pattern Match":
        value = record.get("constantValue")
        if isinstance(value, str) and value.strip():
            return value.strip()
        stmt = record.get("sourceStmt") or ""
        quoted = _QUOTED_RE.search(stmt)
        if quoted:
            return quoted.group(1).strip()
    return ""


def _algorithm(record):
    constant = _algorithm_constant(record)
    if constant:
        # JCE transformation strings are algorithm/mode/padding descriptors.
        # A separate Finding named "AES/ECB/PKCS5Padding" duplicates the
        # scanner's AES/ECB finding and is not a distinct algorithm. Preserve
        # the full literal in evidence.raw.algorithm_constant below.
        parts = constant.split("/")
        if len(parts) >= 2 and parts[0].upper() == "AES" and parts[1].upper() == "ECB":
            return "AES/ECB"
        if len(parts) >= 2:
            return parts[0]
        return constant
    callee = record.get("calleeMethod") or ""
    if "PBEKeySpec" in callee:
        return "PBKDF2"
    return ""


def _usage(record):
    callee = record.get("calleeMethod") or ""
    if "Signature" in callee:
        return "signing"
    if "KeyAgreement" in callee:
        return "key_exchange"
    if "MessageDigest" in callee:
        return "hashing"
    if "Mac:" in callee or "PBEKeySpec" in callee:
        return "authentication"
    if ("Cipher" in callee or "SecretKeySpec" in callee or
            "KeyGenerator" in callee):
        return "encryption"
    return "unknown"


def _raw(record):
    """保留可溯源元数据，但不保存 sourceStmt/凭据原文。"""
    keys = ("judgeType", "message", "callSite", "sourceMethod", "var",
            "calleeMethod", "subSignature")
    out = {k: record[k] for k in keys if k in record}
    out["sourceStmt_present"] = bool(record.get("sourceStmt"))
    alg = _algorithm_constant(record)
    if alg:
        out["algorithm_constant"] = alg
    return out


def _flow(record, sink, index):
    source_stmt = record.get("sourceStmt") or ""
    source = _method(record.get("sourceMethod"), index) if source_stmt else None
    complete = "partial" if source is not None else "source_missing"
    return {"source": source, "sink": sink, "path": [], "completeness": complete}


def adapt(data, source_root):
    """返回 (located_records, unresolved_deep_evidence)。"""
    index = _source_index(source_root)
    located, unresolved = [], []
    for record in data if isinstance(data, list) else []:
        sink = _site(record.get("callSite"), index)
        is_taint = record.get("judgeType") == "Predictable Source"
        if not sink or not sink.get("file") or not sink.get("line"):
            if is_taint:
                fallback = sink or {"file": None, "line": None, "method": None}
                unresolved.append({
                    "tool": TOOL_NAME, "kind": "taint",
                    "reason": "CrySentry 调用点无法可靠映射到项目源码文件/行号。",
                    "flow": _flow(record, fallback, index),
                })
            continue
        evidence = {"tool": TOOL_NAME,
                    "kind": "taint" if is_taint else "pattern",
                    "lines": [sink["line"]], "raw": _raw(record)}
        if is_taint:
            evidence["flow"] = _flow(record, sink, index)
        located.append({"file": sink["file"], "line": sink["line"],
                        "algorithm": _algorithm(record), "usage": _usage(record),
                        "evidence": evidence})
    return located, unresolved


def _id(file, alg, usage):
    return hashlib.sha1((file + "|" + alg + "|" + usage).encode("utf-8")).hexdigest()[:12]


def fuse(fast_findings, deep_records):
    """把定位成功的深度证据挂到快速 Finding；无法对齐但有算法时新建。"""
    rows = copy.deepcopy(fast_findings)
    unresolved = []
    # CrySentry 不保证输出顺序：同一调用点的 Predictable Source 可能排在
    # Pattern Match 前。先处理有算法的记录建立锚点，再挂无算法 taint，
    # 否则结果会随 JSON 顺序变化并静默丢证据。
    ordered = sorted(deep_records, key=lambda r: 0 if r.get("algorithm") else 1)
    for rec in ordered:
        alg = canon_algorithm(rec.get("algorithm") or "")
        candidates = []
        for row in rows:
            if row.get("file") != rec["file"]:
                continue
            lines = {row.get("line")}
            for ev in row.get("evidence", []):
                lines.update(ev.get("lines") or [])
            if rec["line"] not in lines:
                continue
            if alg and row.get("algorithm_normalized") != alg:
                continue
            candidates.append(row)
        # 同一文件/算法/用途的不同调用点属于同一 Finding，行号进 evidence。
        # 先尝试精确行号；没有时再按冻结的计数单位收口。
        if not candidates and alg:
            candidates = [row for row in rows
                          if row.get("file") == rec["file"]
                          and row.get("algorithm_normalized") == alg
                          and row.get("usage", "unknown") in
                          (rec.get("usage", "unknown"), "unknown")]
        if len(candidates) > 1 and rec.get("usage") not in (None, "unknown"):
            same_usage = [row for row in candidates
                          if row.get("usage") == rec.get("usage")]
            if same_usage:
                candidates = same_usage
        if len(candidates) == 1:
            ev = rec["evidence"]
            fingerprint = (ev["tool"], ev["kind"], tuple(ev["lines"]),
                           str(ev.get("raw", {}).get("callSite")))
            existing = {(e["tool"], e["kind"], tuple(e["lines"]),
                         str(e.get("raw", {}).get("callSite")))
                        for e in candidates[0].get("evidence", [])}
            if fingerprint not in existing:
                candidates[0].setdefault("evidence", []).append(ev)
                candidates[0]["line"] = min(candidates[0].get("line", rec["line"]),
                                             rec["line"])
            continue
        if not alg:
            ev = rec["evidence"]
            if ev.get("kind") == "taint" and ev.get("flow"):
                unresolved.append({
                    "tool": TOOL_NAME, "kind": "taint",
                    "reason": "调用点已定位，但缺少算法且无法唯一对齐快速 Finding。",
                    "flow": ev["flow"],
                })
            continue
        usage = rec.get("usage") or "unknown"
        risk = risk_for(alg)
        rows.append({
            "schema_version": "0.1", "finding_id": _id(rec["file"], alg, usage),
            "file": rec["file"], "line": rec["line"],
            "algorithm": rec["algorithm"], "algorithm_normalized": alg,
            "usage": usage, "risk": risk,
            "severity": "high" if risk in ("shor", "broken") else "medium",
            "confidence": 0.9, "evidence": [rec["evidence"]],
            "remediation": {"decided": False, "reason": "not-enriched",
                            "source": "none"},
            "finding_kind": "algorithm", "tags": ["deep-java-new"],
        })
    rows.sort(key=lambda f: (f.get("file", ""), f.get("line", 0), f.get("finding_id", "")))
    return rows, unresolved
