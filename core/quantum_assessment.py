"""C 层前置量子风险评估：v0.1 scanner Finding -> v0.2 assessed Finding。

确定性密码事实来自本地规则，不调用 LLM。该层位于扫描之后、AI 解释之前。
"""
import argparse
import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.rules.pqc_routing import route  # noqa: E402
from core.quantum_timeline import assess as assess_timeline, make_profile  # noqa: E402
from core.schema.validate_v02 import errors as contract_errors  # noqa: E402

RULES_PATH = ROOT / "core" / "rules" / "quantum_rules.json"
USAGE_RULE = {
    "signing": "PQC-USAGE-SIGNING",
    "encryption": "PQC-USAGE-ENCRYPTION",
    "key_exchange": "PQC-USAGE-KEY-EXCHANGE",
}
RISK_RULE = {
    "shor": ("assessed", "shor", "QR-SHOR-PUBLIC-KEY"),
    "grover": ("assessed", "quantum_search", "QR-QUANTUM-SEARCH"),
    "broken": ("assessed", "no_known_quantum_break", "QR-CLASSICAL-BROKEN"),
    "safe": ("assessed", "no_known_quantum_break", "QR-NO-KNOWN-QUANTUM-BREAK"),
}
AI_FIELDS = ("explanation", "evidence_refs", "usage_assessment",
             "remediation_steps", "analysis_provenance", "quantum_assessment")


def _rules():
    return json.loads(RULES_PATH.read_text(encoding="utf-8"))


def rule_version():
    return _rules()["version"]


def _evidence_refs(finding):
    return ["E%d" % (i + 1) for i in range(len(finding.get("evidence", [])))]


def prepare_scanned(finding):
    """升级扫描事实并清除可能残留的旧 AI 派生字段。"""
    out = copy.deepcopy(finding)
    for name in AI_FIELDS:
        out.pop(name, None)
    out["schema_version"] = "0.2"
    out["stage"] = "scanned"
    out.setdefault("finding_kind", "algorithm")
    out.setdefault("usage", "unknown")
    out["remediation"] = {
        "decided": False,
        "reason": "not-enriched",
        "source": "none",
    }
    return out


def _migration_candidates(finding):
    if finding.get("risk") != "shor":
        return []
    algorithm = finding.get("algorithm", "")
    normalized = finding.get("algorithm_normalized")
    usage = finding.get("usage", "unknown")
    first = route(algorithm, usage, normalized)
    usages = [usage] if first["decided"] and usage in USAGE_RULE else []
    if first["reason"] == "usage-undetermined":
        usages = ["signing", "encryption", "key_exchange"]
    candidates = []
    for candidate_usage in usages:
        routed = route(algorithm, candidate_usage, normalized)
        if not routed["decided"]:
            continue
        rule_id = USAGE_RULE[candidate_usage]
        candidates.append({
            "usage": candidate_usage,
            "route_id": _rules()["rules"][rule_id]["route_id"],
            "rule_refs": [rule_id],
            "conditions": [
                "仅当实际用途确认为 %s 时采用；最终路线由规则库复核。"
                % candidate_usage
            ],
        })
    return candidates


def assess_one(finding, timeline_profile=None):
    out = prepare_scanned(finding)
    refs = _evidence_refs(out)
    version = rule_version()
    kind = out["finding_kind"]
    risk = out.get("risk", "review")

    if kind == "credential" or risk == "not_applicable":
        assessment = {
            "status": "not_applicable",
            "quantum_effect": "not_applicable",
            "classical_issues": (["该发现属于凭据问题，按凭据规则整改。"]
                                 if kind == "credential" else []),
            "rule_version": version,
            "rule_refs": [],
            "evidence_refs": refs,
            "unknowns": [],
            "migration_candidates": [],
        }
    elif risk in RISK_RULE:
        status, effect, rule_id = RISK_RULE[risk]
        assessment = {
            "status": status,
            "quantum_effect": effect,
            "classical_issues": (["该算法或用法已存在经典安全问题，应立即整改。"]
                                 if risk == "broken" else []),
            "rule_version": version,
            "rule_refs": [rule_id],
            "evidence_refs": refs,
            "unknowns": (["实际业务用途尚未确认。"]
                         if risk == "shor" and out.get("usage") == "unknown" else []),
            "migration_candidates": _migration_candidates(out),
        }
    else:
        assessment = {
            "status": "insufficient_evidence",
            "quantum_effect": "unknown",
            "classical_issues": [],
            "rule_version": version,
            "rule_refs": [],
            "evidence_refs": refs,
            "unknowns": ["风险仍为 review，需要确认具体算法、参数或调用上下文。"],
            "migration_candidates": [],
        }

    assessment["quantum_timeline"] = assess_timeline(
        assessment["quantum_effect"], out.get("usage", "unknown"),
        timeline_profile)
    out["quantum_assessment"] = assessment
    out["stage"] = "assessed"
    problems = contract_errors(out)
    if problems:
        raise ValueError("v0.2 契约校验失败: %s" % "; ".join(problems))
    return out


def assess_all(findings, timeline_profile=None):
    return [assess_one(f, timeline_profile) for f in findings]


def assess_file(input_path, output_path, timeline_profile=None):
    rows = json.loads(Path(input_path).read_text(encoding="utf-8-sig"))
    if not isinstance(rows, list):
        rows = [rows]
    result = assess_all(rows, timeline_profile)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="执行本地前置量子风险评估")
    parser.add_argument("input", help="scanner 产出的 v0.1 findings.json")
    parser.add_argument("-o", "--output", default="out/findings_assessed.json")
    parser.add_argument("--data-lifetime-years", type=float)
    parser.add_argument("--migration-lead-years", type=float)
    parser.add_argument("--threat-horizon-years", type=float)
    parser.add_argument("--hndl-exposure", choices=["yes", "no", "unknown"],
                        default="unknown")
    args = parser.parse_args(argv)
    try:
        profile = make_profile(args.data_lifetime_years, args.migration_lead_years,
                               args.threat_horizon_years, args.hndl_exposure,
                               "user-input" if args.data_lifetime_years is not None
                               else "not-provided")
        result = assess_file(args.input, args.output, profile)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("[错误] 量子风险评估失败: %s" % exc)
        return 2
    counts = {}
    for finding in result:
        key = finding["quantum_assessment"]["quantum_effect"]
        counts[key] = counts.get(key, 0) + 1
    print("[ok] 前置量子风险评估完成：%d 条，%s" %
          (len(result), json.dumps(counts, ensure_ascii=False)))
    print("输出: %s" % Path(args.output).resolve())
    return 0


if __name__ == "__main__":
    sys.exit(main())
