"""AI-CryptoGuard 统一入口（C 线）。

当前接通：快速扫描 -> v0.2 前置量子风险评估 -> 任务状态。
CrySentry 与 v0.2 AI 由 A/B 合入后接入这里；未接通阶段明确标 skipped。
"""
import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.quantum_assessment import assess_file, rule_version  # noqa: E402
from core.schema.validate_v02 import errors as contract_errors  # noqa: E402
from scanner.scan import main as scanner_main  # noqa: E402


def _stage(name, status="pending", reason=None, seconds=0, tool_version=None):
    return {"name": name, "status": status, "reason": reason,
            "seconds": round(seconds, 3), "tool_version": tool_version}


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                   encoding="utf-8")
    tmp.replace(path)


def _languages(target=None, findings=None):
    suffixes = {
        ".java": "java", ".py": "python", ".go": "go", ".js": "javascript",
        ".ts": "typescript", ".c": "c", ".cc": "cpp", ".cpp": "cpp",
    }
    found = set()
    if target:
        for path in Path(target).rglob("*"):
            if path.is_file() and path.suffix.lower() in suffixes:
                found.add(suffixes[path.suffix.lower()])
    for finding in findings or []:
        suffix = Path(finding.get("file", "")).suffix.lower()
        if suffix in suffixes:
            found.add(suffixes[suffix])
    return sorted(found) or ["unknown"]


def _task_id(seed):
    raw = (str(seed) + "|" + str(time.time_ns())).encode("utf-8")
    return "task-" + hashlib.sha256(raw).hexdigest()[:12]


def run(target=None, findings_path=None, output_dir="out/run", tools_dir=None,
        tool="both", timeout=300, keep_raw=False, cbom=False):
    out_dir = Path(output_dir).resolve()
    scan_path = out_dir / "findings.json"
    assessed_path = out_dir / "findings_assessed.json"
    task_path = out_dir / "task.json"
    task = {
        "schema_version": "0.2",
        "task_id": _task_id(target or findings_path),
        "mode": "fast",
        "languages": ["unknown"],
        "stages": [
            _stage("scan"),
            _stage("deep_java", "skipped", "CrySentry runner 尚未由 A 合入统一入口。"),
            _stage("quantum_assessment"),
            _stage("ai", "skipped", "B 的 v0.2 AI 输出尚未合入统一入口。"),
        ],
        "unresolved_deep_evidence": [],
    }
    _write(task_path, task)

    if findings_path:
        source = Path(findings_path).resolve()
        if not source.is_file():
            raise ValueError("找不到已有扫描结果: %s" % source)
        rows = json.loads(source.read_text(encoding="utf-8-sig"))
        rows = rows if isinstance(rows, list) else [rows]
        task["stages"][0] = _stage("scan", "skipped", "使用已有扫描结果。")
    else:
        if not target or not Path(target).is_dir():
            raise ValueError("必须提供有效项目目录，或使用 --findings。")
        source = scan_path
        args = [str(Path(target).resolve()), "-o", str(scan_path), "--tool", tool,
                "--timeout", str(timeout)]
        if tools_dir:
            args += ["--tools-dir", tools_dir]
        if not keep_raw:
            args.append("--no-raw")
        if cbom:
            args.append("--cbom")
        started = time.time()
        code = scanner_main(args)
        elapsed = time.time() - started
        if code != 0:
            task["stages"][0] = _stage("scan", "failed",
                                                "scanner 退出码 %d" % code, elapsed)
            _write(task_path, task)
            raise RuntimeError("扫描失败，退出码 %d" % code)
        rows = json.loads(scan_path.read_text(encoding="utf-8-sig"))
        task["stages"][0] = _stage("scan", "completed", seconds=elapsed,
                                    tool_version="scanner-v0.1")

    task["languages"] = _languages(target, rows)
    _write(task_path, task)
    started = time.time()
    try:
        result = assess_file(source, assessed_path)
    except Exception:
        task["stages"][2] = _stage(
            "quantum_assessment", "failed",
            "前置量子评估失败；详见本地控制台。", time.time() - started,
            "quantum-rules-" + rule_version())
        _write(task_path, task)
        raise
    task["stages"][2] = _stage("quantum_assessment", "completed",
                                seconds=time.time() - started,
                                tool_version="quantum-rules-" + rule_version())
    problems = contract_errors(task)
    if problems:
        raise ValueError("task.json 不合规: %s" % "; ".join(problems))
    _write(task_path, task)
    return result, task, assessed_path, task_path


def main(argv=None):
    parser = argparse.ArgumentParser(description="扫描 -> 前置量子评估统一入口")
    parser.add_argument("target", nargs="?", help="要扫描的项目目录")
    parser.add_argument("--findings", help="跳过扫描，使用已有 v0.1 findings.json")
    parser.add_argument("-o", "--output-dir", default="out/run")
    parser.add_argument("--tools-dir")
    parser.add_argument("--tool", choices=["both", "cbom-scan", "cryptoscan"],
                        default="both")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--keep-raw", action="store_true")
    parser.add_argument("--cbom", action="store_true")
    args = parser.parse_args(argv)
    if bool(args.target) == bool(args.findings):
        parser.error("项目目录与 --findings 必须且只能提供一个")
    try:
        result, task, assessed, task_path = run(
            args.target, args.findings, args.output_dir, args.tools_dir,
            args.tool, args.timeout, args.keep_raw, args.cbom)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print("[错误] 流水线失败: %s" % exc)
        return 2
    print("\n====== C 线统一入口完成 ======")
    print("assessed findings : %d 条" % len(result))
    print("AI 阶段           : skipped（等待 B 的 v0.2 交付）")
    print("深度 Java         : skipped（等待 A 的 runner 交付）")
    print("评估输出          : %s" % assessed)
    print("任务状态          : %s" % task_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
