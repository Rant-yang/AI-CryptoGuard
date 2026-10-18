"""AI-CryptoGuard 统一入口（C 线）。

快速扫描 -> 可选 CrySentry Java 深度证据 -> 前置量子评估 -> 可选 AI 解释。
AI 必须显式开启；未开启时状态保持 skipped。
"""
import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.quantum_assessment import assess_all, rule_version  # noqa: E402
from core.quantum_timeline import make_profile  # noqa: E402
from core.schema.validate_v02 import errors as contract_errors  # noqa: E402
from ai.enrich_v02 import enrich_file as enrich_ai_file  # noqa: E402
from scanner.scan import main as scanner_main  # noqa: E402
from scanner.adapters.crysentry import adapt as adapt_crysentry  # noqa: E402
from scanner.adapters.crysentry import fuse as fuse_crysentry  # noqa: E402
from scanner.runners.crysentry import run as run_crysentry  # noqa: E402


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
        tool="both", timeout=300, keep_raw=False, cbom=False,
        timeline_profile=None, mode="fast", java_artifact=None,
        java_classpath=None, source_root=None, crysentry_home=None,
        crysentry_java=None, crysentry_jar=None, deep_timeout=900,
        deep_memory_mb=4096, java_target_version=8, ai=False,
        ai_context="full", ai_resume=False, ai_checkpoint=10):
    out_dir = Path(output_dir).resolve()
    scan_path = out_dir / "findings.json"
    assessed_path = out_dir / "findings_assessed.json"
    explained_path = out_dir / "findings_explained.json"
    if not ai_resume and explained_path.exists():
        explained_path.unlink()
    explained_written = False
    task_path = out_dir / "task.json"
    timeline_profile = timeline_profile or make_profile(source="not-provided")
    task = {
        "schema_version": "0.2",
        "task_id": _task_id(target or findings_path),
        "mode": mode,
        "languages": ["unknown"],
        "stages": [
            _stage("scan"),
            _stage("deep_java", "skipped", "未请求 Java 深度扫描。"),
            _stage("quantum_assessment"),
            _stage("ai", "skipped", "未请求云端 AI 解释；评估结果仍可查看。"),
        ],
        "quantum_timeline_profile": timeline_profile,
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

    task["languages"] = _languages(target or source_root, rows)
    _write(task_path, task)

    # ---- 可选 Java 深度证据。失败/超时保留快速扫描结果，不把 skipped 当零问题。
    if mode == "deep-java":
        root = source_root or target
        if "java" not in task["languages"]:
            task["stages"][1] = _stage(
                "deep_java", "skipped", "目标中未发现 Java 源文件。")
        elif not java_artifact:
            task["stages"][1] = _stage(
                "deep_java", "skipped", "未提供 --java-artifact；未自动执行 Maven/Gradle。")
        elif not root or not Path(root).is_dir():
            task["stages"][1] = _stage(
                "deep_java", "skipped", "缺少源码根目录，无法把字节码调用点映射回源码。")
        elif not crysentry_home:
            task["stages"][1] = _stage(
                "deep_java", "skipped", "未提供 --crysentry-home 或 CRYSENTRY_HOME。")
        else:
            task["stages"][1] = _stage("deep_java", "running")
            _write(task_path, task)
            deep = run_crysentry(
                java_artifact, out_dir / "deep-java", crysentry_home,
                java_classpath or [], crysentry_java, crysentry_jar,
                deep_timeout, deep_memory_mb, java_target_version)
            if deep["status"] == "completed":
                try:
                    located, unresolved = adapt_crysentry(deep["data"], root)
                    rows, fuse_unresolved = fuse_crysentry(rows, located)
                    unresolved += fuse_unresolved
                    task["unresolved_deep_evidence"] = unresolved
                    reason = "定位 %d 条深度记录；未定位 %d 条。" % (
                        len(located), len(unresolved))
                    task["stages"][1] = _stage(
                        "deep_java", "completed", reason, deep["seconds"],
                        deep["tool_version"])
                    if not keep_raw:
                        shutil.rmtree(out_dir / "deep-java", ignore_errors=True)
                except Exception as exc:  # 深度适配失败也不得抹掉 fast 结果
                    task["stages"][1] = _stage(
                        "deep_java", "failed", "深度结果适配失败: %s" % exc,
                        deep["seconds"], deep["tool_version"])
            else:
                task["stages"][1] = _stage(
                    "deep_java", deep["status"], deep["reason"], deep["seconds"],
                    deep["tool_version"])
        _write(task_path, task)

    started = time.time()
    try:
        result = assess_all(rows, timeline_profile)
        _write(assessed_path, result)
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
    if ai:
        remote_rows = [f for f in result
                       if f.get("finding_kind") != "credential" and
                       "conditional-default" not in f.get("tags", []) and
                       f.get("rule_id") != "PY-WEAK-RANDOM-CRYPTO"]
        if remote_rows and (not os.environ.get("ANTHROPIC_AUTH_TOKEN") or
                            not os.environ.get("ANTHROPIC_MODEL")):
            task["stages"][3] = _stage(
                "ai", "failed", "缺少模型配置 ANTHROPIC_AUTH_TOKEN / ANTHROPIC_MODEL；未调用云端。")
        else:
            started = time.time()
            task["stages"][3] = _stage("ai", "running")
            _write(task_path, task)
            try:
                explained, failed, reused = enrich_ai_file(
                    assessed_path, explained_path, context=ai_context,
                    resume=ai_resume, checkpoint=ai_checkpoint)
                explained_written = explained_path.is_file()
                task["stages"][3] = _stage(
                    "ai", "failed" if failed else "completed",
                    ("%d 条解释成功，%d 条失败，%d 条复用。" %
                     (len(explained) - len(failed), len(failed), reused)),
                    time.time() - started, "ai-v0.2")
                result = explained
            except Exception as exc:
                task["stages"][3] = _stage(
                    "ai", "failed", "AI 阶段异常: %s" % type(exc).__name__,
                    time.time() - started, "ai-v0.2")
    problems = contract_errors(task)
    if problems:
        raise ValueError("task.json 不合规: %s" % "; ".join(problems))
    _write(task_path, task)
    result_path = (explained_path if ai and explained_written
                   else assessed_path)
    return result, task, result_path, task_path


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="快速扫描 -> 可选 Java 深度证据 -> 量子评估 -> 可选 AI 解释")
    parser.add_argument("target", nargs="?", help="要扫描的项目目录")
    parser.add_argument("--findings", help="跳过扫描，使用已有 v0.1 findings.json")
    parser.add_argument("-o", "--output-dir", default="out/run")
    parser.add_argument("--tools-dir")
    parser.add_argument("--tool", choices=["both", "cbom-scan", "cryptoscan"],
                        default="both")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--keep-raw", action="store_true")
    parser.add_argument("--cbom", action="store_true")
    parser.add_argument("--mode", choices=["fast", "deep-java"], default="fast")
    parser.add_argument("--java-artifact", help="已编译的 Java jar 或 classes 目录")
    parser.add_argument("--java-classpath", action="append", default=[],
                        help="依赖 jar/目录；可重复传入。不会自动执行构建脚本")
    parser.add_argument("--source-root",
                        help="使用 --findings 时用于深度结果源码映射的项目根目录")
    parser.add_argument("--crysentry-home", default=os.environ.get("CRYSENTRY_HOME"),
                        help="仓库外的 CrySentry 目录（也可设 CRYSENTRY_HOME）")
    parser.add_argument("--crysentry-java", help="JDK 17 java.exe")
    parser.add_argument("--crysentry-jar", help="已构建的 tai-e-all jar")
    parser.add_argument("--deep-timeout", type=int, default=900)
    parser.add_argument("--deep-memory-mb", type=int, default=4096)
    parser.add_argument("--java-target-version", type=int, default=8,
                        help="目标字节码 Java 版本（默认 8）")
    parser.add_argument("--data-lifetime-years", type=float,
                        help="X：数据/安全有效期（年）")
    parser.add_argument("--migration-lead-years", type=float,
                        help="Y：完成迁移所需时间（年）")
    parser.add_argument("--threat-horizon-years", type=float,
                        help="Z：组织采用的量子威胁时间窗（年）")
    parser.add_argument("--hndl-exposure", choices=["yes", "no", "unknown"],
                        default="unknown", help="是否存在先收集后解密暴露")
    parser.add_argument("--ai", action="store_true", help="显式启用 v0.2 AI 解释")
    parser.add_argument("--ai-context", choices=["shape", "full"], default="full",
                        help="full 发送脱敏代码行；shape 仅发送调用形状")
    parser.add_argument("--ai-resume", action="store_true", help="复用校验通过的 AI 结果")
    parser.add_argument("--ai-checkpoint", type=int, default=10)
    args = parser.parse_args(argv)
    if bool(args.target) == bool(args.findings):
        parser.error("项目目录与 --findings 必须且只能提供一个")
    try:
        timeline_profile = make_profile(
            args.data_lifetime_years, args.migration_lead_years,
            args.threat_horizon_years, args.hndl_exposure,
            "user-input" if args.data_lifetime_years is not None
            else "not-provided")
        result, task, assessed, task_path = run(
            args.target, args.findings, args.output_dir, args.tools_dir,
            args.tool, args.timeout, args.keep_raw, args.cbom,
            timeline_profile, args.mode, args.java_artifact,
            args.java_classpath, args.source_root, args.crysentry_home,
            args.crysentry_java, args.crysentry_jar, args.deep_timeout,
            args.deep_memory_mb, args.java_target_version, args.ai,
            args.ai_context, args.ai_resume, args.ai_checkpoint)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print("[错误] 流水线失败: %s" % exc)
        return 2
    print("\n====== C 线统一入口完成 ======")
    print("findings          : %d 条" % len(result))
    by_name = {stage["name"]: stage for stage in task["stages"]}
    print("AI 阶段           : %s" % by_name["ai"]["status"])
    print("深度 Java         : %s%s" % (
        by_name["deep_java"]["status"],
        ("（%s）" % by_name["deep_java"]["reason"])
        if by_name["deep_java"]["reason"] else ""))
    print("结果输出          : %s" % assessed)
    print("任务状态          : %s" % task_path)
    return 1 if args.ai and by_name["ai"]["status"] != "completed" else 0


if __name__ == "__main__":
    sys.exit(main())
