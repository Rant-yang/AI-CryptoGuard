"""AI-CryptoGuard 本地 Web 入口：静态页面 + 项目上传 + 扫描任务 API。

仅监听 127.0.0.1。拖入的项目写入 workspace/web_tasks/<task_id>/，
不会上传到互联网；流水线默认不保留第三方工具原始输出。
"""
import hashlib
import http.server
import json
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.parse
import webbrowser
import zipfile
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.quantum_timeline import make_profile  # noqa: E402
from ai.redact import scrub  # noqa: E402
from core.report import render_report  # noqa: E402

TASK_BASE = ROOT / "workspace" / "web_tasks"
PORT = int(os.environ.get("ACG_WEB_PORT", "8000"))
HOST = os.environ.get("ACG_WEB_HOST", "127.0.0.1")
TOOLS_DIR = Path(os.environ.get("ACG_TOOLS_DIR", str(ROOT.parent / "_smoke")))
MAX_FILES = 4000
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TASK_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
TASK_TTL_SECONDS = 24 * 60 * 60
TASKS = {}
LOCK = threading.Lock()


def _json_bytes(data):
    return (json.dumps(data, ensure_ascii=False) + "\n").encode("utf-8")


def _safe_result_rows(rows):
    """Browser/report view must never receive upstream raw scanner records."""
    safe_rows = []
    for finding in rows:
        clean = json.loads(json.dumps(finding))
        for evidence in clean.get("evidence", []):
            evidence.pop("raw", None)
            if clean.get("finding_kind") == "credential":
                evidence.pop("call_context", None)
                evidence.pop("call_shape", None)
            elif "call_context" in evidence:
                evidence["call_context"] = scrub(evidence["call_context"])
        safe_rows.append(clean)
    return safe_rows


def _safe_relative(raw):
    value = urllib.parse.unquote(raw or "").replace("\\", "/")
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or ".." in path.parts or
            any(":" in part or part in ("", ".") for part in path.parts)):
        raise ValueError("非法相对路径")
    return Path(*path.parts)


def _task_dir(task_id):
    if not task_id.startswith("web-") or not task_id[4:].isalnum():
        raise ValueError("非法任务编号")
    path = (TASK_BASE / task_id).resolve()
    path.relative_to(TASK_BASE.resolve())
    return path


def _remove_task(task_id):
    path = _task_dir(task_id)
    if path.exists():
        shutil.rmtree(path)
    with LOCK:
        TASKS.pop(task_id, None)


def _cleanup_expired():
    TASK_BASE.mkdir(parents=True, exist_ok=True)
    now = time.time()
    for child in TASK_BASE.iterdir():
        if not child.is_dir() or not child.name.startswith("web-"):
            continue
        try:
            if now - child.stat().st_mtime > TASK_TTL_SECONDS:
                _remove_task(child.name)
        except (OSError, ValueError):
            continue


def _new_task(meta):
    scan_mode = meta.get("scan_mode", "fast")
    if scan_mode not in ("fast", "deep-java"):
        raise ValueError("未知扫描模式")
    if scan_mode == "deep-java":
        home = os.environ.get("ACG_CRYSENTRY_HOME")
        java = os.environ.get("ACG_CRYSENTRY_JAVA")
        if not home or not Path(home).is_dir():
            raise ValueError("Java 深扫需先配置有效的 ACG_CRYSENTRY_HOME。")
        if not java or not Path(java).is_file():
            raise ValueError("Java 深扫需先配置 JDK 17 的 ACG_CRYSENTRY_JAVA。")
    salt = "%s|%s|%s" % (time.time_ns(), meta.get("name", "project"), os.getpid())
    task_id = "web-" + hashlib.sha256(salt.encode("utf-8")).hexdigest()[:16]
    task_dir = _task_dir(task_id)
    (task_dir / "input").mkdir(parents=True)
    raw_timeline = meta.get("quantum_timeline_profile") or {}
    timeline_profile = make_profile(
        raw_timeline.get("data_lifetime_years"),
        raw_timeline.get("migration_lead_years"),
        raw_timeline.get("threat_horizon_years"),
        raw_timeline.get("hndl_exposure", "unknown"),
        "user-input" if raw_timeline else "not-provided")
    task = {
        "task_id": task_id,
        "name": str(meta.get("name") or "project")[:100],
        "state": "uploading",
        "message": "正在接收项目文件",
        "uploaded_files": 0,
        "uploaded_bytes": 0,
        "expected_files": min(int(meta.get("file_count") or 0), MAX_FILES),
        "expected_bytes": min(int(meta.get("total_bytes") or 0), MAX_TASK_BYTES),
        "created_at": time.time(),
        "return_code": None,
        "findings_count": None,
        "quantum_timeline_profile": timeline_profile,
        "ai_enabled": meta.get("ai_enabled") is True,
        "scan_mode": scan_mode,
        "artifact_uploaded": False,
        "ai_context": (meta.get("ai_context") if meta.get("ai_context") in
                       ("full", "shape") else "full"),
    }
    with LOCK:
        TASKS[task_id] = task
    return task


def _snapshot(task_id):
    with LOCK:
        task = dict(TASKS.get(task_id) or {})
    if not task:
        raise KeyError(task_id)
    task_json = _task_dir(task_id) / "out" / "task.json"
    if task_json.is_file():
        try:
            task["pipeline"] = json.loads(task_json.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            task["pipeline"] = None
    return task


def _set_task(task_id, **values):
    with LOCK:
        if task_id in TASKS:
            TASKS[task_id].update(values)


def _pipeline_command(task_id):
    task_dir = _task_dir(task_id)
    input_dir = task_dir / "input"
    output_dir = task_dir / "out"
    cmd = [sys.executable, str(ROOT / "core" / "pipeline.py"), str(input_dir),
           "--tools-dir", str(TOOLS_DIR), "-o", str(output_dir)]
    task = _snapshot(task_id)
    if task["scan_mode"] == "deep-java":
        cmd += ["--mode", "deep-java",
                "--java-artifact", str(task_dir / "artifact" / "target.jar"),
                "--crysentry-home", os.environ["ACG_CRYSENTRY_HOME"],
                "--crysentry-java", os.environ["ACG_CRYSENTRY_JAVA"]]
    if _snapshot(task_id).get("ai_enabled"):
        cmd += ["--ai", "--ai-context", _snapshot(task_id)["ai_context"]]
    profile = _snapshot(task_id).get("quantum_timeline_profile") or {}
    if profile.get("data_lifetime_years") is not None:
        cmd += ["--data-lifetime-years", str(profile["data_lifetime_years"]),
                "--migration-lead-years", str(profile["migration_lead_years"]),
                "--threat-horizon-years", str(profile["threat_horizon_years"]),
                "--hndl-exposure", profile["hndl_exposure"]]
    return cmd


def _run_task(task_id):
    task_dir = _task_dir(task_id)
    task = _snapshot(task_id)
    output_dir = task_dir / "out"
    log_path = task_dir / "pipeline.log"
    if not TOOLS_DIR.is_dir():
        _set_task(task_id, state="failed",
                  message="找不到第三方工具目录，请设置 ACG_TOOLS_DIR。")
        return
    _set_task(task_id, state="running", message="正在执行密码资产扫描")
    cmd = _pipeline_command(task_id)
    try:
        with log_path.open("wb") as log:
            proc = subprocess.run(cmd, cwd=str(ROOT), stdout=log,
                                  stderr=subprocess.STDOUT,
                                  timeout=1800 if _snapshot(task_id)["scan_mode"] == "deep-java" else 900)
    except subprocess.TimeoutExpired:
        _set_task(task_id, state="failed", message="扫描超过 15 分钟，任务已终止。")
        return
    except OSError:
        _set_task(task_id, state="failed", message="无法启动本地扫描进程。")
        return
    result = output_dir / "findings_assessed.json"
    if not result.is_file():
        _set_task(task_id, state="failed", return_code=proc.returncode,
                  message="扫描未完成，请查看本机任务日志。")
        return
    try:
        pipeline = json.loads((output_dir / "task.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        _set_task(task_id, state="failed", return_code=proc.returncode,
                  message="任务状态文件无法解析，请查看本机日志。")
        return
    scan_status = {s["name"]: s["status"] for s in pipeline["stages"]}
    if scan_status.get("scan") == "failed" or scan_status.get("quantum_assessment") != "completed":
        _set_task(task_id, state="failed", return_code=proc.returncode,
                  message="扫描或规则评估失败；请查看本机任务日志。")
        return
    chosen = (output_dir / "findings_explained.json")
    if not chosen.is_file():
        chosen = result
    try:
        rows = json.loads(chosen.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        _set_task(task_id, state="failed", message="扫描结果无法解析。")
        return
    ai_failed = _snapshot(task_id).get("ai_enabled") and scan_status.get("ai") != "completed"
    deep = next((s for s in pipeline["stages"] if s["name"] == "deep_java"), {})
    deep_label = {"failed": "失败", "skipped": "跳过", "timeout": "超时"}.get(
        deep.get("status"), "未完成")
    deep_warning = (
        "；Java 深扫%s：%s" %
        (deep_label, deep.get("reason") or "请检查任务状态")
        if task["scan_mode"] == "deep-java" and deep.get("status") != "completed"
        else "")
    scan_reason = next((s.get("reason") for s in pipeline["stages"]
                        if s.get("name") == "scan"), None)
    partial_warning = ("；注意：" + scan_reason) if scan_reason else ""
    _set_task(task_id, state="completed", return_code=proc.returncode,
              findings_count=len(rows),
              message=(("本地扫描完成；AI 解释未完成，请查看任务阶段状态。"
                        if ai_failed else "扫描完成，正在生成风险视图") +
                       partial_warning + deep_warning))


def _run_task_safe(task_id):
    """A worker error must terminate the visible task, never leave it running."""
    try:
        _run_task(task_id)
    except Exception as exc:
        # Do not copy exception text into the browser: it can contain paths or
        # scanner-provided material. Keep only the exception class locally.
        sys.stderr.write("本地扫描任务内部错误: %s\n" % type(exc).__name__)
        _set_task(task_id, state="failed", message="本地扫描任务发生内部错误；请查看本机终端。")


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def translate_path(self, path):
        """Static serving is limited to the UI; never expose workspace, out or .env."""
        route = urllib.parse.urlparse(path).path
        if route in ("/", "/web/index.html"):
            return str(HERE / "index.html")
        if route == "/web/semantic_review.html":
            return str(HERE / "semantic_review.html")
        if route == "/web/semantic_review.js":
            return str(HERE / "semantic_review.js")
        return str(HERE / "__not_found__")

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def log_message(self, fmt, *args):
        if args and str(args[1]) not in ("200", "201", "204"):
            sys.stderr.write("  %s\n" % (fmt % args))

    def _send_json(self, status, data):
        body = _json_bytes(data)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self, limit=1024 * 1024):
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > limit:
            raise ValueError("请求体过大")
        return self.rfile.read(length)

    def _api_parts(self):
        parsed = urllib.parse.urlparse(self.path)
        return parsed, parsed.path.strip("/").split("/")

    def do_POST(self):
        parsed, parts = self._api_parts()
        try:
            if parsed.path == "/api/tasks":
                meta = json.loads(self._body().decode("utf-8"))
                if int(meta.get("file_count") or 0) > MAX_FILES:
                    raise ValueError("文件数量超过上限")
                if int(meta.get("total_bytes") or 0) > MAX_TASK_BYTES:
                    raise ValueError("项目大小超过上限")
                task = _new_task(meta)
                return self._send_json(201, _snapshot(task["task_id"]))
            if len(parts) == 4 and parts[:2] == ["api", "tasks"] and parts[3] == "files":
                task_id = parts[2]
                rel = _safe_relative(urllib.parse.parse_qs(parsed.query).get("path", [""])[0])
                body = self._body(MAX_FILE_BYTES)
                base = (_task_dir(task_id) / "input").resolve()
                target = (base / rel).resolve()
                target.relative_to(base)
                with LOCK:
                    task = TASKS.get(task_id)
                    if not task or task["state"] != "uploading":
                        raise ValueError("任务不在上传阶段")
                    if target.exists():
                        raise ValueError("文件路径重复")
                    if task["uploaded_files"] >= MAX_FILES:
                        raise ValueError("文件数量超过上限")
                    if task["uploaded_bytes"] + len(body) > MAX_TASK_BYTES:
                        raise ValueError("项目大小超过上限")
                    # 浏览器并行上传时，检查、落盘和计数必须处于同一临界区。
                    # ``xb`` 还保证同一路径不会被另一个请求覆盖。
                    try:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with target.open("xb") as handle:
                            handle.write(body)
                    except FileExistsError:
                        raise ValueError("文件路径重复")
                    except OSError:
                        raise ValueError("文件写入失败")
                    task["uploaded_files"] += 1
                    task["uploaded_bytes"] += len(body)
                return self._send_json(201, {"ok": True})
            if len(parts) == 4 and parts[:2] == ["api", "tasks"] and parts[3] == "artifact":
                task_id = parts[2]
                body = self._body(MAX_ARTIFACT_BYTES)
                if not body.startswith(b"PK\x03\x04"):
                    raise ValueError("编译产物必须是有效的 Java jar。")
                with LOCK:
                    task = TASKS.get(task_id)
                    if not task or task["state"] != "uploading" or task["scan_mode"] != "deep-java":
                        raise ValueError("当前任务不接受 Java 编译产物")
                    if task["artifact_uploaded"]:
                        raise ValueError("编译产物已上传")
                    target = _task_dir(task_id) / "artifact" / "target.jar"
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open("xb") as handle:
                        handle.write(body)
                    if not zipfile.is_zipfile(target):
                        target.unlink()
                        raise ValueError("编译产物不是有效的 jar/ZIP 结构")
                    task["artifact_uploaded"] = True
                return self._send_json(201, {"ok": True})
            if len(parts) == 4 and parts[:2] == ["api", "tasks"] and parts[3] == "start":
                task_id = parts[2]
                with LOCK:
                    task = TASKS.get(task_id)
                    if not task or task["state"] != "uploading" or task["uploaded_files"] < 1:
                        raise ValueError("没有可扫描的文件")
                    if task["scan_mode"] == "deep-java" and not task["artifact_uploaded"]:
                        raise ValueError("Java 深扫尚未上传编译后的 jar")
                    task["state"] = "queued"
                    task["message"] = "项目已接收，准备扫描"
                threading.Thread(target=_run_task_safe, args=(task_id,), daemon=True).start()
                return self._send_json(202, _snapshot(task_id))
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            return self._send_json(400, {"error": str(exc)})
        return self._send_json(404, {"error": "not found"})

    def do_GET(self):
        parsed, parts = self._api_parts()
        try:
            if len(parts) == 3 and parts[:2] == ["api", "tasks"]:
                return self._send_json(200, _snapshot(parts[2]))
            if len(parts) == 4 and parts[:2] == ["api", "tasks"] and parts[3] in ("result", "report"):
                out = _task_dir(parts[2]) / "out"
                result = out / "findings_explained.json"
                if not result.is_file():
                    result = out / "findings_assessed.json"
                if not result.is_file():
                    return self._send_json(409, {"error": "result not ready"})
                rows = json.loads(result.read_text(encoding="utf-8-sig"))
                safe_rows = _safe_result_rows(rows)
                if parts[3] == "report":
                    task_file = out / "task.json"
                    task = json.loads(task_file.read_text(encoding="utf-8-sig")) if task_file.is_file() else None
                    body = render_report(safe_rows, task).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Disposition", 'attachment; filename="AI-CryptoGuard-report.html"')
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                body = _json_bytes(safe_rows)
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
        except (ValueError, KeyError):
            return self._send_json(404, {"error": "task not found"})
        return super().do_GET()

    def do_DELETE(self):
        _, parts = self._api_parts()
        if len(parts) == 3 and parts[:2] == ["api", "tasks"]:
            try:
                _remove_task(parts[2])
                self.send_response(204)
                self.end_headers()
                return
            except ValueError:
                pass
        self._send_json(404, {"error": "task not found"})


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def port_busy(port):
    with socket.socket() as sock:
        return sock.connect_ex(("127.0.0.1", port)) == 0


def main():
    if HOST not in ("127.0.0.1", "0.0.0.0"):
        raise ValueError("ACG_WEB_HOST 只接受 127.0.0.1 或 0.0.0.0。")
    _cleanup_expired()
    port = PORT
    while port_busy(port):
        if os.environ.get("ACG_WEB_STRICT_PORT") == "1":
            raise OSError("端口 %d 被占用；容器模式不自动换端口。" % port)
        print("[!] 端口 %d 被占用，试 %d" % (port, port + 1))
        port += 1
    url = "http://127.0.0.1:%d/web/index.html" % port
    with Server((HOST, port), Handler) as httpd:
        print("AI-CryptoGuard 本地审计入口")
        print("  地址     : %s" % url)
        print("  工具目录 : %s" % TOOLS_DIR)
        print("  临时任务 : %s（24 小时后自动清理）" % TASK_BASE)
        print("  停止     : Ctrl+C")
        if os.environ.get("ACG_NO_BROWSER") != "1":
            threading.Timer(0.6, lambda: webbrowser.open(url)).start()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n已停止。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
