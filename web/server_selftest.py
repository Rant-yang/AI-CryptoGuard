"""本地 Web API 自检：创建任务、上传、拒绝越界路径、清理。"""
import json
import io
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from web import serve


def request(base, path, method="GET", body=None, content_type="application/json"):
    req = urllib.request.Request(base + path, data=body, method=method,
                                 headers={"Content-Type": content_type})
    with urllib.request.urlopen(req, timeout=5) as response:
        raw = response.read()
        return response.status, json.loads(raw) if raw else None


def main():
    original = serve.TASK_BASE
    old_home = os.environ.get("ACG_CRYSENTRY_HOME")
    old_java = os.environ.get("ACG_CRYSENTRY_JAVA")
    with tempfile.TemporaryDirectory(prefix="acg-web-api-") as temp:
        serve.TASK_BASE = Path(temp)
        serve.TASKS.clear()
        server = serve.Server(("127.0.0.1", 0), serve.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = "http://127.0.0.1:%d" % server.server_address[1]
        try:
            _, task = request(base, "/api/tasks", "POST",
                              json.dumps({"name": "demo", "file_count": 1,
                                          "ai_enabled": True, "ai_context": "shape",
                                          "total_bytes": 12,
                                          "quantum_timeline_profile": {
                                              "data_lifetime_years": 10,
                                              "migration_lead_years": 3,
                                              "threat_horizon_years": 8,
                                              "hndl_exposure": "yes",
                                          }}).encode("utf-8"))
            task_id = task["task_id"]
            assert task["quantum_timeline_profile"]["data_lifetime_years"] == 10
            assert task["ai_enabled"] and task["ai_context"] == "shape"
            path = urllib.parse.quote("demo/src/a.py", safe="")
            status, _ = request(base, "/api/tasks/%s/files?path=%s" % (task_id, path),
                                "POST", b"print('ok')\n", "application/octet-stream")
            assert status == 201
            _, snapshot = request(base, "/api/tasks/" + task_id)
            assert snapshot["uploaded_files"] == 1
            with urllib.request.urlopen(base + "/web/index.html", timeout=5) as page:
                assert page.status == 200 and b"AI-CryptoGuard" in page.read()
            for allowed in ("/web/semantic_review.html", "/web/semantic_review.js"):
                with urllib.request.urlopen(base + allowed, timeout=5) as page:
                    assert page.status == 200 and b"review" in page.read().lower()
            for forbidden in ("/README.md", "/out/run/findings.json",
                              "/workspace/web_tasks", "/.env",
                              "/web/semantic_review_selftest.js"):
                try:
                    urllib.request.urlopen(base + forbidden, timeout=5)
                    raise AssertionError("static file exposed: " + forbidden)
                except urllib.error.HTTPError as exc:
                    assert exc.code == 404
            test_out = serve._task_dir(task_id) / "out"
            test_out.mkdir()
            (test_out / "findings_assessed.json").write_text(json.dumps([{
                "finding_kind": "credential", "evidence": [{
                    "tool": "credential-scan", "kind": "pattern", "lines": [1],
                    "raw": {"secret": "LEAK-ME-SECRET"},
                    "call_context": ["LEAK-ME-CONTEXT"]}]}]), encoding="utf-8")
            _, safe = request(base, "/api/tasks/%s/result" % task_id)
            assert "LEAK-ME" not in json.dumps(safe)
            with urllib.request.urlopen(base + "/api/tasks/%s/report" % task_id, timeout=5) as page:
                report = page.read().decode("utf-8")
                assert page.status == 200
                assert page.headers.get("Content-Type") == "text/html; charset=utf-8"
                assert "attachment" in page.headers.get("Content-Disposition", "")
                assert "AI-CryptoGuard 审计报告" in report
                assert "LEAK-ME" not in report
            uploaded = serve._task_dir(task_id) / "input" / "demo" / "src" / "a.py"
            assert uploaded.read_bytes() == b"print('ok')\n"

            # Deep mode must carry the uploaded bytecode and external engine
            # configuration into the actual pipeline command. No build runs.
            fake_home = Path(temp) / "external-engine"
            fake_home.mkdir()
            fake_java = Path(temp) / "jdk17-java.exe"
            fake_java.write_bytes(b"test-only")
            os.environ["ACG_CRYSENTRY_HOME"] = str(fake_home)
            os.environ["ACG_CRYSENTRY_JAVA"] = str(fake_java)
            _, deep_task = request(base, "/api/tasks", "POST",
                                   json.dumps({"name": "java-demo", "file_count": 1,
                                               "total_bytes": 24,
                                               "scan_mode": "deep-java"}).encode("utf-8"))
            deep_id = deep_task["task_id"]
            assert deep_task["scan_mode"] == "deep-java"
            src = urllib.parse.quote("demo/src/Demo.java", safe="")
            request(base, "/api/tasks/%s/files?path=%s" % (deep_id, src),
                    "POST", b"class Demo {}", "application/octet-stream")
            try:
                request(base, "/api/tasks/%s/start" % deep_id, "POST", b"")
                raise AssertionError("deep task started without jar")
            except urllib.error.HTTPError as exc:
                assert exc.code == 400
            try:
                request(base, "/api/tasks/%s/artifact" % deep_id,
                        "POST", b"not-a-jar", "application/java-archive")
                raise AssertionError("invalid jar accepted")
            except urllib.error.HTTPError as exc:
                assert exc.code == 400
            jar = io.BytesIO()
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("Demo.class", b"test-only")
            status, _ = request(base, "/api/tasks/%s/artifact" % deep_id,
                                "POST", jar.getvalue(), "application/java-archive")
            assert status == 201
            cmd = serve._pipeline_command(deep_id)
            assert cmd[cmd.index("--mode") + 1] == "deep-java"
            assert cmd[cmd.index("--java-artifact") + 1] == str(
                serve._task_dir(deep_id) / "artifact" / "target.jar")
            assert cmd[cmd.index("--crysentry-home") + 1] == str(fake_home)
            assert cmd[cmd.index("--crysentry-java") + 1] == str(fake_java)
            assert "--mode" not in serve._pipeline_command(task_id)
            serve._remove_task(deep_id)

            # An unexpected worker failure must not leave the UI polling forever.
            failed = serve._new_task({"name": "worker-failure"})
            original_worker = serve._run_task
            try:
                def boom(_task_id):
                    raise RuntimeError("do not expose this text")
                serve._run_task = boom
                serve._run_task_safe(failed["task_id"])
                state = serve._snapshot(failed["task_id"])
                assert state["state"] == "failed"
                assert "do not expose" not in state["message"]
            finally:
                serve._run_task = original_worker
                serve._remove_task(failed["task_id"])
            try:
                request(base, "/api/tasks/%s/files?path=%s" % (task_id, path),
                        "POST", b"overwrite", "application/octet-stream")
                raise AssertionError("duplicate path accepted")
            except urllib.error.HTTPError as exc:
                assert exc.code == 400
            _, snapshot = request(base, "/api/tasks/" + task_id)
            assert snapshot["uploaded_files"] == 1
            assert uploaded.read_bytes() == b"print('ok')\n"
            try:
                bad = urllib.parse.quote("../escape.py", safe="")
                request(base, "/api/tasks/%s/files?path=%s" % (task_id, bad),
                        "POST", b"bad", "application/octet-stream")
                raise AssertionError("path traversal accepted")
            except urllib.error.HTTPError as exc:
                assert exc.code == 400
            status, _ = request(base, "/api/tasks/" + task_id, "DELETE")
            assert status == 204
            assert not serve._task_dir(task_id).exists()

            if "--integration" in sys.argv:
                live = serve._new_task({"name": "integration", "file_count": 1,
                                        "total_bytes": 56,
                                        "quantum_timeline_profile": {
                                            "data_lifetime_years": 10,
                                            "migration_lead_years": 3,
                                            "threat_horizon_years": 8,
                                            "hndl_exposure": "yes",
                                        }})
                live_id = live["task_id"]
                sample = serve._task_dir(live_id) / "input" / "demo.py"
                sample.write_text("import hashlib\nprint(hashlib.md5(b'demo').hexdigest())\n",
                                  encoding="utf-8")
                serve._set_task(live_id, uploaded_files=1, uploaded_bytes=sample.stat().st_size,
                                state="queued")
                serve._run_task(live_id)
                completed = serve._snapshot(live_id)
                assert completed["state"] == "completed", completed
                assert completed["findings_count"] is not None
                assert (serve._task_dir(live_id) / "out" /
                        "findings_assessed.json").is_file()
                rows = json.loads((serve._task_dir(live_id) / "out" /
                                   "findings_assessed.json").read_text(encoding="utf-8"))
                assert rows
                assert all(row["quantum_assessment"]["quantum_timeline"]
                           ["data_lifetime_years"] == 10 for row in rows)
                serve._remove_task(live_id)

            if "--deep-integration" in sys.argv:
                assert old_home and old_java, (
                    "设置 ACG_CRYSENTRY_HOME 与 ACG_CRYSENTRY_JAVA 后再跑 --deep-integration")
                os.environ["ACG_CRYSENTRY_HOME"] = old_home
                os.environ["ACG_CRYSENTRY_JAVA"] = old_java
                source = ROOT / "examples" / "java_deep_demo" / "Demo.java"
                classes = Path(temp) / "compiled"
                classes.mkdir()
                javac = Path(old_java).with_name("javac.exe")
                subprocess.run([str(javac), "-g", "-d", str(classes), str(source)],
                               check=True, timeout=30)
                jar_buffer = io.BytesIO()
                with zipfile.ZipFile(jar_buffer, "w") as archive:
                    archive.write(classes / "Demo.class", "Demo.class")
                source_bytes = source.read_bytes()
                _, live = request(base, "/api/tasks", "POST", json.dumps({
                    "name": "java-deep-demo", "file_count": 1,
                    "total_bytes": len(source_bytes), "scan_mode": "deep-java",
                }).encode("utf-8"))
                live_id = live["task_id"]
                path = urllib.parse.quote("java_deep_demo/Demo.java", safe="")
                request(base, "/api/tasks/%s/files?path=%s" % (live_id, path),
                        "POST", source_bytes, "application/octet-stream")
                request(base, "/api/tasks/%s/artifact" % live_id,
                        "POST", jar_buffer.getvalue(), "application/java-archive")
                request(base, "/api/tasks/%s/start" % live_id, "POST", b"")
                deadline = time.monotonic() + 150
                while time.monotonic() < deadline:
                    _, live = request(base, "/api/tasks/" + live_id)
                    if live["state"] in ("completed", "failed"):
                        break
                    time.sleep(0.5)
                assert live["state"] == "completed", live
                stages = {stage["name"]: stage["status"]
                          for stage in live["pipeline"]["stages"]}
                assert stages["deep_java"] == "completed", stages
                _, rows = request(base, "/api/tasks/%s/result" % live_id)
                assert any(e["tool"] == "crysentry" and e["kind"] == "taint"
                           for row in rows for e in row["evidence"]), rows
                serve._remove_task(live_id)
        finally:
            server.shutdown()
            server.server_close()
            serve.TASK_BASE = original
            for key, previous in (("ACG_CRYSENTRY_HOME", old_home),
                                  ("ACG_CRYSENTRY_JAVA", old_java)):
                if previous is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = previous
    print("PASS: local web task API%s%s" %
          (" + real scanner integration" if "--integration" in sys.argv else "",
           " + real CrySentry integration" if "--deep-integration" in sys.argv else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
