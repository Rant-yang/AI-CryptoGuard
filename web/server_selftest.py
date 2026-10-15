"""本地 Web API 自检：创建任务、上传、拒绝越界路径、清理。"""
import json
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
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
                                          "total_bytes": 12}).encode("utf-8"))
            task_id = task["task_id"]
            path = urllib.parse.quote("demo/src/a.py", safe="")
            status, _ = request(base, "/api/tasks/%s/files?path=%s" % (task_id, path),
                                "POST", b"print('ok')\n", "application/octet-stream")
            assert status == 201
            _, snapshot = request(base, "/api/tasks/" + task_id)
            assert snapshot["uploaded_files"] == 1
            uploaded = serve._task_dir(task_id) / "input" / "demo" / "src" / "a.py"
            assert uploaded.read_bytes() == b"print('ok')\n"
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
                                        "total_bytes": 56})
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
                serve._remove_task(live_id)
        finally:
            server.shutdown()
            server.server_close()
            serve.TASK_BASE = original
    print("PASS: local web task API%s" %
          (" + real scanner integration" if "--integration" in sys.argv else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
