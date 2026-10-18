"""Exercise a running Compose Web service with a public project example.

The test uploads one repository-owned source file, runs the real external
CryptoScan/cbom-scan pipeline, checks its assessed result, and removes the task.
It does not enable the cloud AI service or print source/evidence contents.
"""

import argparse
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "examples" / "repair_demo" / "app.py"


def request(base, path, method="GET", body=None, content_type=None):
    headers = {"Content-Type": content_type} if content_type else {}
    req = urllib.request.Request(base + path, data=body, method=method,
                                 headers=headers)
    with urllib.request.urlopen(req, timeout=15) as response:
        raw = response.read()
        return response.status, json.loads(raw) if raw else None


def main():
    ap = argparse.ArgumentParser(description="容器 Web 快速扫描端到端验收")
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--timeout", type=int, default=90)
    args = ap.parse_args()
    base = args.base.rstrip("/")
    task_id = None
    try:
        with urllib.request.urlopen(base + "/web/index.html", timeout=15) as page:
            assert page.status == 200 and b"AI-CryptoGuard" in page.read()
        payload = SAMPLE.read_bytes()
        _, task = request(base, "/api/tasks", "POST", json.dumps({
            "name": "compose-smoke", "file_count": 1,
            "total_bytes": len(payload), "ai_enabled": False,
        }).encode("utf-8"), "application/json")
        task_id = task["task_id"]
        status, _ = request(base, "/api/tasks/%s/files?path=%s" % (
            task_id, urllib.parse.quote("app.py")), "POST", payload,
            "application/octet-stream")
        assert status == 201
        request(base, "/api/tasks/%s/start" % task_id, "POST")
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            _, snapshot = request(base, "/api/tasks/" + task_id)
            if snapshot["state"] in ("completed", "failed"):
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("扫描任务未在 %d 秒内结束" % args.timeout)
        if snapshot["state"] != "completed":
            raise RuntimeError("扫描失败：%s" % snapshot.get("message"))
        stages = {s["name"]: s["status"] for s in snapshot["pipeline"]["stages"]}
        assert stages["scan"] == "completed", stages
        assert stages["quantum_assessment"] == "completed", stages
        assert stages["ai"] == "skipped", stages
        _, rows = request(base, "/api/tasks/%s/result" % task_id)
        assert isinstance(rows, list) and rows, "真实扫描未返回 Finding"
        assert len(rows) == snapshot["findings_count"]
        assert all("quantum_assessment" in row for row in rows)
        assert all("raw" not in evidence for row in rows
                   for evidence in row.get("evidence", []))
        print("[PASS] Compose Web 真实扫描：%d 条 Finding；scan/quantum 完成，AI 跳过。"
              % len(rows))
        return 0
    finally:
        if task_id:
            request(base, "/api/tasks/" + task_id, "DELETE")
            try:
                request(base, "/api/tasks/" + task_id)
            except urllib.error.HTTPError as exc:
                if exc.code != 404:
                    raise
                print("[PASS] 临时上传任务已删除。")
            else:
                raise AssertionError("临时上传任务仍可读取")


if __name__ == "__main__":
    raise SystemExit(main())
