"""Offline product regression: overview privacy, retry isolation and concurrency."""
import json
import os
import sys
import tempfile
import threading
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from web import serve
from core.project_overview import build_overview
from core.schema.validate_v02 import errors as contract_errors
from web.server_selftest import request


def main():
    row = {'finding_id': 'f1', 'severity': 'high', 'file': 'src/a.java', 'line': 8,
           'algorithm': 'RSA', 'usage': 'signing', 'stage': 'explained',
           'evidence': [{'raw': {'secret': 'NEVER-DISPLAY'}, 'lines': [8]}],
           'remediation': {'action': '规则建议'},
           'remediation_steps': [{'action': '错误引用不显示', 'evidence_refs': ['E9']},
                                 {'action': '先核查签名接口', 'evidence_refs': ['E1']}]}
    cred = dict(row, finding_id='f2', finding_kind='credential',
                explanation='NEVER-DISPLAY', remediation={'action': 'NEVER-DISPLAY'})
    unknown = dict(row, finding_id='f3', usage='unknown')
    overview = build_overview([unknown, cred, row])
    assert overview['counts']['usage_unknown'] == 1
    assert len(overview['actions']) == 3
    text = json.dumps(overview, ensure_ascii=False)
    assert 'NEVER-DISPLAY' not in text and '错误引用不显示' not in text
    assert '先核查签名接口' in text
    assert all(a['evidence_refs'] == ['E1'] for a in overview['actions'])
    assert '不代表已验证漏洞或已经完成整改' in overview['basis']
    assert build_overview([])['counts']['findings'] == 0

    with tempfile.TemporaryDirectory(prefix='acg-product-') as temp, \
            patch.object(serve, 'TASK_BASE', Path(temp)), \
            patch.object(serve, 'TASKS', {}), \
            patch.dict(os.environ, {'ANTHROPIC_AUTH_TOKEN': 'offline-test-only',
                                    'ANTHROPIC_MODEL': 'offline-test-only'}):
        task = serve._new_task({'ai_enabled': True, 'ai_context': 'shape'})
        tid = task['task_id']
        out = serve._task_dir(tid) / 'out'
        out.mkdir()
        pipeline = json.loads((ROOT / 'core/samples/v0.2/task.json').read_text(encoding='utf-8'))
        for stage in pipeline['stages']:
            stage['status'] = 'failed' if stage['name'] == 'ai' else 'completed'
        assessed = out / 'findings_assessed.json'
        assessed.write_text(json.dumps([row]), encoding='utf-8')
        before = assessed.read_bytes()
        (out / 'task.json').write_text(json.dumps(pipeline), encoding='utf-8')
        (out / 'findings_explained.json.failures.json').write_text(json.dumps([
            {'category': 'APIConnectionError', 'error': 'NEVER-DISPLAY'},
            {'category': 'NEVER-DISPLAY', 'error': 'NEVER-DISPLAY'}]), encoding='utf-8')
        serve._set_task(tid, state='completed')
        snapshot = serve._snapshot(tid)
        assert snapshot['ai_feedback']['retry_available']
        assert '连接失败' in snapshot['ai_feedback']['message']
        assert 'NEVER-DISPLAY' not in json.dumps(snapshot)
        with patch.object(serve.threading, 'Thread') as thread:
            serve._queue_ai_retry(tid)
            assert thread.call_count == 1
            try:
                serve._queue_ai_retry(tid)
                raise AssertionError('duplicate retry accepted')
            except ValueError:
                pass
            try:
                serve._remove_task(tid)
                raise AssertionError('running task deleted')
            except ValueError:
                pass

        def fake_run(cmd, **kwargs):
            assert cmd[1].endswith('enrich_v02.py') and '--resume' in cmd
            assert cmd[cmd.index('--context') + 1] == 'shape'
            assert 'pipeline.py' not in ' '.join(cmd)
            (out / 'findings_explained.json').write_text(json.dumps([row]), encoding='utf-8')
            return SimpleNamespace(returncode=0)

        with patch.object(serve.subprocess, 'run', fake_run):
            serve._run_ai_retry_safe(tid)
        after = json.loads((out / 'task.json').read_text(encoding='utf-8'))
        assert not contract_errors(after)
        assert after['stages'][:3] == pipeline['stages'][:3]
        assert assessed.read_bytes() == before
        assert after['stages'][3]['status'] == 'completed'
        assert not serve._snapshot(tid)['ai_feedback']['retry_available']

        # Failed attempts preserve scan results and are visibly retryable.
        with patch.object(serve.subprocess, 'run', side_effect=OSError('NEVER-DISPLAY')):
            serve._run_ai_retry_safe(tid)
        assert assessed.read_bytes() == before
        assert serve._snapshot(tid)['ai_feedback']['retry_available']
        assert 'NEVER-DISPLAY' not in (out / 'task.json').read_text(encoding='utf-8')

        entered, release = threading.Event(), threading.Event()
        def held_run(cmd, **kwargs):
            entered.set()
            assert release.wait(5)
            return fake_run(cmd, **kwargs)
        server = serve.Server(('127.0.0.1', 0), serve.Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = 'http://127.0.0.1:%d' % server.server_address[1]
        try:
            with patch.object(serve.subprocess, 'run', held_run):
                status, _ = request(base, '/api/tasks/%s/retry-ai' % tid, 'POST')
                assert status == 202 and entered.wait(3)
                try:
                    request(base, '/api/tasks/%s/retry-ai' % tid, 'POST')
                    raise AssertionError('HTTP duplicate accepted')
                except urllib.error.HTTPError as exc:
                    assert exc.code == 400
                status, summary = request(base, '/api/tasks/%s/summary' % tid)
                assert status == 200 and summary['actions'][0]['finding_id'] == 'f1'
                release.set()
                for _ in range(50):
                    _, current = request(base, '/api/tasks/' + tid)
                    if current['state'] == 'completed':
                        break
                    threading.Event().wait(.05)
                assert current['state'] == 'completed'
                assert assessed.read_bytes() == before
        finally:
            release.set()
            server.shutdown()
            server.server_close()
    print('PASS: overview evidence/privacy; AI-only retry, stage preservation, duplicate guard')


if __name__ == '__main__':
    main()
