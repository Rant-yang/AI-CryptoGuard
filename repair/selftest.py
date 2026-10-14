"""Repair -> Verify 的安全合成自检。"""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from repair.engine import RULES, repair_and_verify  # noqa: E402


SYNTHETIC_SECRET = 'SyntheticOnly_DoNotUse_123!'
SOURCE = '''import hashlib
import random

password = "%s"
digest = hashlib.md5(b"demo").hexdigest()
nonce = random.Random().randbytes(12)
''' % SYNTHETIC_SECRET


def main():
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, 'demo.py')
        out = os.path.join(td, 'report.json')
        with open(src, 'w', encoding='utf-8') as fh:
            fh.write(SOURCE)
        before = open(src, encoding='utf-8').read()
        report = repair_and_verify(src, out)
        after_original = open(src, encoding='utf-8').read()
        saved = open(out, encoding='utf-8').read()

    assert before == after_original
    assert report['original_unchanged'] is True
    assert report['syntax'] == 'PASS'
    assert {r['rule_id'] for r in report['repairs']} == set(RULES)
    assert all(r['original_finding'] == 'PRESENT' for r in report['repairs'])
    assert all(r['patch_applied'] is True for r in report['repairs'])
    assert all(r['rescan'] == 'ELIMINATED' for r in report['repairs'])
    assert SYNTHETIC_SECRET not in json.dumps(report, ensure_ascii=False)
    assert SYNTHETIC_SECRET not in saved
    print('[PASS] Repair -> Verify 自检通过（3 类；临时副本；原文件不变；报告零凭据）')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
