"""Repair -> Verify 的安全合成自检。"""
import json
import argparse
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


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--tools-dir', help='同时跑正式 scanner 的独立前后对照')
    args = ap.parse_args(argv)
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, 'demo.py')
        out = os.path.join(td, 'report.json')
        with open(src, 'w', encoding='utf-8') as fh:
            fh.write(SOURCE)
        before = open(src, encoding='utf-8').read()
        report = repair_and_verify(src, out, args.tools_dir)
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
    if args.tools_dir:
        assert report['independent_scan']['status'] == 'COMPLETED'
        assert report['independent_scan']['rules']['PY-REPAIR-MD5'] == 'ELIMINATED'
        assert report['independent_scan']['rules']['PY-REPAIR-HARDCODED-PASSWORD'] == 'ELIMINATED'
        assert report['independent_scan']['rules']['PY-REPAIR-WEAK-RANDOM'] == 'ELIMINATED'
        assert report['new_high_findings'] == 0
        print('[PASS] 正式 scanner 独立对照：MD5 / 口令 / 弱随机均消失')
    else:
        assert report['independent_scan']['status'] == 'NOT_RUN'
        assert report['new_high_findings'] is None
    print('[PASS] Repair -> Verify 自检通过（3 类；临时副本；原文件不变；报告零凭据）')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
