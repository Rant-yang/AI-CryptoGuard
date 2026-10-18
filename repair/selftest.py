"""Repair -> Verify 的安全合成自检。"""
import json
import argparse
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from repair.engine import RULES, _apply, _syntax_check, repair_and_verify  # noqa: E402


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
    tricky = ('# coding: utf-8\nfrom __future__ import annotations\n'
              'import hashlib\n# hashlib.md5( stays a comment\n'
              'example = "hashlib.md5("\n'
              'password = "SyntheticOnly_DoNotUse_123!"\n'
              'digest = hashlib.md5("测试".encode())\n')
    tricky_patch, tricky_rules = _apply(tricky)
    assert _syntax_check(tricky_patch, 'tricky.py')[0]
    assert tricky_patch.index('from __future__') < tricky_patch.index('import os')
    assert '# hashlib.md5( stays a comment' in tricky_patch
    assert 'example = "hashlib.md5("' in tricky_patch
    assert 'hashlib.sha256("测试".encode())' in tricky_patch
    assert tricky_rules['PY-REPAIR-MD5'] and tricky_rules['PY-REPAIR-HARDCODED-PASSWORD']
    assert not _apply('note = "hashlib.md5("\n')[1]['PY-REPAIR-MD5']
    assert not _syntax_check('import os\nfrom __future__ import annotations\n',
                             'bad_future.py')[0]
    protocol = ('import hashlib\n'
                'digest = hashlib.md5(b"wire", usedforsecurity=False).hexdigest()\n')
    protocol_patch, protocol_rules = _apply(protocol)
    assert protocol_patch == protocol
    assert not protocol_rules['PY-REPAIR-MD5']
    password_md5 = ('import hashlib\n'
                    'def hash_password(data):\n'
                    '    return hashlib.md5(data).hexdigest()\n'
                    'password_hash = hashlib.md5(password.encode()).hexdigest()\n')
    password_patch, password_rules = _apply(password_md5)
    assert password_patch == password_md5
    assert not password_rules['PY-REPAIR-MD5']
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, 'password_hash.py')
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(password_md5)
        guarded_password = repair_and_verify(path)
        assert guarded_password['skipped_password_md5'] == 2
        assert guarded_password['verification_scope'] == 'NO_APPLICABLE_PATCH'
        md5_row = next(r for r in guarded_password['repairs']
                       if r['rule_id'] == 'PY-REPAIR-MD5')
        assert md5_row['original_finding'] == 'PRESENT'
        assert md5_row['rescan'] == 'STILL_PRESENT'
    mixed_random = ('import random\n'
                    'simulation = random.Random(7)\n'
                    'sample = random.Random().randbytes(8)\n'
                    'nonce = random.Random().randbytes(12)\n')
    mixed_patch, mixed_rules = _apply(mixed_random)
    assert mixed_rules['PY-REPAIR-WEAK-RANDOM']
    assert 'simulation = random.Random(7)' in mixed_patch
    assert 'sample = random.Random().randbytes(8)' in mixed_patch
    assert 'nonce = random.SystemRandom().randbytes(12)' in mixed_patch
    conditional = ('from __future__ import annotations\nimport random\n'
                   'nonce = random.Random().randbytes(16) if hasattr(random.Random, "randbytes") '
                   'else bytes(random.randint(0, 255) for _ in range(16))\n')
    conditional_patch, conditional_rules = _apply(conditional)
    assert conditional_rules['PY-REPAIR-WEAK-RANDOM']
    assert 'nonce = secrets.token_bytes(16)' in conditional_patch
    assert conditional_patch.index('from __future__') < conditional_patch.index('import secrets')
    assert _syntax_check(conditional_patch, 'conditional.py')[0]
    assert not _apply(conditional.replace('range(16)', 'range(15)'))[1][
        'PY-REPAIR-WEAK-RANDOM']
    assert not _apply(conditional.replace('randint(0, 255)', 'randint(1, 255)'))[1][
        'PY-REPAIR-WEAK-RANDOM']
    assert not _apply(conditional.replace('import random\n', 'import random\nsecrets = fake\n'))[1][
        'PY-REPAIR-WEAK-RANDOM']
    assert not _apply(conditional.replace('import random\n', 'import random\nbytes = fake\n'))[1][
        'PY-REPAIR-WEAK-RANDOM']
    rebound = ('import random\n'
               'def source(random):\n'
               '    nonce = random.Random().randbytes(12)\n')
    assert _apply(rebound)[0] == rebound
    assert not _apply('import random\nsimulation = random.Random(7)\n')[1][
        'PY-REPAIR-WEAK-RANDOM']
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, 'protocol.py')
        with open(src, 'w', encoding='utf-8') as fh:
            fh.write(protocol)
        guarded = repair_and_verify(src)
        assert guarded['skipped_protocol_md5'] == 1
        assert guarded['verification_scope'] == 'NO_APPLICABLE_PATCH'
    print('[PASS] AST 定位不修改注释/字符串，兼容 Unicode 和 future 导入顺序')
    print('[PASS] usedforsecurity=False 的协议 MD5 不自动改写')
    print('[PASS] 口令哈希 MD5 不自动换成另一种快速摘要')
    print('[PASS] 弱随机修复只触及安全用途 randbytes，保留同文件模拟/测试随机源')
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
        demo = os.path.join(ROOT, 'examples', 'repair_demo')
        project = repair_and_verify(os.path.join(demo, 'app.py'),
                                    tools_dir=args.tools_dir,
                                    project_root=demo)
        assert project['tests']['before'] == 'PASS'
        assert project['tests']['after'] == 'PASS'
        assert project['tests']['count_before'] == 3
        assert project['tests']['count_after'] == 3
        assert project['verification_scope'] == 'SYNTAX_SCANNER_PROJECT_TESTS'
        assert project['new_high_findings'] == 0
        assert all(row['scanner_rescan'] == 'ELIMINATED'
                   for row in project['repairs'])
        print('[PASS] 演示项目：3/3 测试前后通过，三类正式复扫均消失')
    else:
        assert report['independent_scan']['status'] == 'NOT_RUN'
        assert report['new_high_findings'] is None
    with tempfile.TemporaryDirectory() as td:
        os.mkdir(os.path.join(td, 'tests'))
        src = os.path.join(td, 'app.py')
        with open(src, 'w', encoding='utf-8') as fh:
            fh.write('import hashlib\ndef digest():\n    return hashlib.md5(b"x").hexdigest()\n')
        with open(os.path.join(td, 'tests', 'test_app.py'), 'w', encoding='utf-8') as fh:
            fh.write('import unittest\nimport app\n'
                     'class T(unittest.TestCase):\n'
                     '    def test_old_protocol(self):\n'
                     '        self.assertEqual(len(app.digest()), 32)\n')
        incompatible = repair_and_verify(src, project_root=td)
        assert incompatible['tests']['before'] == 'PASS'
        assert incompatible['tests']['after'] == 'FAIL'
        assert incompatible['verification_scope'] == 'TESTS_FAILED'
    print('[PASS] 兼容性回归会明确失败，不把复扫消失当作可部署')
    print('[PASS] Repair -> Verify 自检通过（3 类；临时副本；原文件不变；报告零凭据）')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
