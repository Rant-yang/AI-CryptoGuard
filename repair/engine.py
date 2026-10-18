"""三类可验证的 Python 修复模板。

只在临时副本中应用；报告不包含源码 diff 或凭据原文。当前 v1 支持：
hashlib.md5 -> sha256、random.Random -> SystemRandom、硬编码口令 -> 环境变量。
"""
import ast
from collections import Counter
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import tempfile


RULES = ('PY-REPAIR-MD5', 'PY-REPAIR-WEAK-RANDOM',
         'PY-REPAIR-HARDCODED-PASSWORD')

_MD5 = re.compile(r'\bhashlib\.md5\s*\(')
_RANDOM = re.compile(r'\brandom\.Random\s*\(')
_PASSWORD = re.compile(
    r'(?P<indent>^[ \t]*)(?P<name>(?=[A-Za-z0-9_]*(?:password|passwd|passphrase|pwd))'
    r'[A-Za-z_][A-Za-z0-9_]*)'
    r'\s*=\s*(?P<quote>["\'])(?P<value>[^"\'\r\n]{3,4096})(?P=quote)',
    re.I | re.M)


def repair_and_verify(source_file, output_report=None, tools_dir=None):
    """在临时目录修复一个 Python 文件，返回不含敏感材料的报告。"""
    source_file = os.path.abspath(source_file)
    if not os.path.isfile(source_file):
        raise FileNotFoundError(source_file)
    original = _read(source_file)
    before = _detect(original)

    with tempfile.TemporaryDirectory(prefix='acg-repair-') as td:
        temp_file = os.path.join(td, os.path.basename(source_file))
        shutil.copy2(source_file, temp_file)
        patched, applied = _apply(original)
        with open(temp_file, 'w', encoding='utf-8', newline='') as fh:
            fh.write(patched)

        syntax_ok, syntax_error = _syntax_check(patched, temp_file)
        after = _detect(patched) if syntax_ok else before
        if not syntax_ok:
            independent = {'status': 'NOT_RUN', 'reason': '临时补丁语法失败，未运行扫描。'}
        elif not tools_dir:
            independent = {'status': 'NOT_RUN', 'reason': '未提供扫描工具目录。'}
        else:
            try:
                independent = _independent_rescan(
                    original, patched, os.path.basename(source_file), td, tools_dir)
            except (OSError, ValueError, RuntimeError) as exc:
                independent = {'status': 'FAILED',
                               'reason': '独立扫描异常: %s' % type(exc).__name__}
        rows = []
        for rule in RULES:
            rows.append({
                'rule_id': rule,
                'original_finding': 'PRESENT' if before[rule] else 'ABSENT',
                'patch_applied': bool(applied[rule]),
                'syntax': 'PASS' if syntax_ok else 'FAIL',
                'rescan': ('ELIMINATED' if before[rule] and not after[rule]
                           else 'NOT_PRESENT' if not before[rule]
                           else 'STILL_PRESENT'),
                'scanner_rescan': independent.get('rules', {}).get(rule, 'NOT_RUN'),
            })

    report = {
        'source_file': os.path.basename(source_file),
        'temporary_copy': True,
        'original_unchanged': _read(source_file) == original,
        'syntax': 'PASS' if syntax_ok else 'FAIL',
        'syntax_error': syntax_error,
        'tests': 'NOT_RUN',
        'new_high_findings': independent.get('new_high_findings'),
        'independent_scan': independent,
        'verification_scope': ('FAILED' if not syntax_ok else
                               'SYNTAX_AND_SCANNER_ONLY'
                               if independent.get('status') == 'COMPLETED'
                               else 'SYNTAX_ONLY'),
        'manual_review_required': True,
        'behavioral_compatibility': 'NOT_VERIFIED',
        'repairs': rows,
    }
    if output_report:
        os.makedirs(os.path.dirname(os.path.abspath(output_report)), exist_ok=True)
        with open(output_report, 'w', encoding='utf-8') as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
    return report


def _independent_rescan(original, patched, filename, work, tools_dir):
    """Run the actual scanner on isolated before/after copies, never on originals.

    A regex patch checked by the same regex is circular evidence. The scanner
    is a separate implementation; it also tells us when it does *not* cover a
    repair class instead of falsely declaring that class verified.
    """
    from scanner.scan import main as scanner_main

    rows = {}
    for phase, text in (('before', original), ('after', patched)):
        folder = os.path.join(work, phase)
        os.makedirs(folder)
        with open(os.path.join(folder, filename), 'w', encoding='utf-8') as fh:
            fh.write(text)
        result_path = os.path.join(work, phase + '-findings.json')
        with contextlib.redirect_stdout(io.StringIO()):
            exit_code = scanner_main([folder, '-o', result_path,
                                      '--tools-dir', tools_dir, '--no-coverage'])
        if exit_code != 0:
            return {'status': 'FAILED', 'reason': '独立扫描器未完成；exit=%d。' % exit_code}
        meta_path = os.path.splitext(result_path)[0] + '.meta.json'
        with open(meta_path, encoding='utf-8') as fh:
            metadata = json.load(fh)
        if metadata.get('failures'):
            return {'status': 'FAILED', 'reason': '独立扫描器有工具失败；不能判定问题已消除。'}
        with open(result_path, encoding='utf-8') as fh:
            rows[phase] = json.load(fh)

    def markers(findings):
        return {
            'PY-REPAIR-MD5': any(f.get('algorithm_normalized') == 'MD5'
                                   for f in findings),
            'PY-REPAIR-HARDCODED-PASSWORD': any(
                f.get('rule_id') in ('CRED-HARDCODED-PASSWORD', 'CRED-DEFAULT-WEAK')
                for f in findings),
            'PY-REPAIR-WEAK-RANDOM': any(
                f.get('rule_id') == 'PY-WEAK-RANDOM-CRYPTO' for f in findings),
        }

    b, a = markers(rows['before']), markers(rows['after'])
    by_rule = {}
    for rule in RULES:
        if rule not in b:
            by_rule[rule] = 'NOT_COVERED'
        elif b[rule] and not a[rule]:
            by_rule[rule] = 'ELIMINATED'
        elif b[rule] and a[rule]:
            by_rule[rule] = 'STILL_PRESENT'
        else:
            by_rule[rule] = 'NOT_DETECTED_BEFORE'

    def high_keys(findings):
        return Counter((f.get('algorithm_normalized'), f.get('rule_id'), f.get('risk'))
                       for f in findings if f.get('severity') in ('high', 'critical'))

    return {'status': 'COMPLETED', 'rules': by_rule,
            'new_high_findings': sum((high_keys(rows['after']) -
                                     high_keys(rows['before'])).values())}


def _read(path):
    with open(path, encoding='utf-8-sig', errors='strict') as fh:
        return fh.read()


def _detect(text):
    return {
        'PY-REPAIR-MD5': bool(_MD5.search(text)),
        'PY-REPAIR-WEAK-RANDOM': bool(_RANDOM.search(text)),
        'PY-REPAIR-HARDCODED-PASSWORD': bool(_PASSWORD.search(text)),
    }


def _apply(text):
    applied = {rule: False for rule in RULES}
    text, n = _MD5.subn('hashlib.sha256(', text)
    applied['PY-REPAIR-MD5'] = n > 0
    text, n = _RANDOM.subn('random.SystemRandom(', text)
    applied['PY-REPAIR-WEAK-RANDOM'] = n > 0

    def replace_password(match):
        name = match.group('name')
        env_name = re.sub(r'[^A-Za-z0-9]+', '_', name).upper()
        return '%s%s = os.environ["%s"]' % (match.group('indent'), name, env_name)

    text, n = _PASSWORD.subn(replace_password, text)
    applied['PY-REPAIR-HARDCODED-PASSWORD'] = n > 0
    if n and not re.search(r'^\s*(?:import os|from os\b)', text, re.M):
        text = 'import os\n' + text
    return text, applied


def _syntax_check(text, filename):
    try:
        ast.parse(text, filename=filename)
        return True, None
    except SyntaxError as exc:
        # 只保留位置和异常类型，不把包含源码的 exc.text 写入报告。
        return False, 'SyntaxError at line %s column %s' % (exc.lineno, exc.offset)


def report_fingerprint(report):
    """报告内容指纹，便于演示前后结果复现。"""
    raw = json.dumps(report, ensure_ascii=False, sort_keys=True).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()
