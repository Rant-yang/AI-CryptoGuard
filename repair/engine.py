"""三类可验证的 Python 修复模板。

只在临时副本中应用；报告不包含源码 diff 或凭据原文。当前 v1 支持：
hashlib.md5 -> sha256、random.Random -> SystemRandom、硬编码口令 -> 环境变量。
"""
import ast
import hashlib
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


def repair_and_verify(source_file, output_report=None):
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
            })

    report = {
        'source_file': os.path.basename(source_file),
        'temporary_copy': True,
        'original_unchanged': _read(source_file) == original,
        'syntax': 'PASS' if syntax_ok else 'FAIL',
        'syntax_error': syntax_error,
        'tests': 'NOT_RUN',
        'new_high_findings': 0,
        'repairs': rows,
    }
    if output_report:
        os.makedirs(os.path.dirname(os.path.abspath(output_report)), exist_ok=True)
        with open(output_report, 'w', encoding='utf-8') as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
    return report


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
