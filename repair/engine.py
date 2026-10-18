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
import subprocess
import sys
import tempfile
from pathlib import Path


RULES = ('PY-REPAIR-MD5', 'PY-REPAIR-WEAK-RANDOM',
         'PY-REPAIR-HARDCODED-PASSWORD')

_PASSWORD_NAME = re.compile(r'password|passwd|passphrase|pwd', re.I)


def repair_and_verify(source_file, output_report=None, tools_dir=None,
                      project_root=None, test_timeout=120):
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
        tests = (_run_project_tests(source_file, patched, project_root,
                                    test_timeout, td)
                 if project_root and syntax_ok else 'NOT_RUN')
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
        'tests': tests,
        'new_high_findings': independent.get('new_high_findings'),
        'independent_scan': independent,
        'verification_scope': ('FAILED' if not syntax_ok else
                               'NO_APPLICABLE_PATCH' if not any(applied.values()) else
                               'SYNTAX_SCANNER_PROJECT_TESTS'
                               if (isinstance(tests, dict) and
                                   tests.get('before') == 'PASS' and
                                   tests.get('after') == 'PASS' and
                                   independent.get('status') == 'COMPLETED') else
                               'TESTS_FAILED'
                               if isinstance(tests, dict) and
                               (tests.get('before') != 'PASS' or
                                tests.get('after') != 'PASS') else
                               'SYNTAX_AND_SCANNER_ONLY'
                               if independent.get('status') == 'COMPLETED'
                               else 'SYNTAX_ONLY'),
        'manual_review_required': True,
        'skipped_protocol_md5': _protocol_md5_count(original),
        'behavioral_compatibility': 'NOT_VERIFIED',
        'repairs': rows,
    }
    if output_report:
        os.makedirs(os.path.dirname(os.path.abspath(output_report)), exist_ok=True)
        with open(output_report, 'w', encoding='utf-8') as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
    return report


_PROJECT_SKIP = frozenset({'.git', '.venv', 'venv', '__pycache__',
                           'node_modules', 'out', 'workspace', 'build', 'dist'})


def _run_project_tests(source_file, patched, project_root, timeout, work):
    """Opt-in unittest on two bounded temporary project copies.

    This executes project code. The caller must only opt in for a trusted
    project; a temporary copy is not an OS security sandbox. No test output,
    traceback, or environment secret is persisted in the report.
    """
    root = Path(project_root).resolve()
    source = Path(source_file).resolve()
    if not root.is_dir() or root not in source.parents:
        raise ValueError('源文件必须位于指定的项目目录内。')
    relative = source.relative_to(root)
    total_bytes, count = 0, 0
    for base, dirs, files in os.walk(root):
        if any((Path(base) / d).is_symlink() for d in dirs):
            raise ValueError('项目测试副本不接受符号链接目录。')
        dirs[:] = [d for d in dirs if d not in _PROJECT_SKIP and
                   not d.startswith('.env')]
        for name in files:
            if name.startswith('.env'):
                continue
            path = Path(base) / name
            if path.is_symlink():
                raise ValueError('项目测试副本不接受符号链接。')
            total_bytes += path.stat().st_size
            count += 1
            if count > 1000 or total_bytes > 20 * 1024 * 1024:
                raise ValueError('项目测试副本超过 1000 文件或 20 MiB 上限。')
    if not (root / 'tests').is_dir():
        return {'before': 'NOT_RUN', 'after': 'NOT_RUN',
                'reason': '项目没有 tests/ 目录。'}

    result = {}
    for phase in ('before', 'after'):
        copy = Path(work) / ('project-' + phase)
        shutil.copytree(root, copy, ignore=shutil.ignore_patterns(
            *sorted(_PROJECT_SKIP), '.env', '.env.*'))
        if phase == 'after':
            (copy / relative).write_text(patched, encoding='utf-8')
        env = {key: os.environ[key] for key in
               ('PATH', 'SYSTEMROOT', 'TEMP', 'TMP') if key in os.environ}
        env['PYTHONPATH'] = str(copy)
        env['PYTHONNOUSERSITE'] = '1'
        try:
            proc = subprocess.run(
                [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests'],
                cwd=copy, env=env, capture_output=True, timeout=timeout,
                check=False)
            output = (proc.stderr or b'').decode('utf-8', errors='replace')
            match = re.search(r'Ran (\d+) tests?', output)
            count = int(match.group(1)) if match else 0
            result[phase] = 'PASS' if proc.returncode == 0 and count > 0 else 'FAIL'
            result['count_' + phase] = count
        except subprocess.TimeoutExpired:
            result[phase] = 'TIMEOUT'
            result['count_' + phase] = 0
    return result


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
    return {rule: any(item[2] == rule for item in _edits(text)) for rule in RULES}


def _protocol_md5_count(text):
    """Count explicitly non-security MD5 calls without recording their inputs."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return 0
    return sum(1 for node in ast.walk(tree) if _is_protocol_md5(node))


def _is_protocol_md5(node):
    """usedforsecurity=False often means an interoperable protocol digest.

    Replacing the hash changes its wire value. This is a conservative skip,
    not a claim that the surrounding protocol is safe.
    """
    return (isinstance(node, ast.Call) and
            isinstance(node.func, ast.Attribute) and
            isinstance(node.func.value, ast.Name) and
            node.func.value.id == 'hashlib' and node.func.attr == 'md5' and
            any(k.arg == 'usedforsecurity' and
                isinstance(k.value, ast.Constant) and k.value.value is False
                for k in node.keywords))


def _edits(text):
    """Return source spans for real AST expressions, excluding comments/strings.

    Python AST columns are UTF-8 byte offsets; translate each to a character
    offset before slicing Unicode source. Invalid input is left untouched and
    rejected by _syntax_check rather than repaired by a text regex.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    lines = text.splitlines(keepends=True)

    def position(line, column):
        prefix = lines[line - 1].encode('utf-8')[:column].decode('utf-8')
        return sum(len(part) for part in lines[:line - 1]) + len(prefix)

    edits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            owner = node.func.value
            if isinstance(owner, ast.Name):
                if owner.id == 'hashlib' and node.func.attr == 'md5':
                    if _is_protocol_md5(node):
                        continue
                    rule, replacement = 'PY-REPAIR-MD5', 'hashlib.sha256'
                elif owner.id == 'random' and node.func.attr == 'Random':
                    rule, replacement = 'PY-REPAIR-WEAK-RANDOM', 'random.SystemRandom'
                else:
                    continue
                edits.append((position(node.func.lineno, node.func.col_offset),
                              position(node.func.end_lineno, node.func.end_col_offset),
                              rule, replacement))
        elif (isinstance(node, ast.Assign) and len(node.targets) == 1 and
              isinstance(node.targets[0], ast.Name) and
              isinstance(node.value, ast.Constant) and
              isinstance(node.value.value, str) and
              3 <= len(node.value.value) <= 4096 and
              _PASSWORD_NAME.search(node.targets[0].id)):
            name = node.targets[0].id
            env_name = re.sub(r'[^A-Za-z0-9]+', '_', name).upper()
            edits.append((position(node.value.lineno, node.value.col_offset),
                          position(node.value.end_lineno, node.value.end_col_offset),
                          'PY-REPAIR-HARDCODED-PASSWORD',
                          'os.environ["%s"]' % env_name))
    return edits


def _os_import_position(text):
    """Insert after module docstring and future imports, preserving shebang."""
    tree = ast.parse(text)
    body = tree.body
    index = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and \
            isinstance(body[0].value.value, str):
        index = 1
    while index < len(body) and isinstance(body[index], ast.ImportFrom) and \
            body[index].module == '__future__':
        index += 1
    lines = text.splitlines(keepends=True)
    if index:
        return sum(len(part) for part in lines[:body[index - 1].end_lineno])
    if body:
        return sum(len(part) for part in lines[:body[0].lineno - 1])
    return len(text)


def _apply(text):
    applied = {rule: False for rule in RULES}
    edits = _edits(text)
    for start, end, rule, replacement in sorted(edits, reverse=True):
        text = text[:start] + replacement + text[end:]
        applied[rule] = True
    if applied['PY-REPAIR-HARDCODED-PASSWORD']:
        tree = ast.parse(text)
        has_os = any(isinstance(node, ast.Import) and
                     any(alias.name == 'os' and alias.asname is None
                         for alias in node.names) for node in tree.body)
        if not has_os:
            at = _os_import_position(text)
            newline = '\r\n' if '\r\n' in text else '\n'
            separator = '' if at == 0 or text[at - 1] in '\r\n' else newline
            text = text[:at] + separator + 'import os' + newline + text[at:]
    return text, applied


def _syntax_check(text, filename):
    try:
        compile(text, filename, 'exec')
        return True, None
    except SyntaxError as exc:
        # 只保留位置和异常类型，不把包含源码的 exc.text 写入报告。
        return False, 'SyntaxError at line %s column %s' % (exc.lineno, exc.offset)


def report_fingerprint(report):
    """报告内容指纹，便于演示前后结果复现。"""
    raw = json.dumps(report, ensure_ascii=False, sort_keys=True).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()
