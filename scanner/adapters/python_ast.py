"""Conservative Python AST rule for security bytes from ``random.Random``.

Only report ``Random().randbytes`` assigned to security-named variables,
including a conditional expression with a weak-random branch. General
simulation/test use of ``random.Random`` is out of scope.
The evidence contains structure and location, never a source line or value.
"""

import ast
import hashlib
import os
import re


TOOL_NAME = 'python-ast'
RULE_ID = 'PY-WEAK-RANDOM-CRYPTO'
_MAX_BYTES = 2 * 1024 * 1024
_SKIP = frozenset({'.git', '.venv', 'venv', '__pycache__', 'node_modules',
                   'build', 'dist', '.tox', 'site-packages'})
_SECURITY_NAME = re.compile(
    r'(?i)(?:^|_)(?:nonce|iv|salt|key|secret|token)(?:_|$)')


def _security_target(target):
    if isinstance(target, ast.Name):
        return bool(_SECURITY_NAME.search(target.id))
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_security_target(item) for item in target.elts)
    return False


def _is_random_ctor(expr, modules, ctors):
    if not isinstance(expr, ast.Call):
        return False
    func = expr.func
    return ((isinstance(func, ast.Attribute) and func.attr == 'Random'
             and isinstance(func.value, ast.Name) and func.value.id in modules)
            or (isinstance(func, ast.Name) and func.id in ctors))


def _is_weak_bytes(expr, modules, ctors):
    return (isinstance(expr, ast.Call) and
            isinstance(expr.func, ast.Attribute) and
            expr.func.attr == 'randbytes' and
            _is_random_ctor(expr.func.value, modules, ctors))


def _lines(tree):
    modules, ctors = set(), set()
    # Only module-level imports are unambiguous across functions. If an alias
    # is assigned elsewhere in the file, prefer a missed hit to a false claim
    # that the name still resolves to the standard-library random module.
    for node in tree.body:
        if isinstance(node, ast.Import):
            modules.update(alias.asname or alias.name for alias in node.names
                           if alias.name == 'random')
        elif isinstance(node, ast.ImportFrom) and node.module == 'random':
            ctors.update(alias.asname or alias.name for alias in node.names
                         if alias.name == 'Random')
    rebound = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            rebound.add(node.id)
        elif isinstance(node, ast.arg):
            rebound.add(node.arg)
    modules.difference_update(rebound)
    ctors.difference_update(rebound)

    hits = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            target_ok = any(_security_target(t) for t in node.targets)
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            target_ok = _security_target(node.target)
            value = node.value
        else:
            continue
        weak = _is_weak_bytes(value, modules, ctors)
        if isinstance(value, ast.IfExp):
            weak = (weak or _is_weak_bytes(value.body, modules, ctors) or
                    _is_weak_bytes(value.orelse, modules, ctors))
        if target_ok and weak:
            hits.add(node.lineno)
    return sorted(hits)


def scan(root):
    """Return v0.1 configuration findings; never include literal source text."""
    root = os.path.abspath(root)
    findings = []
    for directory, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP)
        for name in sorted(files):
            if not name.endswith('.py'):
                continue
            path = os.path.join(directory, name)
            try:
                if os.path.getsize(path) > _MAX_BYTES:
                    continue
                with open(path, encoding='utf-8-sig') as fh:
                    tree = ast.parse(fh.read(), filename=name)
            except (OSError, UnicodeError, SyntaxError, ValueError):
                continue
            lines = _lines(tree)
            if not lines:
                continue
            rel = os.path.relpath(path, root).replace('\\', '/')
            finding_id = hashlib.sha1(
                ('%s|%s' % (rel, RULE_ID)).encode('utf-8')).hexdigest()[:12]
            findings.append({
                'schema_version': '0.1',
                'finding_id': finding_id,
                'finding_kind': 'configuration',
                'rule_id': RULE_ID,
                'file': rel,
                'line': lines[0],
                'algorithm': '',
                'algorithm_normalized': '',
                'usage': 'unknown',
                'risk': 'not_applicable',
                'severity': 'high',
                'confidence': 0.9,
                'evidence': [{
                    'tool': TOOL_NAME,
                    'kind': 'ast',
                    'lines': lines,
                    'raw': {'rule_id': RULE_ID,
                            'source': 'random.Random().randbytes',
                            'sink': 'security-named-assignment'},
                }],
                'explanation': ('安全用途命名的随机字节由 random.Random 生成。'
                                '该伪随机源不适合生成 nonce、IV、盐或密钥材料。'),
                'evidence_refs': ['E1'],
                'remediation': {
                    'decided': True,
                    'reason': 'decided',
                    'source': 'rule-base',
                    'action': ('改用 secrets.token_bytes 或 os.urandom；'
                               '若协议要求特定长度与唯一性，还需验证实际调用约束。'),
                    'references': ['PY-WEAK-RANDOM-CRYPTO'],
                },
                'tags': ['python-ast', 'weak-random'],
            })
    return findings
