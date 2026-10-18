"""Conservative Python AST rules for security bytes and weak hash constructors.

Only report ``Random().randbytes`` assigned to security-named variables,
including a conditional expression with a weak-random branch. General
simulation/test use of ``random.Random`` is out of scope.
The evidence contains structure and location, never a source line or value.
"""

import ast
import collections
import hashlib
import io
import os
import re
import token
import tokenize


TOOL_NAME = 'python-ast'
RULE_ID = 'PY-WEAK-RANDOM-CRYPTO'
HASH_RULE_ID = 'PY-HASHLIB-NEW-WEAK-HASH'
_WEAK_HASHES = {'md2': 'MD2', 'md4': 'MD4',
                'md5': 'MD5', 'sha1': 'SHA1', 'sha-1': 'SHA1'}
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


def _scope_nodes(scope):
    """Walk one lexical scope without borrowing imports from nested scopes."""
    stack = list(reversed(scope.body))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef, ast.Lambda)):
            continue
        yield node
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _hash_lines(tree):
    """Recognize literal ``hashlib.new('md5'/'sha1')`` calls with proven imports.

    Only direct imports in a module/function body establish identity. A store
    to an alias anywhere in that scope disqualifies it; this favors a miss over
    claiming a user-defined object is the standard-library hashlib module.
    """
    hits = {}

    def visit_scope(scope, inherited_modules=frozenset(),
                    inherited_functions=frozenset()):
        modules = set(inherited_modules)
        functions = set(inherited_functions)
        for stmt in scope.body:
            if isinstance(stmt, ast.Import):
                modules.update(a.asname or a.name for a in stmt.names
                               if a.name == 'hashlib')
            elif isinstance(stmt, ast.ImportFrom) and stmt.module == 'hashlib':
                functions.update(a.asname or a.name for a in stmt.names
                                 if a.name == 'new')

        blocked = {n.id for n in _scope_nodes(scope)
                   if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = scope.args
            blocked.update(a.arg for a in (args.posonlyargs + args.args +
                                            args.kwonlyargs))
            if args.vararg:
                blocked.add(args.vararg.arg)
            if args.kwarg:
                blocked.add(args.kwarg.arg)
        modules.difference_update(blocked)
        functions.difference_update(blocked)

        for node in _scope_nodes(scope):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            matched = (isinstance(func, ast.Attribute) and func.attr == 'new'
                       and isinstance(func.value, ast.Name)
                       and func.value.id in modules)
            matched = matched or (isinstance(func, ast.Name) and
                                  func.id in functions)
            if not matched:
                continue
            argument = node.args[0] if node.args else next(
                (k.value for k in node.keywords if k.arg == 'name'), None)
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                alg = _WEAK_HASHES.get(argument.value.strip().lower())
                if alg:
                    hits.setdefault(alg, set()).add(node.lineno)

        for stmt in scope.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit_scope(stmt, frozenset(modules), frozenset(functions))
            elif isinstance(stmt, ast.ClassDef):
                # Class-body bindings are not lexical bindings in a method.
                for child in stmt.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        visit_scope(child, frozenset(modules), frozenset(functions))

    visit_scope(tree)
    return {alg: sorted(lines) for alg, lines in hits.items()}


def _hash_tokens(source):
    """Limited recovery for a newer-Python file that Python 3.11 cannot parse.

    The tokenizer still distinguishes code from comments/string contents. Only
    an imported hashlib identity followed by a literal ``.new`` call counts.
    This is deliberately narrower than parsing the whole file and is marked
    ``partial-parse`` in the resulting evidence.
    """
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError):
        return {}
    depth, modules, funcs, hits = 0, {}, {}, {}
    significant = [t for t in tokens if t.type not in
                   (tokenize.NL, tokenize.NEWLINE, tokenize.COMMENT,
                    tokenize.ENCODING)]
    for i, tok in enumerate(significant):
        if tok.type == tokenize.INDENT:
            depth += 1
            continue
        if tok.type == tokenize.DEDENT:
            depth -= 1
            modules = {k: v for k, v in modules.items() if v <= depth}
            funcs = {k: v for k, v in funcs.items() if v <= depth}
            continue
        nearby = significant[i + 1:i + 6]
        words = [t.string for t in nearby]
        if tok.string == 'import' and words[:1] == ['hashlib']:
            alias = words[2] if len(words) >= 3 and words[1] == 'as' else 'hashlib'
            modules[alias] = depth
        elif tok.string == 'from' and words[:2] == ['hashlib', 'import']:
            if len(words) >= 3 and words[2] == 'new':
                alias = words[4] if len(words) >= 5 and words[3] == 'as' else 'new'
                funcs[alias] = depth
        if tok.type != token.NAME:
            continue
        if tok.string in modules and words[:1] in (['='], [':=']):
            modules.pop(tok.string, None)
            continue
        if tok.string in funcs and words[:1] in (['='], [':=']):
            funcs.pop(tok.string, None)
            continue
        start = 0
        if tok.string in modules and words[:3] == ['.', 'new', '(']:
            start = 3
        elif tok.string in funcs and words[:1] == ['(']:
            start = 1
        if not start or len(words) <= start:
            continue
        arg_token = nearby[start]
        if arg_token.type != token.STRING:
            continue
        try:
            value = ast.literal_eval(arg_token.string)
        except (SyntaxError, ValueError):
            continue
        alg = _WEAK_HASHES.get(value.strip().lower()) if isinstance(value, str) else None
        if alg:
            hits.setdefault(alg, set()).add(tok.start[0])
    return {alg: sorted(lines) for alg, lines in hits.items()}


def scan(root, diagnostics=None):
    """Return v0.1 findings; never include literal source text.

    Optional diagnostics exposes parse coverage so a 3.11 run on newer Python
    source cannot silently look like full AST coverage.
    """
    root = os.path.abspath(root)
    findings = []
    coverage = collections.Counter({
        'full_ast_files': 0, 'partial_parse_files': 0,
        'oversize_skipped': 0, 'unreadable_skipped': 0,
        'token_recovery_findings': 0,
    })
    for directory, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP)
        for name in sorted(files):
            if not name.endswith('.py'):
                continue
            path = os.path.join(directory, name)
            try:
                if os.path.getsize(path) > _MAX_BYTES:
                    coverage['oversize_skipped'] += 1
                    continue
                with open(path, encoding='utf-8-sig') as fh:
                    source = fh.read()
            except (OSError, UnicodeError, ValueError):
                coverage['unreadable_skipped'] += 1
                continue
            partial = False
            try:
                tree = ast.parse(source, filename=name)
            except SyntaxError:
                # Newer Python syntax (notably PEP 701 f-strings) cannot be
                # parsed by Python 3.11. Recover only the narrow hash call;
                # do not pretend that the entire AST was analyzed.
                partial = True
                coverage['partial_parse_files'] += 1
                lines, hash_hits = [], _hash_tokens(source)
            else:
                coverage['full_ast_files'] += 1
                lines, hash_hits = _lines(tree), _hash_lines(tree)
            if not lines and not hash_hits:
                continue
            rel = os.path.relpath(path, root).replace('\\', '/')
            if lines:
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
            for alg, alg_lines in sorted(hash_hits.items()):
                finding_id = hashlib.sha1(
                    ('%s|%s|hashing' % (rel, alg)).encode('utf-8')).hexdigest()[:12]
                findings.append({
                    'schema_version': '0.1',
                    'finding_id': finding_id,
                    'rule_id': HASH_RULE_ID,
                    'file': rel,
                    'line': alg_lines[0],
                    'algorithm': alg,
                    'algorithm_normalized': alg,
                    'usage': 'hashing',
                    'risk': 'broken',
                    'severity': 'high',
                    'confidence': 0.95,
                    'evidence': [{
                        'tool': TOOL_NAME,
                        'kind': 'ast',
                        'lines': alg_lines,
                        'raw': {'rule_id': HASH_RULE_ID,
                                'api': 'hashlib.new', 'algorithm': alg,
                                'parse_scope': 'token_fallback' if partial else 'full_ast'},
                    }],
                    'remediation': {
                        'decided': True,
                        'reason': 'decided',
                        'source': 'rule-base',
                        'action': ('%s 不适合安全敏感哈希。先确认是口令哈希、'
                                   '签名、完整性校验还是协议兼容用途，再按用途迁移；'
                                   '口令存储应选有成本参数的专用口令 KDF。' % alg),
                        'references': [HASH_RULE_ID],
                    },
                    'tags': (['python-ast', 'weak-hash', 'partial-parse'] if partial
                             else ['python-ast', 'weak-hash']),
                })
                if partial:
                    coverage['token_recovery_findings'] += 1
    if diagnostics is not None:
        diagnostics.update(coverage)
    return findings
