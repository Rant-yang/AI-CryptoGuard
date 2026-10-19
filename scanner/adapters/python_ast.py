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

from core.rules.key_size import (RSA_WEAK_KEY_SIZE_RULE, RSA_MIN_CLASSICAL_BITS,
                                 RSA_WEAK_KEY_ACTION, RSA_KEY_SIZE_REFERENCE)
from core.rules.iv_nonce import (FIXED_CBC_IV_RULE, FIXED_GCM_NONCE_RULE,
                                 CBC_ACTION, GCM_ACTION, CBC_REFERENCE,
                                 GCM_REFERENCE)

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
        # A def/class statement binds its name without an ast.Name(Store).
        # Such a declaration can replace an imported alias in this scope.
        blocked.update(stmt.name for stmt in scope.body
                       if isinstance(stmt, (ast.FunctionDef,
                                            ast.AsyncFunctionDef, ast.ClassDef)))
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


def _weak_rsa_key_sizes(tree):
    """Return literal key sizes from proven cryptography RSA generation calls.

    This deliberately excludes variable-derived sizes and aliases rebound in
    the lexical scope. We do not infer a key's business use or execution path.
    """
    hits = set()

    def visit_scope(scope, inherited=frozenset()):
        modules = set(inherited)
        for stmt in scope.body:
            if (isinstance(stmt, ast.ImportFrom) and
                    stmt.module == 'cryptography.hazmat.primitives.asymmetric'):
                modules.update(a.asname or a.name for a in stmt.names
                               if a.name == 'rsa')
        blocked = {n.id for n in _scope_nodes(scope)
                   if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
        blocked.update(stmt.name for stmt in scope.body
                       if isinstance(stmt, (ast.FunctionDef,
                                            ast.AsyncFunctionDef, ast.ClassDef)))
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = scope.args
            blocked.update(a.arg for a in (args.posonlyargs + args.args +
                                            args.kwonlyargs))
            if args.vararg:
                blocked.add(args.vararg.arg)
            if args.kwarg:
                blocked.add(args.kwarg.arg)
        modules.difference_update(blocked)

        for node in _scope_nodes(scope):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and
                    func.attr == 'generate_private_key' and
                    isinstance(func.value, ast.Name) and
                    func.value.id in modules):
                continue
            key_size = next((k.value for k in node.keywords
                             if k.arg == 'key_size'), None)
            if (isinstance(key_size, ast.Constant) and
                    type(key_size.value) is int and
                    0 < key_size.value < RSA_MIN_CLASSICAL_BITS):
                hits.add((key_size.lineno, key_size.value))

        for stmt in scope.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit_scope(stmt, frozenset(modules))
            elif isinstance(stmt, ast.ClassDef):
                for child in stmt.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        visit_scope(child, frozenset(modules))

    visit_scope(tree)
    return sorted(hits)


def _literal_byte_length(expr):
    """Only direct byte literals and literal repetition; never inspect values."""
    if isinstance(expr, ast.Constant) and isinstance(expr.value, bytes):
        return len(expr.value) or None
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mult):
        for value, count in ((expr.left, expr.right), (expr.right, expr.left)):
            if (isinstance(value, ast.Constant) and isinstance(value.value, bytes)
                    and isinstance(count, ast.Constant) and type(count.value) is int
                    and 0 < count.value <= 32):
                length = len(value.value) * count.value
                return length if 0 < length <= 32 else None
    return None


def _direct_fixed_iv_nonce(tree):
    """Recognize direct encryption API calls with a fixed bytes argument.

    CBC requires an actual ``encryptor()`` call on a proved Cipher value;
    AESGCM requires ``encrypt()`` on a proved AESGCM value. Simple same-scope
    literal/constructor assignments are followed in statement order. Branches,
    unknown calls and decryption-only use do not establish this finding.
    """
    hits = set()

    def attr_call(node, owner, name):
        return (isinstance(node, ast.Call) and
                isinstance(node.func, ast.Attribute) and node.func.attr == name and
                isinstance(node.func.value, ast.Name) and
                node.func.value.id in owner)

    def visit_scope(scope, inherited=(frozenset(), frozenset(), frozenset(),
                                     frozenset(), frozenset())):
        ciphers, modes, algorithms, gcm, py_aes = map(set, inherited)
        other_imports = set()
        for stmt in scope.body:
            if isinstance(stmt, ast.Import):
                other_imports.update(a.asname or a.name.split('.')[0]
                                     for a in stmt.names)
            elif isinstance(stmt, ast.ImportFrom):
                if stmt.module == 'cryptography.hazmat.primitives.ciphers':
                    for alias in stmt.names:
                        name = alias.asname or alias.name
                        target = {'Cipher': ciphers, 'modes': modes,
                                  'algorithms': algorithms}.get(alias.name)
                        if target is not None:
                            target.add(name)
                        else:
                            other_imports.add(name)
                elif stmt.module == 'cryptography.hazmat.primitives.ciphers.aead':
                    for alias in stmt.names:
                        name = alias.asname or alias.name
                        if alias.name == 'AESGCM':
                            gcm.add(name)
                        else:
                            other_imports.add(name)
                elif stmt.module in ('Crypto.Cipher', 'Cryptodome.Cipher'):
                    for alias in stmt.names:
                        name = alias.asname or alias.name
                        if alias.name == 'AES':
                            py_aes.add(name)
                        else:
                            other_imports.add(name)
                else:
                    other_imports.update(a.asname or a.name for a in stmt.names)
        blocked = {n.id for n in _scope_nodes(scope)
                   if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
        blocked.update(other_imports)
        blocked.update(stmt.name for stmt in scope.body
                       if isinstance(stmt, (ast.FunctionDef,
                                            ast.AsyncFunctionDef, ast.ClassDef)))
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = scope.args
            blocked.update(a.arg for a in (args.posonlyargs + args.args +
                                            args.kwonlyargs))
            if args.vararg:
                blocked.add(args.vararg.arg)
            if args.kwarg:
                blocked.add(args.kwarg.arg)
        for names in (ciphers, modes, algorithms, gcm, py_aes):
            names.difference_update(blocked)

        def pycrypto_cbc_iv(expr, resolve):
            if not attr_call(expr, py_aes, 'new') or len(expr.args) < 2:
                return None
            mode = expr.args[1]
            if not (isinstance(mode, ast.Attribute) and mode.attr == 'MODE_CBC'
                    and isinstance(mode.value, ast.Name) and mode.value.id in py_aes):
                return None
            iv = expr.args[2] if len(expr.args) >= 3 else next(
                (k.value for k in expr.keywords if k.arg == 'iv'), None)
            info = resolve(iv)
            return info if info and info[0] == 16 else None

        for node in _scope_nodes(scope):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            # Cipher(algorithms.AES(key), modes.CBC(b'...')).encryptor()
            if node.func.attr == 'encryptor' and not node.args and not node.keywords:
                cipher = node.func.value
                if (isinstance(cipher, ast.Call) and isinstance(cipher.func, ast.Name)
                        and cipher.func.id in ciphers and len(cipher.args) >= 2
                        and attr_call(cipher.args[0], algorithms, 'AES')
                        and attr_call(cipher.args[1], modes, 'CBC')):
                    mode = cipher.args[1]
                    iv = mode.args[0] if mode.args else next(
                        (k.value for k in mode.keywords
                         if k.arg == 'initialization_vector'), None)
                    nbytes = _literal_byte_length(iv)
                    if nbytes == 16:
                        hits.add((FIXED_CBC_IV_RULE, iv.lineno, nbytes,
                                  'Cipher.encryptor'))
            # AESGCM(key).encrypt(b'...', plaintext, associated_data)
            if node.func.attr == 'encrypt' and isinstance(node.func.value, ast.Call):
                ctor = node.func.value
                py_iv = pycrypto_cbc_iv(ctor, lambda value: (
                    (_literal_byte_length(value), value.lineno)
                    if _literal_byte_length(value) is not None else None))
                if py_iv:
                    hits.add((FIXED_CBC_IV_RULE, py_iv[1], py_iv[0],
                              'AES.new.encrypt'))
                if (isinstance(ctor.func, ast.Name) and ctor.func.id in gcm
                        and (ctor.args or any(k.arg == 'key' for k in ctor.keywords))):
                    nonce = node.args[0] if node.args else next(
                        (k.value for k in node.keywords if k.arg == 'nonce'), None)
                    nbytes = _literal_byte_length(nonce)
                    if nbytes == 12:
                        hits.add((FIXED_GCM_NONCE_RULE, nonce.lineno, nbytes,
                                  'AESGCM.encrypt'))

        # Straight-line local propagation covers the common library idiom:
        # iv = b'...'; cipher = Cipher(AES(key), CBC(iv)); cipher.encryptor().
        # Never borrow a value across branches or assume a constructor is used
        # for encryption merely because it exists.
        literals, cipher_vars, pycrypto_vars, aead_vars = {}, {}, {}, set()

        def byte_info(expr):
            size = _literal_byte_length(expr)
            if size is not None:
                return size, expr.lineno
            if isinstance(expr, ast.Name):
                return literals.get(expr.id)
            return None

        def cipher_iv(expr):
            if not (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name)
                    and expr.func.id in ciphers and len(expr.args) >= 2
                    and attr_call(expr.args[0], algorithms, 'AES')
                    and attr_call(expr.args[1], modes, 'CBC')):
                return None
            mode = expr.args[1]
            iv = mode.args[0] if mode.args else next(
                (k.value for k in mode.keywords
                 if k.arg == 'initialization_vector'), None)
            info = byte_info(iv)
            return info if info and info[0] == 16 else None

        def is_aead_ctor(expr):
            return (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name)
                    and expr.func.id in gcm and
                    (expr.args or any(k.arg == 'key' for k in expr.keywords)))

        for stmt in scope.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef, ast.Import, ast.ImportFrom)):
                continue
            if isinstance(stmt, ast.Assign):
                expr = stmt.value
                targets = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
            elif isinstance(stmt, ast.AnnAssign):
                expr = stmt.value
                targets = [stmt.target.id] if isinstance(stmt.target, ast.Name) else []
            elif isinstance(stmt, (ast.Expr, ast.Return)):
                expr = stmt.value
                targets = []
            else:
                # Control flow might rebind any local name on one path.
                stores = {n.id for n in ast.walk(stmt)
                          if isinstance(n, ast.Name) and
                          isinstance(n.ctx, (ast.Store, ast.Del))}
                for name in stores:
                    literals.pop(name, None)
                    cipher_vars.pop(name, None)
                    pycrypto_vars.pop(name, None)
                    aead_vars.discard(name)
                continue

            if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
                receiver = expr.func.value
                if isinstance(receiver, ast.Name):
                    if (expr.func.attr == 'encryptor' and not expr.args and
                            not expr.keywords and receiver.id in cipher_vars):
                        size, source_line = cipher_vars[receiver.id]
                        hits.add((FIXED_CBC_IV_RULE, source_line, size,
                                  'Cipher.encryptor'))
                    elif expr.func.attr == 'encrypt' and receiver.id in aead_vars:
                        nonce = expr.args[0] if expr.args else next(
                            (k.value for k in expr.keywords if k.arg == 'nonce'), None)
                        info = byte_info(nonce)
                        if info and info[0] == 12:
                            hits.add((FIXED_GCM_NONCE_RULE, info[1], info[0],
                                      'AESGCM.encrypt'))
                    elif expr.func.attr == 'encrypt' and receiver.id in pycrypto_vars:
                        size, source_line = pycrypto_vars[receiver.id]
                        hits.add((FIXED_CBC_IV_RULE, source_line, size,
                                  'AES.new.encrypt'))

            info = byte_info(expr)
            cipher_info = cipher_iv(expr)
            pycrypto_info = pycrypto_cbc_iv(expr, byte_info)
            aead_ctor = is_aead_ctor(expr)
            for name in targets:
                literals.pop(name, None)
                cipher_vars.pop(name, None)
                pycrypto_vars.pop(name, None)
                aead_vars.discard(name)
                if info:
                    literals[name] = info
                elif cipher_info:
                    cipher_vars[name] = cipher_info
                elif pycrypto_info:
                    pycrypto_vars[name] = pycrypto_info
                elif aead_ctor:
                    aead_vars.add(name)

        children = (ciphers, modes, algorithms, gcm, py_aes)
        for stmt in scope.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit_scope(stmt, tuple(frozenset(s) for s in children))
            elif isinstance(stmt, ast.ClassDef):
                for child in stmt.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        visit_scope(child, tuple(frozenset(s) for s in children))

    visit_scope(tree)
    return sorted(hits)


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
                lines, hash_hits, rsa_sizes, direct_iv = [], _hash_tokens(source), [], []
            else:
                coverage['full_ast_files'] += 1
                lines, hash_hits = _lines(tree), _hash_lines(tree)
                rsa_sizes = _weak_rsa_key_sizes(tree)
                direct_iv = _direct_fixed_iv_nonce(tree)
            if not lines and not hash_hits and not rsa_sizes and not direct_iv:
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
            for line, bits in rsa_sizes:
                finding_id = hashlib.sha1(
                    ('%s|%s|%d' % (rel, RSA_WEAK_KEY_SIZE_RULE, line))
                    .encode('utf-8')).hexdigest()[:12]
                findings.append({
                    'schema_version': '0.1',
                    'finding_id': finding_id,
                    'finding_kind': 'configuration',
                    'rule_id': RSA_WEAK_KEY_SIZE_RULE,
                    'file': rel,
                    'line': line,
                    'algorithm': 'RSA',
                    'algorithm_normalized': 'RSA',
                    'usage': 'unknown',
                    'risk': 'not_applicable',
                    'severity': 'high',
                    'confidence': 0.95,
                    'evidence': [{
                        'tool': TOOL_NAME, 'kind': 'ast', 'lines': [line],
                        'raw': {'rule_id': RSA_WEAK_KEY_SIZE_RULE,
                                'api': 'rsa.generate_private_key',
                                'key_size_bits': bits},
                    }],
                    'evidence_refs': ['E1'],
                    'remediation': {
                        'decided': True, 'reason': 'decided',
                        'source': 'rule-base', 'action': RSA_WEAK_KEY_ACTION,
                        'references': [RSA_KEY_SIZE_REFERENCE],
                    },
                    'tags': ['python-ast', 'weak-rsa-key-size'],
                })
            for rule_id, line, nbytes, api in direct_iv:
                is_cbc = rule_id == FIXED_CBC_IV_RULE
                finding_id = hashlib.sha1(
                    ('%s|%s|%d' % (rel, rule_id, line)).encode('utf-8')).hexdigest()[:12]
                findings.append({
                    'schema_version': '0.1', 'finding_id': finding_id,
                    'finding_kind': 'configuration', 'rule_id': rule_id,
                    'file': rel, 'line': line,
                    'algorithm': 'AES-CBC' if is_cbc else 'AES-GCM',
                    'algorithm_normalized': 'AESCBC' if is_cbc else 'AESGCM',
                    'usage': 'encryption', 'risk': 'not_applicable',
                    'severity': 'high' if is_cbc else 'medium',
                    'confidence': 0.95 if is_cbc else 0.85,
                    'evidence': [{
                        'tool': TOOL_NAME, 'kind': 'ast', 'lines': [line],
                        'raw': {'rule_id': rule_id,
                                'api': api,
                                'literal_bytes': nbytes},
                    }],
                    'evidence_refs': ['E1'],
                    'remediation': {
                        'decided': True, 'reason': 'decided', 'source': 'rule-base',
                        'action': CBC_ACTION if is_cbc else GCM_ACTION,
                        'references': [CBC_REFERENCE if is_cbc else GCM_REFERENCE],
                    },
                    'tags': ['python-ast', 'fixed-iv' if is_cbc else 'fixed-nonce',
                             'runtime-reuse-unverified'],
                })
    if diagnostics is not None:
        diagnostics.update(coverage)
    return findings
