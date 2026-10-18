"""Attach bounded Java JCA consumer evidence to an existing Finding.

This is a source-side evidence bridge, not a dataflow proof or new detector.
Only a literal algorithm argument to Signature/KeyAgreement.getInstance or
AES/ECB Cipher.getInstance is accepted. The source text is never copied into
the Finding or cloud payload. Cipher.init(ENCRYPT_MODE) proves configuration,
not execution of doFinal or runtime reachability.
"""
import re
from pathlib import Path


_CALL = re.compile(
    r'\b(?P<api>Signature|KeyAgreement)\s*\.\s*getInstance\s*\('
    r'\s*"(?P<literal>[A-Za-z0-9_-]{2,60})"\s*[,)]', re.S)
_CIPHER_CALL = re.compile(
    r'\bCipher\s*\.\s*getInstance\s*\(\s*'
    r'"(?P<literal>[A-Za-z0-9_-]+/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)?)"\s*[,)]', re.S)
_SIGNATURE = ('ED25519', 'ECDSA', 'RSA', 'DSA')
_AGREEMENT = {'ECDH': 'ECDH', 'DH': 'DH', 'X25519': 'X25519'}


def _without_comments(src):
    """Space comments; retain offsets and mark only code character positions."""
    out, code_at, i, mode = [], [], 0, 'code'
    while i < len(src):
        ch = src[i]
        nxt = src[i + 1] if i + 1 < len(src) else ''
        if mode == 'code':
            if ch == '/' and nxt == '/':
                out.extend('  ')
                code_at.extend((False, False))
                i += 2
                mode = 'line'
                continue
            if ch == '/' and nxt == '*':
                out.extend('  ')
                code_at.extend((False, False))
                i += 2
                mode = 'block'
                continue
            if src.startswith('"""', i):
                out.extend('"""')
                code_at.extend((False, False, False))
                i += 3
                mode = 'text_block'
                continue
            if ch in ('"', "'"):
                mode = ch
                code_at.append(False)
            else:
                code_at.append(True)
            out.append(ch)
        elif mode == 'line':
            out.append('\n' if ch == '\n' else ' ')
            code_at.append(False)
            if ch == '\n':
                mode = 'code'
        elif mode == 'block':
            if ch == '*' and nxt == '/':
                out.extend('  ')
                code_at.extend((False, False))
                i += 2
                mode = 'code'
                continue
            out.append('\n' if ch == '\n' else ' ')
            code_at.append(False)
        elif mode == 'text_block':
            if src.startswith('"""', i):
                out.extend('"""')
                code_at.extend((False, False, False))
                i += 3
                mode = 'code'
                continue
            out.append(ch)
            code_at.append(False)
        else:
            out.append(ch)
            code_at.append(False)
            if ch == '\\' and i + 1 < len(src):
                out.append(src[i + 1])
                code_at.append(False)
                i += 2
                continue
            if ch == mode:
                mode = 'code'
        i += 1
    return ''.join(out), code_at


def _consumer_hits(src):
    clean, code_at = _without_comments(src)
    for match in _CALL.finditer(clean):
        if not code_at[match.start()]:
            continue
        token = match.group('literal').upper().replace('-', '').replace('_', '')
        api = match.group('api')
        if api == 'Signature':
            names = [name for name in _SIGNATURE if token.endswith(name)]
            if len(names) != 1:
                continue
            algorithm, usage = names[0], 'signing'
        else:
            algorithm = _AGREEMENT.get(token)
            if algorithm is None:
                continue
            usage = 'key_exchange'
        yield algorithm, usage, api + '.getInstance', clean.count('\n', 0, match.start()) + 1
        # A second fact is emitted only when the *same local variable*
        # receives the provider and is subsequently initialized and consumed
        # before the next closing brace. This is bounded lexical evidence,
        # not an interprocedural dataflow proof.
        prefix = clean[max(0, match.start() - 100):match.start()]
        binding = re.search(r'\b' + api + r'\s+([A-Za-z_]\w*)\s*=\s*$', prefix)
        tail = clean[match.end():match.end() + 2000]
        end = tail.find('}')
        if binding is None or end < 0:
            continue
        tail = tail[:end]
        variable = re.escape(binding.group(1))
        methods = (('initSign', 'sign') if api == 'Signature'
                   else ('init', 'doPhase', 'generateSecret'))
        occurrences = [re.search(r'\b' + variable + r'\s*\.\s*' + method +
                                 r'\s*\(', tail) for method in methods]
        if all(occurrences) and all(a.start() < b.start()
                                    for a, b in zip(occurrences, occurrences[1:])):
            consumed = occurrences[-1]
            line = clean.count('\n', 0, match.end() + consumed.start()) + 1
            yield algorithm, usage, api + '.' + methods[-1], line

    # This source-side bridge only asserts that a single local Cipher is
    # configured for encryption.  It does not claim doFinal runs, that the
    # branch is feasible, or that interprocedural aliases point to this value.
    for match in _CIPHER_CALL.finditer(clean):
        if not code_at[match.start()]:
            continue
        parts = match.group('literal').upper().split('/')
        if parts[:2] != ['AES', 'ECB']:
            continue
        yield 'AESECB', 'encryption', 'Cipher.getInstance', clean.count('\n', 0, match.start()) + 1
        prefix = clean[max(0, match.start() - 100):match.start()]
        binding = re.search(r'\bCipher\s+([A-Za-z_]\w*)\s*=\s*$', prefix)
        tail = clean[match.end():match.end() + 2000]
        end = tail.find('}')
        if binding is None or end < 0:
            continue
        tail = tail[:end]
        variable = re.escape(binding.group(1))
        init_re = re.compile(r'\b' + variable +
                             r'\s*\.\s*init\s*\(\s*Cipher\s*\.\s*ENCRYPT_MODE\b')
        init = next((hit for hit in init_re.finditer(tail)
                     if code_at[match.end() + hit.start()]), None)
        if init is None:
            continue
        line = clean.count('\n', 0, match.end() + init.start()) + 1
        yield 'AESECB', 'encryption', 'Cipher.init(ENCRYPT_MODE)', line


def attach_java_consumers(rows, source_root):
    """Append safe consumer evidence to same-file, same-algorithm findings.

    Returns the number of evidence entries appended. Findings and IDs are not
    reclassified or merged; an unmatched consumer does not create a finding.
    """
    if not source_root:
        return 0
    root = Path(source_root).resolve()
    if not root.is_dir():
        return 0
    by_file = {}
    for finding in rows:
        rel = Path(str(finding.get('file') or ''))
        if rel.is_absolute() or '..' in rel.parts or rel.suffix.lower() != '.java':
            continue
        by_file.setdefault(rel, []).append(finding)
    added = 0
    for rel, findings in by_file.items():
        path = (root / rel).resolve()
        if not path.is_relative_to(root) or not path.is_file() or path.stat().st_size > 2_000_000:
            continue
        hits = list(_consumer_hits(path.read_text(encoding='utf-8', errors='replace')))
        for algorithm, usage, api, line in hits:
            for finding in findings:
                if finding.get('algorithm_normalized') != algorithm:
                    continue
                if finding.get('usage', 'unknown') not in ('unknown', usage):
                    continue
                evidence = finding.setdefault('evidence', [])
                anchor_lines = [n for ev in evidence for n in ev.get('lines', [])
                                if isinstance(n, int)]
                if not anchor_lines or min(abs(n - line) for n in anchor_lines) > 20:
                    continue
                if any((e.get('raw') or {}).get('kind') == 'java-jca-consumer' and
                       e.get('lines') == [line] and
                       (e.get('raw') or {}).get('api') == api for e in evidence):
                    continue
                evidence.append({
                    'tool': 'local-literal', 'kind': 'pattern', 'lines': [line],
                    'raw': {'kind': 'java-jca-consumer', 'api': api,
                            'algorithm': algorithm, 'usage': usage},
                })
                added += 1
    return added
