"""Resolve simple Java Properties -> JCE algorithm flows without guessing.

This adapter only handles an explicit, same-file chain:
  properties.load(...getResourceAsStream("name.properties"));
  String algorithm = properties.getProperty("key", "fallback");
  Cipher/MessageDigest.getInstance(algorithm);

The referenced resource basename must be unique in the scanned tree. Complex
classpath rules, runtime overrides, reassignment and unresolved expressions
are intentionally out of scope. The emitted evidence records the Java call
site and resource reference, but never an arbitrary property value/secret.
"""

import os
import re

from scanner.adapters.local_literal import BROKEN_ALGORITHMS
from scanner.normalize import canon_algorithm, norm_algorithm, to_relative_path

_RESOURCE_RE = re.compile(
    r'\b(?P<obj>[A-Za-z_]\w*)\.load\s*\(\s*[^;]{0,1024}?'
    r'getResourceAsStream\s*\(\s*"(?P<file>[^"\n]+\.properties)"\s*\)'
    r'[^;]{0,1024}?\)\s*;', re.S)
_GET_RE = re.compile(
    r'\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<obj>[A-Za-z_]\w*)'
    r'\.getProperty\s*\(\s*"(?P<key>[^"\n]+)"'
    r'(?:\s*,\s*"(?P<fallback>[^"\n]*)")?\s*\)', re.S)
_JCE_RE = re.compile(
    r'\b(?:Cipher|MessageDigest|Mac|KeyGenerator|SecretKeyFactory)'
    r'\s*\.\s*getInstance\s*\(\s*(?P<var>[A-Za-z_]\w*)\s*'
    r'(?:,|\))')
_ASSIGN_RE = re.compile(r'\b{var}\s*=(?!=)')
_MAX_FILE_BYTES = 1024 * 1024


def _without_comments(source):
    """Mask Java comments while preserving strings, length and line offsets."""
    out = list(source)
    state = 'code'
    i = 0
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ''
        if state == 'code':
            if ch == '/' and nxt in ('/', '*'):
                state = 'line' if nxt == '/' else 'block'
                out[i] = out[i + 1] = ' '
                i += 2
                continue
            if ch == '"':
                state = 'string'
            elif ch == "'":
                state = 'char'
        elif state == 'line':
            if ch == '\n':
                state = 'code'
            else:
                out[i] = ' '
        elif state == 'block':
            if ch == '*' and nxt == '/':
                out[i] = out[i + 1] = ' '
                state = 'code'
                i += 2
                continue
            if ch != '\n':
                out[i] = ' '
        else:
            if ch == '\\' and nxt:
                i += 2
                continue
            if (state == 'string' and ch == '"') or (state == 'char' and ch == "'"):
                state = 'code'
        i += 1
    return ''.join(out)


def _property_map(path):
    """Parse only unambiguous single-line Java .properties entries."""
    values = {}
    try:
        if os.path.getsize(path) > _MAX_FILE_BYTES:
            return {}
        with open(path, encoding='iso-8859-1') as stream:
            for line_no, line in enumerate(stream, 1):
                stripped = line.strip()
                if not stripped or stripped[0] in ('#', '!') or stripped.endswith('\\'):
                    continue
                match = re.match(r'^([^=:\s]+)\s*[=:]\s*(.*?)\s*$', stripped)
                if match and '\\' not in match.group(1) + match.group(2):
                    values[match.group(1)] = (match.group(2), line_no)
    except OSError:
        return {}
    return values


def _algorithm(value):
    """Return only recognized crypto algorithms/modes, never arbitrary values."""
    parts = value.split('/')
    head = parts[0].strip()
    if norm_algorithm(head) in BROKEN_ALGORITHMS:
        return head, 'broken'
    if (len(parts) >= 2 and norm_algorithm(head) == 'AES'
            and parts[1].strip().upper() == 'ECB'):
        return 'AES/ECB', 'review'
    return None


def analyze(target):
    """Return (effective-algorithm groups, overridden-default evidence)."""
    target = os.path.abspath(target)
    resources = {}
    java_files = []
    for directory, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if not d.startswith('.')]
        for name in filenames:
            path = os.path.join(directory, name)
            if name.endswith('.properties'):
                resources.setdefault(name, []).append(path)
            elif name.endswith('.java'):
                java_files.append(path)

    groups = {}
    conditional_defaults = []
    for path in java_files:
        try:
            if os.path.getsize(path) > _MAX_FILE_BYTES:
                continue
            with open(path, encoding='utf-8', errors='replace') as stream:
                source = stream.read()
        except OSError:
            continue
        rel = to_relative_path(path, target)
        visible = _without_comments(source)
        loads = {}
        for match in _RESOURCE_RE.finditer(visible):
            literal = match.group('file')
            # Relative classpath subpaths need package-aware resolution; a
            # same-basename guess can silently bind a different resource.
            if '/' in literal or '\\' in literal or '..' in literal:
                continue
            basename = literal
            matches = resources.get(basename, [])
            if len(matches) == 1:
                loads.setdefault(match.group('obj'), []).append(
                    (match.end(), matches[0]))
        if not loads:
            continue

        sinks = list(_JCE_RE.finditer(visible))
        for match in _GET_RE.finditer(visible):
            candidates = [(end, resource) for end, resource
                          in loads.get(match.group('obj'), [])
                          if end < match.start()
                          and '}' not in visible[end:match.start()]]
            if len(candidates) != 1:
                continue
            _load_end, resource = candidates[0]
            props = _property_map(resource)
            key = match.group('key')
            source_value = props.get(key)
            configured = source_value is not None
            if source_value is None:
                fallback = match.group('fallback')
                source_value = (fallback, None) if fallback is not None else None
            if source_value is None:
                continue
            value, resource_line = source_value
            resolved = _algorithm(value)
            fallback_alg = _algorithm(match.group('fallback') or '')
            var = match.group('var')
            for sink in sinks:
                if sink.group('var') != var or sink.start() <= match.end():
                    continue
                # Same variable reassigned between property read and sink:
                # we cannot prove the configured algorithm reaches the API.
                interval = visible[match.end():sink.start()]
                if ('}' in interval or len(interval) > 10000 or
                        re.search(_ASSIGN_RE.pattern.format(var=re.escape(var)),
                                  interval)):
                    continue
                line = source.count('\n', 0, sink.start()) + 1
                property_line = source.count('\n', 0, match.start()) + 1
                resource_file = to_relative_path(resource, target)
                if resolved is not None:
                    display, risk = resolved
                    alg_norm = canon_algorithm(display)
                    group_key = (rel, alg_norm)
                    group = groups.setdefault(group_key, {
                        'tool': 'local-literal', 'file': rel,
                        'alg_norm': alg_norm, 'algorithm': display,
                        'usage': 'unknown', 'lines': set(),
                        'severity': None, 'confidence': None, 'risk': risk,
                        'risk_types': [], 'quantum_as_seen': [],
                        'raw': {
                            'kind': 'java-properties-flow',
                            'resource_file': resource_file,
                            'property_key': key,
                            'resource_line': resource_line,
                            'resolved_algorithm': display,
                        },
                    })
                    group['lines'].add(line)
                if (configured and fallback_alg is not None and
                        (resolved is None or
                         canon_algorithm(resolved[0]) !=
                         canon_algorithm(fallback_alg[0]))):
                    conditional_defaults.append({
                        'file': rel,
                        'alg_norm': canon_algorithm(fallback_alg[0]),
                        'lines': [property_line, line],
                        'resource_file': resource_file,
                        'resource_line': resource_line,
                        'property_key': key,
                    })
    for group in groups.values():
        group['lines'] = sorted(group['lines'])
    return list(groups.values()), conditional_defaults


def scan(target):
    """Existing ToolGroup-only interface, for callers needing no override data."""
    return analyze(target)[0]
