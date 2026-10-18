"""Build a source-only submission candidate from committed HEAD.

No third-party scanner binaries, user uploads, scan output, benchmark copies,
or local environment files are read. The archive is deterministic for a commit.
"""
import argparse
import hashlib
import io
import json
import os
import posixpath
import re
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parent.parent
PREFIX = 'AI-CryptoGuard/'
FORBIDDEN_DIRS = frozenset({
    'workspace', 'out', '_smoke', 'tools', 'crysentry', 'cryptoscan',
    'cbom-scan', 'jdk', 'jdk17', 'node_modules', '.venv', 'venv',
    '__pycache__', 'build', 'dist', '.git',
})
FORBIDDEN_SUFFIXES = ('.jar', '.exe', '.dll', '.class', '.pyc', '.zip',
                      '.tar', '.gz', '.map.json')
REQUIRED = frozenset({'README.md', 'core/pipeline.py', 'core/report.py',
                      'web/index.html', 'setup/README.md',
                      'docs/第三方来源与分发边界.md'})
ANONYMOUS_DIRS = frozenset({
    'ai', 'benchmark', 'core', 'examples', 'repair', 'scanner', 'setup', 'web',
})
ANONYMOUS_DOCS = frozenset({
    'docs/用户手册.md', 'docs/性能与评测口径.md',
    'docs/第三方来源与分发边界.md',
})
ANONYMOUS_ROOT = frozenset({'.dockerignore', '.gitignore', 'compose.yaml'})
ANONYMOUS_README = 'setup/submission_readme.md'
ANONYMOUS_EXCLUDE = frozenset({
    'setup/package.py', 'setup/package_selftest.py',
    'setup/submission_audit.py', 'setup/submission_audit_selftest.py',
    'setup/support_bundle.py',
})
# Strong, reviewable tripwires for this repository's known team and local
# account identifiers. These are not a substitute for a human anonymity check.
IDENTITY_PATTERNS = (
    re.compile(r'Rant[-_ ]?yang|Alanxbr|BQ[-_]?park', re.I),
    re.compile(r'C:[\\/]Users[\\/][^\\/\s"\x27<>]+', re.I),
)


def _anonymous_member(name):
    if name in ANONYMOUS_EXCLUDE:
        return False
    if name in ANONYMOUS_ROOT or name in ANONYMOUS_DOCS:
        return True
    return name.split('/', 1)[0] in ANONYMOUS_DIRS


def _anonymous_audit(entries):
    hits = []
    for name, data in entries.items():
        if name.lower().endswith(('.pptx', '.pdf', '.png', '.jpg', '.jpeg')):
            continue  # binary artifacts require separate metadata/pixel review
        content = data.decode('utf-8', errors='ignore')
        if any(pattern.search(content) for pattern in IDENTITY_PATTERNS):
            hits.append(name)
    if hits:
        raise ValueError('Anonymous archive contains identity/local-account '
                         'markers in: ' + ', '.join(sorted(hits)))


_MD_LINK = re.compile(r'(?<!!)\[([^\]]+)\]\(([^)]+)\)')


def _strip_missing_local_links(entries):
    """Keep a curated archive readable without pointing to omitted records."""
    available = set(entries)
    for name, data in list(entries.items()):
        if not name.lower().endswith('.md'):
            continue
        content = data.decode('utf-8')
        def replace(match):
            label, target = match.groups()
            if target.startswith(('http:', 'https:', 'mailto:', '#')):
                return match.group(0)
            path = target.split('#', 1)[0]
            resolved = posixpath.normpath(posixpath.join(
                posixpath.dirname(name), path))
            if not path or resolved in available or any(
                    item.startswith(resolved.rstrip('/') + '/') for item in available):
                return match.group(0)
            return label
        entries[name] = _MD_LINK.sub(replace, content).encode('utf-8')


def _check_member(name, info):
    path = PurePosixPath(name)
    parts = tuple(part.lower() for part in path.parts)
    if (not name or path.is_absolute() or '..' in path.parts or
            any(':' in part or '\\' in part for part in path.parts) or
            (len(parts) >= 2 and parts[0] == 'benchmark' and
             parts[1] in ('labels', '_anon')) or
            any(part in FORBIDDEN_DIRS or part.startswith('.env')
                for part in parts) or
            name.lower().endswith(FORBIDDEN_SUFFIXES)):
        raise ValueError('Unsafe release member: ' + name)
    if stat.S_ISLNK(info.external_attr >> 16):
        raise ValueError('Symlink in release archive: ' + name)


def _git(*args):
    result = subprocess.run(['git', *args], cwd=ROOT, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError('Git cannot read committed HEAD; release not created')
    return result.stdout


def build(output, anonymous=False):
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError('Refusing to overwrite existing release: %s' % output)
    commit = _git('rev-parse', 'HEAD').decode('ascii').strip()
    source = _git('archive', '--format=zip', 'HEAD')
    entries = {}
    with zipfile.ZipFile(io.BytesIO(source)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            _check_member(info.filename, info)
            if anonymous and not _anonymous_member(info.filename):
                continue
            if info.filename in entries:
                raise ValueError('Duplicate release member: ' + info.filename)
            if info.file_size > 5 * 1024 * 1024:
                raise ValueError('Release member exceeds 5 MiB: ' + info.filename)
            entries[info.filename] = archive.read(info)
    if anonymous:
        if ANONYMOUS_README not in entries:
            raise ValueError('Missing anonymous submission README')
        entries['README.md'] = entries.pop(ANONYMOUS_README)
        _strip_missing_local_links(entries)
        _anonymous_audit(entries)
    if sum(len(data) for data in entries.values()) > 30 * 1024 * 1024:
        raise ValueError('Source release exceeds 30 MiB')
    if not REQUIRED.issubset(entries):
        raise ValueError('Release missing required files: %s' %
                         ', '.join(sorted(REQUIRED - entries.keys())))
    if 'RELEASE_MANIFEST.json' in entries:
        raise ValueError('Committed RELEASE_MANIFEST.json conflicts with generated manifest')
    manifest = {
        'format': ('AI-CryptoGuard-anonymous-source-v1' if anonymous
                   else 'AI-CryptoGuard-source-release-v1'),
        'commit': commit,
        'distribution': 'our source only; scanners and benchmarks are external',
        'files': {name: hashlib.sha256(data).hexdigest()
                  for name, data in sorted(entries.items())},
    }
    entries['RELEASE_MANIFEST.json'] = (json.dumps(manifest, ensure_ascii=False,
                                                  sort_keys=True, indent=2) + '\n').encode('utf-8')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix='acg-release-', suffix='.zip',
                                     dir=output.parent, delete=False) as stream:
        temp = Path(stream.name)
    try:
        with zipfile.ZipFile(temp, 'w', compression=zipfile.ZIP_DEFLATED,
                             compresslevel=9) as archive:
            for name, data in sorted(entries.items()):
                item = zipfile.ZipInfo(PREFIX + name, (1980, 1, 1, 0, 0, 0))
                item.compress_type = zipfile.ZIP_DEFLATED
                item.external_attr = 0o644 << 16
                archive.writestr(item, data, compress_type=zipfile.ZIP_DEFLATED,
                                 compresslevel=9)
        os.replace(temp, output)
    finally:
        if temp.exists():
            temp.unlink()
    return {'path': str(output), 'commit': commit, 'files': len(entries),
            'sha256': hashlib.sha256(output.read_bytes()).hexdigest()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-o', '--output', required=True)
    parser.add_argument('--anonymous', action='store_true',
                        help='Build an identity-audited, curated source package for anonymous review')
    args = parser.parse_args(argv)
    print(json.dumps(build(args.output, anonymous=args.anonymous),
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
