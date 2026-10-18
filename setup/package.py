"""Build a source-only submission candidate from committed HEAD.

No third-party scanner binaries, user uploads, scan output, benchmark copies,
or local environment files are read. The archive is deterministic for a commit.
"""
import argparse
import hashlib
import io
import json
import os
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


def build(output):
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
            if info.filename in entries:
                raise ValueError('Duplicate release member: ' + info.filename)
            if info.file_size > 5 * 1024 * 1024:
                raise ValueError('Release member exceeds 5 MiB: ' + info.filename)
            entries[info.filename] = archive.read(info)
    if sum(len(data) for data in entries.values()) > 30 * 1024 * 1024:
        raise ValueError('Source release exceeds 30 MiB')
    if not REQUIRED.issubset(entries):
        raise ValueError('Release missing required files: %s' %
                         ', '.join(sorted(REQUIRED - entries.keys())))
    if 'RELEASE_MANIFEST.json' in entries:
        raise ValueError('Committed RELEASE_MANIFEST.json conflicts with generated manifest')
    manifest = {
        'format': 'AI-CryptoGuard-source-release-v1',
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
    args = parser.parse_args(argv)
    print(json.dumps(build(args.output), ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
