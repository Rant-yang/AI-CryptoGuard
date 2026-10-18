"""Submission candidate must be deterministic and contain only reviewed source."""
import hashlib
import json
import tempfile
import zipfile
from pathlib import Path

from setup.package import PREFIX, _check_member, build


def main():
    for path in ('../escape.txt', '.env', 'workspace/secret.py',
                 'Workspace/secret.py',
                 'out/findings.json', 'CrySentry/a.py', 'deps/a.jar',
                 'benchmark/labels/a.json'):
        try:
            _check_member(path, zipfile.ZipInfo(path))
            raise AssertionError('unsafe member accepted: ' + path)
        except ValueError:
            pass
    with tempfile.TemporaryDirectory(prefix='acg-package-test-') as temp:
        first = Path(temp) / 'first.zip'
        second = Path(temp) / 'second.zip'
        a, b = build(first), build(second)
        assert a['sha256'] == b['sha256']
        with zipfile.ZipFile(first) as archive:
            names = set(archive.namelist())
            manifest = json.loads(archive.read(PREFIX + 'RELEASE_MANIFEST.json'))
            assert manifest['commit'] == a['commit']
            assert PREFIX + 'docs/第三方来源与分发边界.md' in names
            assert all(not n.startswith(PREFIX + 'workspace/') for n in names)
            assert all(not n.startswith(PREFIX + 'out/') for n in names)
            assert all(not n.endswith('.jar') for n in names)
            for name, expected in manifest['files'].items():
                assert hashlib.sha256(archive.read(PREFIX + name)).hexdigest() == expected
    print('PASS: deterministic source-only release, checksums and path exclusions')


if __name__ == '__main__':
    main()
