"""Submission candidate must be deterministic and contain only reviewed source."""
import hashlib
import json
import posixpath
import re
import tempfile
import zipfile
from pathlib import Path

from setup.package import PREFIX, _anonymous_audit, _check_member, build


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
    try:
        _anonymous_audit({'README.md': b'Rant-yang'})
        raise AssertionError('anonymous identity marker accepted')
    except ValueError:
        pass
    with tempfile.TemporaryDirectory(prefix='acg-package-test-') as temp:
        first = Path(temp) / 'first.zip'
        second = Path(temp) / 'second.zip'
        anonymous = Path(temp) / 'anonymous.zip'
        anonymous_repeat = Path(temp) / 'anonymous-repeat.zip'
        a, b = build(first), build(second)
        c, d = (build(anonymous, anonymous=True),
                build(anonymous_repeat, anonymous=True))
        assert a['sha256'] == b['sha256']
        assert c['sha256'] == d['sha256']
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
        with zipfile.ZipFile(anonymous) as archive:
            names = set(archive.namelist())
            manifest = json.loads(archive.read(PREFIX + 'RELEASE_MANIFEST.json'))
            assert manifest['format'] == 'AI-CryptoGuard-anonymous-source-v1'
            assert manifest['commit'] == c['commit']
            assert PREFIX + 'docs/会议文档_2026-09-29.md' not in names
            assert PREFIX + 'docs/作品说明书_候选版_2026-10-18.md' not in names
            assert PREFIX + 'core/pipeline.py' in names
            assert PREFIX + 'scanner/runners/crysentry.py' in names
            assert PREFIX + 'docs/第三方来源与分发边界.md' in names
            assert PREFIX + 'setup/submission_readme.md' not in names
            assert PREFIX + 'setup/submission_audit_selftest.py' not in names
            assert PREFIX + 'setup/submission_audit.py' not in names
            assert PREFIX + 'setup/support_bundle.py' not in names
            assert PREFIX + 'setup/prepare_submission.py' not in names
            assert PREFIX + 'setup/prepare_submission_selftest.py' not in names
            readme = archive.read(PREFIX + 'README.md').decode('utf-8')
            assert 'Rant-yang' not in readme
            assert '第三方' in readme
            for name in names:
                if not name.endswith('.md'):
                    continue
                text = archive.read(name).decode('utf-8')
                for target in re.findall(r'(?<!!)\[[^\]]+\]\(([^)]+)\)', text):
                    if target.startswith(('http:', 'https:', 'mailto:', '#')):
                        continue
                    rel = target.split('#', 1)[0]
                    resolved = posixpath.normpath(posixpath.join(
                        posixpath.dirname(name), rel))
                    assert not rel or resolved in names or any(
                        member.startswith(resolved.rstrip('/') + '/')
                        for member in names), (name, target)
            for name, expected in manifest['files'].items():
                assert hashlib.sha256(archive.read(PREFIX + name)).hexdigest() == expected
    print('PASS: deterministic source-only and anonymous releases, checksums and path exclusions')


if __name__ == '__main__':
    main()
