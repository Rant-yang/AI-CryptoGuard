"""Build one anonymous support attachment from reviewed slides and source.

The output is a ZIP containing only the presentation, the anonymous source
archive, and a small manifest. It is deliberately separate from the signed
approval page and the anonymous design report.
"""

import argparse
import hashlib
import json
import os
import re
import tempfile
import zipfile
from pathlib import Path

if __package__:
    from .submission_audit import _office, _source
else:
    from submission_audit import _office, _source


MEMBERS = ('答辩演示.pptx', '匿名源码.zip')


def build(slides, source, output, number):
    if not re.fullmatch(r'[A-Za-z0-9-]{1,40}', number):
        raise ValueError('Unexpected project number format; verify platform value')
    paths = (Path(slides), Path(source))
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError('Refusing to overwrite existing support bundle')
    if not all(path.is_file() for path in paths):
        raise FileNotFoundError('Slides or anonymous source archive is missing')
    checks = (_office(paths[0], 'slides'), _source(paths[1]))
    if any(checks):
        raise ValueError('Input failed anonymity/source audit: ' + repr(checks))
    payloads = {name: path.read_bytes() for name, path in zip(MEMBERS, paths)}
    manifest = {
        'format': 'AI-CryptoGuard-anonymous-support-v1',
        'number': number,
        'files': {name: {'sha256': hashlib.sha256(data).hexdigest(),
                         'bytes': len(data)} for name, data in payloads.items()},
    }
    payloads['MANIFEST.json'] = (json.dumps(manifest, ensure_ascii=False,
                                            sort_keys=True, indent=2) + '\n').encode('utf-8')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix='acg-support-', suffix='.zip',
                                     dir=output.parent, delete=False) as stream:
        temp = Path(stream.name)
    try:
        with zipfile.ZipFile(temp, 'w', compression=zipfile.ZIP_DEFLATED,
                             compresslevel=9) as archive:
            for name, data in sorted(payloads.items()):
                item = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                item.compress_type = zipfile.ZIP_DEFLATED
                item.external_attr = 0o644 << 16
                archive.writestr(item, data, compress_type=zipfile.ZIP_DEFLATED,
                                 compresslevel=9)
        os.replace(temp, output)
    finally:
        if temp.exists():
            temp.unlink()
    return {'path': str(output), 'bytes': output.stat().st_size,
            'sha256': hashlib.sha256(output.read_bytes()).hexdigest()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--number', required=True)
    parser.add_argument('--slides', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('-o', '--output', required=True)
    args = parser.parse_args(argv)
    print(json.dumps(build(args.slides, args.source, args.output, args.number),
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
