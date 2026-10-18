"""Check three anonymous semifinal submission candidates before human review.

This is deliberately separate from the runtime preflight. It does not upload,
modify, or print the content of any candidate. Image pixels and unknown personal
names still require a human anonymity review.
"""

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET


PREFIX = 'AI-CryptoGuard/'
IDENTITY = (
    re.compile(r'Rant[-_ ]?yang|Alanxbr|BQ[-_]?park', re.I),
    re.compile(r'C:[\\/]Users[\\/][^\\/\s"\x27<>]+', re.I),
)
FORBIDDEN_PATH = re.compile(
    r'(^|/)(?:\.git|workspace|out|_smoke|_anon|labels|node_modules|__pycache__)/', re.I)
FORBIDDEN_SUFFIX = ('.jar', '.exe', '.dll', '.class', '.pyc', '.map.json')
DOCX_NS = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
PPT_NS = {'p': 'http://schemas.openxmlformats.org/presentationml/2006/main',
          'a': 'http://schemas.openxmlformats.org/drawingml/2006/main'}


def _text_xml(data):
    root = ET.fromstring(data)
    return ''.join(root.itertext())


def _has_identity(text):
    return any(pattern.search(text) for pattern in IDENTITY)


def _office(path, kind, number=None, draft=False):
    problems = []
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            problems.append('damaged-office-zip')
        names = set(archive.namelist())
        if 'docProps/custom.xml' in names or any(
                n.startswith('customXml/') for n in names):
            problems.append('hidden-custom-properties')
        if kind == 'report' and 'word/document.xml' not in names:
            problems.append('missing-report-document')
        if kind == 'slides' and not any(n.startswith('ppt/slides/slide') and
                                     n.endswith('.xml') for n in names):
            problems.append('missing-slides')
        # PptxGenJS creates empty notes parts with generated slide numbers.
        # Reject actual note text, not the empty container itself.
        if kind == 'slides':
            for name in names:
                if not re.fullmatch(r'ppt/notesSlides/notesSlide\d+\.xml', name):
                    continue
                root = ET.fromstring(archive.read(name))
                for shape in root.findall('.//p:sp', PPT_NS):
                    ph = shape.find('./p:nvSpPr/p:nvPr/p:ph', PPT_NS)
                    if ph is not None and ph.get('type') == 'sldNum':
                        continue
                    if any((t.text or '').strip() for t in
                           shape.findall('.//a:t', PPT_NS)):
                        problems.append('slide-notes-content')
                        break
        for name in names:
            if not name.endswith(('.xml', '.rels')):
                continue
            text = archive.read(name).decode('utf-8', errors='replace')
            if _has_identity(text):
                problems.append('identity-marker:' + name)
        if kind == 'report' and 'word/document.xml' in names:
            text = _text_xml(archive.read('word/document.xml'))
            if '提交作品时请将此段落文字删除' in text:
                problems.append('template-warning-present')
            placeholder = '【待填系统编号】' in text
            if draft:
                if not placeholder:
                    problems.append('draft-number-placeholder-missing')
            elif placeholder or not number or number not in text:
                problems.append('final-number-missing-or-placeholder')
    return problems


def _source(path):
    problems = []
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            problems.append('damaged-source-zip')
        names = archive.namelist()
        if len(names) != len(set(names)):
            problems.append('duplicate-source-member')
        manifest_name = PREFIX + 'RELEASE_MANIFEST.json'
        if manifest_name not in names:
            return problems + ['missing-manifest']
        manifest = json.loads(archive.read(manifest_name))
        if manifest.get('format') != 'AI-CryptoGuard-anonymous-source-v1':
            problems.append('not-anonymous-source-format')
        expected = manifest.get('files', {})
        actual = {n[len(PREFIX):] for n in names if n.startswith(PREFIX) and
                  n != manifest_name and not n.endswith('/')}
        if actual != set(expected):
            problems.append('source-member-list-mismatch')
        for name in names:
            if name == manifest_name:
                continue
            if (not name.startswith(PREFIX) or '..' in Path(name).parts or
                    '\\' in name or FORBIDDEN_PATH.search(name) or
                    name.lower().endswith(FORBIDDEN_SUFFIX)):
                problems.append('forbidden-source-member')
                continue
            rel = name[len(PREFIX):]
            data = archive.read(name)
            if hashlib.sha256(data).hexdigest() != expected.get(rel):
                problems.append('source-hash-mismatch:' + rel)
            if name.endswith(('.py', '.js', '.json', '.md', '.html', '.yaml', '.yml', '.txt')):
                if _has_identity(data.decode('utf-8', errors='replace')):
                    problems.append('identity-marker:' + rel)
        if PREFIX + 'README.md' not in names:
            problems.append('missing-anonymous-readme')
        if PREFIX + 'core/pipeline.py' not in names:
            problems.append('missing-entry-point')
    return problems


def _support(path, slides, source, number):
    """Verify the single upload attachment contains the reviewed exact inputs."""
    problems = []
    expected_name = number + '-2026密码竞赛复赛相关支撑材料.zip'
    if path.name != expected_name:
        problems.append('wrong-support-filename')
    if path.stat().st_size > 4 * 1024 ** 3:
        problems.append('support-over-4gb')
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            problems.append('damaged-support-zip')
        expected = {'答辩演示.pptx', '匿名源码.zip', 'MANIFEST.json'}
        if set(archive.namelist()) != expected or len(archive.namelist()) != 3:
            return problems + ['unexpected-support-members']
        manifest = json.loads(archive.read('MANIFEST.json'))
        if (manifest.get('format') != 'AI-CryptoGuard-anonymous-support-v1' or
                manifest.get('number') != number or
                set(manifest.get('files', {})) != expected - {'MANIFEST.json'}):
            problems.append('support-manifest-invalid')
        for name, original in (('答辩演示.pptx', slides), ('匿名源码.zip', source)):
            data = archive.read(name)
            item = manifest.get('files', {}).get(name, {})
            if (item.get('sha256') != hashlib.sha256(data).hexdigest() or
                    item.get('bytes') != len(data) or
                    data != Path(original).read_bytes()):
                problems.append('support-member-mismatch:' + name)
    return problems


def audit(report, slides, source, number=None, draft=False, support=None):
    if not draft and not number:
        raise ValueError('Final audit requires --number from the contest platform')
    if number and not re.fullmatch(r'[A-Za-z0-9-]{1,40}', number):
        raise ValueError('Unexpected project number format; verify platform value')
    paths = {'report': Path(report), 'slides': Path(slides), 'source': Path(source)}
    results = {}
    for kind, path in paths.items():
        if not path.is_file():
            results[kind] = ['missing-file']
            continue
        try:
            results[kind] = (_source(path) if kind == 'source' else
                             _office(path, kind, number=number, draft=draft))
        except (OSError, ValueError, KeyError, ET.ParseError, zipfile.BadZipFile):
            results[kind] = ['unreadable-or-invalid-container']
    if not draft:
        expected_report = number + '-2026密码竞赛复赛作品设计报告.docx'
        if paths['report'].name != expected_report:
            results['report'].append('wrong-report-filename')
    if support is not None:
        path = Path(support)
        if not path.is_file():
            results['support'] = ['missing-file']
        elif not number:
            results['support'] = ['number-required-for-support']
        else:
            try:
                results['support'] = _support(path, slides, source, number)
            except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile):
                results['support'] = ['unreadable-or-invalid-support']
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True)
    parser.add_argument('--slides', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--support', help='Single attachment built by setup/support_bundle.py')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--draft', action='store_true')
    mode.add_argument('--number')
    args = parser.parse_args(argv)
    results = audit(args.report, args.slides, args.source,
                    number=args.number, draft=args.draft, support=args.support)
    print(json.dumps({'mode': 'draft' if args.draft else 'final',
                      'checks': {k: ('PASS' if not v else v)
                                 for k, v in results.items()},
                      'overall': 'PASS' if all(not v for v in results.values()) else 'FAIL'},
                     ensure_ascii=False, indent=2))
    return 0 if all(not v for v in results.values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
