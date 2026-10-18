"""Independent rejection fixtures for the submission material gate."""

import hashlib
import json
import tempfile
import zipfile
from pathlib import Path

from setup.submission_audit import PREFIX, audit


def _zip(path, members):
    with zipfile.ZipFile(path, 'w') as archive:
        for name, data in members.items():
            archive.writestr(name, data)


def _source(path, bad_hash=False, forbidden=False):
    files = {
        'README.md': b'Anonymous source',
        'core/pipeline.py': b'print("ok")',
    }
    if forbidden:
        files['out/raw.json'] = b'{}'
    manifest = {
        'format': 'AI-CryptoGuard-anonymous-source-v1',
        'files': {k: hashlib.sha256(v).hexdigest() for k, v in files.items()},
    }
    if bad_hash:
        manifest['files']['core/pipeline.py'] = '0' * 64
    _zip(path, {**{PREFIX + k: v for k, v in files.items()},
                PREFIX + 'RELEASE_MANIFEST.json': json.dumps(manifest)})


def main():
    with tempfile.TemporaryDirectory(prefix='acg-submission-audit-') as tmp:
        root = Path(tmp)
        report, slides, source = [root / x for x in ('report.docx', 'slides.pptx', 'source.zip')]
        _zip(report, {'word/document.xml':
             '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
             '<w:t>【待填系统编号】</w:t></w:document>'})
        _zip(slides, {'ppt/slides/slide1.xml': '<slide>Title</slide>'})
        _source(source)
        clean = audit(report, slides, source, draft=True)
        assert all(not problems for problems in clean.values()), clean
        assert 'final-number-missing-or-placeholder' in audit(
            report, slides, source, number='TEST-123')['report']
        _zip(report, {'word/document.xml':
             '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
             '<w:t>TEST-123</w:t></w:document>',
             'docProps/core.xml': '<core>Rant-yang</core>'})
        assert any(x.startswith('identity-marker:') for x in
                   audit(report, slides, source, number='TEST-123')['report'])
        _zip(slides, {'ppt/slides/slide1.xml': '<slide>Title</slide>',
                      'ppt/notesSlides/notesSlide1.xml':
                      '<p:notes xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
                      'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
                      '<p:sp><p:nvSpPr><p:nvPr><p:ph type="body"/></p:nvPr></p:nvSpPr>'
                      '<p:txBody><a:t>secret note</a:t></p:txBody></p:sp></p:notes>'})
        assert 'slide-notes-content' in audit(report, slides, source,
                                              number='TEST-123')['slides']
        _source(source, bad_hash=True)
        assert 'source-hash-mismatch:core/pipeline.py' in audit(
            report, slides, source, number='TEST-123')['source']
        _source(source, forbidden=True)
        assert 'forbidden-source-member' in audit(
            report, slides, source, number='TEST-123')['source']
    print('PASS: submission audit accepts draft and rejects wrong number, '
          'identity, hidden notes, source tampering and forbidden outputs')


if __name__ == '__main__':
    main()
