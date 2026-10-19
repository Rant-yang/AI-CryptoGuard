"""Cover regression: preserve the official issuing body and a single date."""
import tempfile
from pathlib import Path

from docx import Document

from docs.build_submission_report import PLACEHOLDER, build


def fixture(path, duplicate_date=False):
    doc = Document()
    for i in range(23):
        value = ('作品编号：' if i == 0 else
                 '2026年10月' if i == 21 else
                 '中国密码学会' if i == 22 else
                 '2026 年 10 月' if i == 20 and duplicate_date else '')
        doc.add_paragraph(value)
    doc.add_table(rows=6, cols=1)
    doc.save(path)


def main():
    with tempfile.TemporaryDirectory(prefix='acg-report-cover-') as temp:
        root = Path(temp)
        template = root / 'template.docx'
        output = root / 'candidate.docx'
        fixture(template)
        build(template, output, PLACEHOLDER)
        cover = Document(output).paragraphs[:23]
        assert cover[21].text == '2026 年 10 月'
        assert cover[22].text == '中国密码学会'
        assert sum('年' in p.text and '月' in p.text for p in cover) == 1

        duplicate = root / 'ambiguous.docx'
        fixture(duplicate, duplicate_date=True)
        try:
            build(duplicate, root / 'must-not-exist.docx', PLACEHOLDER)
        except ValueError as exc:
            assert 'exactly one date' in str(exc)
        else:
            raise AssertionError('Ambiguous cover date unexpectedly accepted')
    print('PASS: report cover retains issuing body and one date')


if __name__ == '__main__':
    main()
