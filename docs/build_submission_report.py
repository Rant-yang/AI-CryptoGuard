"""Fill the official 2026 semifinal DOCX template from the reviewed report draft.

The official template is supplied by the contest and stays outside Git. A
draft uses a conspicuous number placeholder; a final build requires the
platform-assigned work number. Neither mode inserts team identity fields.
Requires python-docx. The result still needs a human page-layout review.
"""
import argparse
import os
import re
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from docx import Document
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'docs' / '作品说明书_候选版_2026-10-18.md'
TITLE = '基于多源证据融合与大模型推理的智能密码安全审计与抗量子迁移系统'
PLACEHOLDER = '【待填系统编号】'
LINK = re.compile(r'\[([^]]+)\]\([^)]+\)')


def clean(text):
    text = LINK.sub(r'\1', text)
    return text.replace('**', '').replace('`', '').strip()


def _set_cell(cell, value):
    cell.text = value
    for para in cell.paragraphs:
        for run in para.runs:
            run.font.size = Pt(10.5)


def _table_borders(table):
    borders = OxmlElement('w:tblBorders')
    for side in ('top', 'left', 'bottom', 'right', 'insideH', 'insideV'):
        item = OxmlElement('w:' + side)
        item.set(qn('w:val'), 'single')
        item.set(qn('w:sz'), '4')
        item.set(qn('w:color'), 'B8C2CC')
        borders.append(item)
    table._element.tblPr.append(borders)


def _keep_table_rows_together(table):
    for idx, row in enumerate(table.rows):
        props = row._tr.get_or_add_trPr()
        props.append(OxmlElement('w:cantSplit'))
        if idx == 0:
            props.append(OxmlElement('w:tblHeader'))


def _fill_cover(doc, number):
    paragraphs = doc.paragraphs
    if len(paragraphs) < 18 or '作品编号' not in paragraphs[0].text:
        raise ValueError('Unexpected official report template cover')
    paragraphs[0].text = '作品编号：' + number
    paragraphs[2].text = '作品类别：☑软件设计   □硬件制作   □工程实践'
    paragraphs[3].text = '□密码应用技术   □其它'
    paragraphs[14].text = '作品题目：' + TITLE
    paragraphs[22].text = '2026 年 10 月'
    # The official template explicitly instructs entrants to delete this note.
    for p in list(doc.paragraphs):
        if '提交作品时请将此段落文字删除' in p.text:
            p._element.getparent().remove(p._element)
    if not doc.tables or len(doc.tables[0].rows) < 6:
        raise ValueError('Unexpected official report template information table')
    table = doc.tables[0]
    _set_cell(table.rows[1].cells[0], '编号：' + number)
    _set_cell(table.rows[2].cells[0], '作品题目：' + TITLE)
    _set_cell(table.rows[3].cells[0],
              '作品类别：☑软件设计   □硬件制作   □工程实践   □密码技术应用   □其它')
    _set_cell(table.rows[4].cells[0],
              '作品内容摘要：本系统面向项目中的密码使用风险，融合现有快速扫描、可选 Java '
              '深度证据和本地规则，区分经典已淘汰算法、量子风险与证据不足；在用户显式开启时，'
              '由 AI 基于可引用证据解释用途和可执行整改步骤。系统提供中文 Web、离线报告、'
              '候选修复与复扫验证，明确标注第三方底层能力及评测边界。')
    _set_cell(table.rows[5].cells[0],
              '关键词（五个）：密码安全审计；多源证据；后量子迁移；大模型解释；修复验证')


def _remove_template_body(doc):
    body = doc._element.body
    table_element = doc.tables[0]._element
    after_table = False
    for element in list(body):
        if element is table_element:
            after_table = True
            continue
        if after_table and element.tag.rsplit('}', 1)[-1] != 'sectPr':
            body.remove(element)


def _append_report(doc, source):
    lines = source.read_text(encoding='utf-8').splitlines()
    in_code = False
    code_lines = []
    paragraphs = []

    def flush_paragraph():
        if paragraphs:
            doc.add_paragraph(clean(' '.join(paragraphs)))
            paragraphs.clear()

    def flush_code():
        if code_lines:
            p = doc.add_paragraph('\n'.join(code_lines))
            for run in p.runs:
                run.font.name = 'Consolas'
                run.font.size = Pt(9)
            code_lines.clear()

    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        if line.startswith('```'):
            flush_paragraph()
            if in_code:
                flush_code()
            in_code = not in_code
            i += 1
            continue
        if in_code:
            code_lines.append(line)
            i += 1
            continue
        if line.startswith('# '):
            i += 1  # Official cover already carries the title.
            continue
        if line.startswith('>'):
            i += 1  # Internal draft-status notes are not report content.
            continue
        if line.startswith('## '):
            flush_paragraph()
            doc.add_heading(clean(line[3:]), level=1)
            i += 1
            continue
        if line.startswith('### '):
            flush_paragraph()
            doc.add_heading(clean(line[4:]), level=2)
            i += 1
            continue
        if line.startswith('|'):
            flush_paragraph()
            rows = []
            while i < len(lines) and lines[i].startswith('|'):
                cells = [clean(x) for x in lines[i].strip().strip('|').split('|')]
                if not all(re.fullmatch(r'[:\- ]+', x) for x in cells):
                    rows.append(cells)
                i += 1
            if rows:
                width = max(map(len, rows))
                t = doc.add_table(rows=len(rows), cols=width)
                _table_borders(t)  # The official template may not define Table Grid.
                for r_idx, row in enumerate(rows):
                    for c_idx, value in enumerate(row):
                        _set_cell(t.rows[r_idx].cells[c_idx], value)
                _keep_table_rows_together(t)
            continue
        if re.match(r'^\d+\.\s+', line) or line.startswith('- '):
            flush_paragraph()
            doc.add_paragraph(clean(line))
            i += 1
            continue
        if not line.strip() or line == '---':
            flush_paragraph()
        else:
            paragraphs.append(line.strip())
        i += 1
    flush_paragraph()
    flush_code()


def _scrub_package_metadata(source_path, output_path):
    """Remove inherited WPS/Office custom data, including encoded user IDs."""
    omitted = ('docProps/custom.xml',)
    with tempfile.NamedTemporaryFile(prefix='acg-report-', suffix='.docx',
                                     dir=output_path.parent, delete=False) as stream:
        staged = Path(stream.name)
    try:
        with zipfile.ZipFile(source_path) as src, zipfile.ZipFile(staged, 'w') as dst:
            for item in src.infolist():
                name = item.filename
                if name in omitted or name.startswith('customXml/'):
                    continue
                data = src.read(name)
                if name in ('[Content_Types].xml', '_rels/.rels',
                            'word/_rels/document.xml.rels'):
                    root = ET.fromstring(data)
                    for child in list(root):
                        path = (child.attrib.get('Target', '') + ' ' +
                                child.attrib.get('PartName', '') + ' ' +
                                child.attrib.get('Type', '')).lower()
                        if 'customxml/' in path or 'custom-properties' in path or \
                                'docprops/custom.xml' in path:
                            root.remove(child)
                    data = ET.tostring(root, encoding='utf-8', xml_declaration=True)
                elif name == 'docProps/app.xml':
                    root = ET.fromstring(data)
                    for child in root:
                        if child.tag.rsplit('}', 1)[-1] in (
                                'Company', 'Manager', 'Application'):
                            child.text = None
                    data = ET.tostring(root, encoding='utf-8', xml_declaration=True)
                dst.writestr(item, data)
        with zipfile.ZipFile(staged) as check:
            if check.testzip() is not None:
                raise ValueError('DOCX archive failed integrity check')
            if any(name.startswith('customXml/') or name in omitted
                   for name in check.namelist()):
                raise ValueError('Inherited custom metadata remained')
        # Confirm python-docx can re-open the cleaned official template.
        Document(staged)
        os.replace(staged, output_path)
    finally:
        if staged.exists():
            staged.unlink()


def _audit_generated_report(path, number):
    doc = Document(path)
    body = '\n'.join(p.text for p in doc.paragraphs)
    body += '\n' + '\n'.join(
        cell.text for table in doc.tables for row in table.rows for cell in row.cells)
    if number not in body:
        raise ValueError('Report number missing')
    if number != PLACEHOLDER and PLACEHOLDER in body:
        raise ValueError('Unfilled number placeholder in final report')
    if '提交作品时请将此段落文字删除' in body:
        raise ValueError('Official template warning remained')
    if re.search(r'Rant[-_ ]?yang|Alanxbr|BQ[-_]?park|lenovo|C:[\\/]Users',
                 body, re.I):
        raise ValueError('Known identity or local account marker in report')
    if doc.core_properties.author or doc.core_properties.last_modified_by:
        raise ValueError('Author metadata in report')
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            raise ValueError('DOCX integrity failure')
        if any(n == 'docProps/custom.xml' or n.startswith('customXml/')
               for n in archive.namelist()):
            raise ValueError('Inherited custom metadata in report')
        app = ET.fromstring(archive.read('docProps/app.xml'))
        if any((child.text or '').strip() for child in app
               if child.tag.rsplit('}', 1)[-1] in ('Company', 'Manager')):
            raise ValueError('Company/manager metadata in report')


def build(template, output, number):
    template, output = Path(template), Path(output)
    if output.exists():
        raise FileExistsError('Refusing to overwrite report: ' + str(output))
    doc = Document(template)
    _fill_cover(doc, number)
    _remove_template_body(doc)
    _append_report(doc, SOURCE)
    props = doc.core_properties
    props.author = ''
    props.last_modified_by = ''
    props.subject = ''
    props.keywords = ''
    props.comments = ''
    props.title = 'AI-CryptoGuard 作品设计报告'
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix='acg-unscrubbed-', suffix='.docx',
                                     dir=output.parent, delete=False) as stream:
        unsanitized = Path(stream.name)
    try:
        doc.save(unsanitized)
        _scrub_package_metadata(unsanitized, output)
        try:
            _audit_generated_report(output, number)
        except BaseException:
            output.unlink(missing_ok=True)
            raise
    finally:
        if unsanitized.exists():
            unsanitized.unlink()
    return {'output': str(output), 'draft': number == PLACEHOLDER,
            'paragraphs': len(doc.paragraphs), 'tables': len(doc.tables)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template', required=True, help='Official 2026 report DOCX, kept outside Git')
    parser.add_argument('-o', '--output', required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--draft', action='store_true', help='Use a conspicuous number placeholder')
    group.add_argument('--number', help='Platform-assigned work number for the final report')
    args = parser.parse_args()
    if args.number and not re.fullmatch(r'[A-Za-z0-9-]{1,40}', args.number):
        parser.error('number must be 1-40 letters, digits or hyphens')
    print(build(args.template, args.output, args.number or PLACEHOLDER))


if __name__ == '__main__':
    main()
