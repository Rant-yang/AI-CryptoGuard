"""Build and machine-audit the anonymous semifinal candidates in one run.

The platform-assigned number is required. This command does not create the
signed approval page, perform visual anonymity review, or upload anything.
Run it only after committing the report source, slides and code to be released.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from setup.package import build as build_source
from setup.submission_audit import audit
from setup.support_bundle import build as build_support


REPORT_SUFFIX = '-2026密码竞赛复赛作品设计报告.docx'
SUPPORT_SUFFIX = '-2026密码竞赛复赛相关支撑材料.zip'
SOURCE_NAME = '匿名源码.zip'


def build_report(template, output, number):
    # python-docx is needed for real report generation, not CI guard tests.
    from docs.build_submission_report import build
    return build(template, output, number)


def _git(*args):
    result = subprocess.run(['git', *args], cwd=ROOT, capture_output=True,
                            check=False)
    if result.returncode:
        raise RuntimeError('无法核对 Git 工作区；请先确认仓库可访问。')
    return result.stdout


def _check_inputs(number, template, slides, output_dir):
    if not re.fullmatch(r'[A-Za-z0-9-]{1,40}', number):
        raise ValueError('作品编号格式不符；须从参赛平台核对。')
    # Reject the known rehearsal prefixes. The human must still verify that
    # every other syntactically valid number really came from the platform.
    if number.upper().startswith(('TEST', 'ACG-TEST')):
        raise ValueError('测试编号不能用于正式出包。')
    output = Path(output_dir).resolve()
    if output == ROOT or ROOT in output.parents:
        raise ValueError('提交材料必须写入仓库外目录，避免误提交。')
    if output.exists():
        raise FileExistsError('输出目录已存在，拒绝覆盖：' + str(output))
    for label, source in (('官方报告模板', template), ('已审阅幻灯片', slides)):
        if not Path(source).is_file():
            raise FileNotFoundError(label + '不存在：' + str(source))
    if _git('status', '--porcelain=v1').strip():
        raise RuntimeError('Git 工作区有未提交内容；先提交并复核，再生成同版材料。')
    return output


def prepare(number, template, slides, output_dir):
    """Return hashes and audit results; publish the directory only on success."""
    output = _check_inputs(number, template, slides, output_dir)
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.acg-submission-stage-',
                                  dir=output.parent)).resolve()
    if stage.parent != output.parent:
        raise RuntimeError('临时目录不在预期输出目录内。')
    published = False
    try:
        report = stage / (number + REPORT_SUFFIX)
        source = stage / SOURCE_NAME
        support = stage / (number + SUPPORT_SUFFIX)
        build_report(template, report, number)
        packaged = build_source(source, anonymous=True)
        build_support(slides, source, support, number)
        checks = audit(report, slides, source, number=number, support=support)
        failures = {name: problems for name, problems in checks.items() if problems}
        if failures:
            raise ValueError('正式材料机器核查未通过：' + json.dumps(
                failures, ensure_ascii=False))
        files = {}
        for path in (report, source, support):
            files[path.name] = {
                'bytes': path.stat().st_size,
                'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        os.replace(stage, output)
        published = True
        return {
            'directory': str(output), 'source_commit': packaged['commit'],
            'files': files, 'machine_audit': 'PASS',
            'human_review_required': [
                '逐页检查报告和幻灯片的文字、图片、布局与匿名性',
                '核对平台编号及附件类型、准备并签署单独审批页',
                '上传后核对平台回执和实际文件',
            ],
        }
    finally:
        if not published and stage.exists():
            # Only the newly-created sibling staging directory may be removed.
            if stage.parent != output.parent or not stage.name.startswith(
                    '.acg-submission-stage-'):
                raise RuntimeError('拒绝清理不在预期范围内的临时目录。')
            shutil.rmtree(stage)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--number', required=True,
                        help='参赛平台生成的真实作品编号；拒绝测试编号')
    parser.add_argument('--template', required=True,
                        help='仓库外保存的当年官方设计报告模板 DOCX')
    parser.add_argument('--slides', required=True,
                        help='已审阅的匿名 PPTX')
    parser.add_argument('-o', '--output-dir', required=True,
                        help='仓库外、尚不存在的输出目录')
    args = parser.parse_args(argv)
    try:
        result = prepare(args.number, args.template, args.slides,
                         args.output_dir)
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(2, '出包失败：%s\n' % exc)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
