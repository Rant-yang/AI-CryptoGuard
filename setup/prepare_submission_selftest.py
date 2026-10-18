"""Regression checks for the one-command submission assembler.

The real builders have independent tests. Here we test publication boundaries,
input guards, output naming and the requirement that audit failures publish
nothing. The separate end-to-end rehearsal uses the official local template.
"""

import tempfile
from pathlib import Path
from unittest.mock import patch

from setup import prepare_submission as target


def main():
    with tempfile.TemporaryDirectory(prefix='acg-finalize-test-') as temp:
        root = Path(temp)
        template = root / 'official.docx'
        slides = root / 'slides.pptx'
        template.write_bytes(b'template')
        slides.write_bytes(b'slides')
        output = root / 'release'
        calls = []

        def report_builder(_template, path, number):
            assert Path(_template) == template
            calls.append('report')
            Path(path).write_bytes(b'report:' + number.encode())

        def source_builder(path, anonymous):
            assert anonymous is True
            calls.append('source')
            Path(path).write_bytes(b'anonymous-source')
            return {'commit': 'a' * 40}

        def support_builder(_slides, _source, path, number):
            assert Path(_slides) == slides
            assert Path(_source).read_bytes() == b'anonymous-source'
            calls.append('support')
            Path(path).write_bytes(b'support:' + number.encode())

        def auditor(report, _slides, source, number, support):
            assert Path(report).name == number + target.REPORT_SUFFIX
            assert Path(source).name == target.SOURCE_NAME
            assert Path(support).name == number + target.SUPPORT_SUFFIX
            calls.append('audit')
            return {'report': [], 'slides': [], 'source': [], 'support': []}

        common = (
            patch.object(target, '_git', return_value=b''),
            patch.object(target, 'build_report', side_effect=report_builder),
            patch.object(target, 'build_source', side_effect=source_builder),
            patch.object(target, 'build_support', side_effect=support_builder),
            patch.object(target, 'audit', side_effect=auditor),
        )
        for item in common:
            item.start()
        try:
            result = target.prepare('REHEARSAL-001', template, slides, output)
            assert calls == ['report', 'source', 'support', 'audit'], calls
            assert output.is_dir() and len(list(output.iterdir())) == 3
            assert result['source_commit'] == 'a' * 40
            assert result['machine_audit'] == 'PASS'
            assert result['human_review_required']
            assert result['files'][target.SOURCE_NAME]['bytes'] == len(b'anonymous-source')
            try:
                target.prepare('REHEARSAL-001', template, slides, output)
                raise AssertionError('Existing release overwritten')
            except FileExistsError:
                pass
            try:
                target.prepare('ACG-TEST-2026', template, slides, root / 'blocked')
                raise AssertionError('Known test number accepted')
            except ValueError:
                pass
            try:
                target.prepare('REHEARSAL-001', template, slides,
                               target.ROOT / 'out' / 'release')
                raise AssertionError('Release permitted inside repo')
            except ValueError:
                pass
        finally:
            for item in reversed(common):
                item.stop()

        failed = root / 'failed'
        with patch.object(target, '_git', return_value=b''), \
             patch.object(target, 'build_report', side_effect=report_builder), \
             patch.object(target, 'build_source', side_effect=source_builder), \
             patch.object(target, 'build_support', side_effect=support_builder), \
             patch.object(target, 'audit', return_value={'source': ['tampered']}):
            try:
                target.prepare('REHEARSAL-001', template, slides, failed)
                raise AssertionError('Failed audit published a release')
            except ValueError as exc:
                assert 'source' in str(exc)
            assert not failed.exists(), 'Failed audit left public output'
            assert not list(root.glob('.acg-submission-stage-*')), 'Staging left behind'

        with patch.object(target, '_git', return_value=b' M docs/report.md\n'):
            try:
                target.prepare('REHEARSAL-001', template, slides, root / 'dirty')
                raise AssertionError('Dirty Git tree accepted')
            except RuntimeError as exc:
                assert '未提交' in str(exc)
            assert not (root / 'dirty').exists()
    print('PASS: formal assembler guards number/tree/path, builds ordered inputs, '
          'refuses overwrite and publishes nothing after audit failure')


if __name__ == '__main__':
    main()
