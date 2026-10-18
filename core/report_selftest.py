"""Offline report checks: normalized evidence, privacy, and escaped content."""
import json
from pathlib import Path

from core.report import render_report


def main():
    root = Path(__file__).resolve().parent
    rows = json.loads((root / 'samples/v0.2/credential.json').read_text(encoding='utf-8'))
    task = json.loads((root / 'samples/v0.2/task.json').read_text(encoding='utf-8'))
    secret = 'SyntheticPasswordDoNotUse9081726354'
    rows[2]['evidence'][0]['raw'] = {'secret': secret, 'html': '<script>raw</script>'}
    rows[2]['explanation'] = '密码值 ' + secret
    rows[2]['remediation']['action'] = '请替换 ' + secret
    rows[2]['remediation_steps'][0]['action'] = '请替换 ' + secret
    report = render_report(rows, task)
    assert 'E1' in report and 'credential-scan' not in report  # sample uses manual
    assert 'manual / manual' in report
    assert '已跳过' in report and 'Python-only input' in report
    assert secret not in report and '<script>raw</script>' not in report
    assert '凭据类解释可能包含敏感上下文' in report
    other = dict(rows[0], finding_kind='algorithm', algorithm='<script>bad</script>',
                 remediation={'decided': False, 'source': 'none'},
                 evidence=[{'tool': 'manual', 'kind': 'manual', 'lines': [1],
                            'raw': {'secret': secret}}])
    safe = render_report([other])
    assert '&lt;script&gt;bad&lt;/script&gt;' in safe
    assert '<script>bad</script>' not in safe and secret not in safe
    assert '未提供任务状态' in safe
    high = dict(other, algorithm='HIGH-EXAMPLE', severity='high', tags=[])
    low = dict(other, algorithm='LOW-EXAMPLE', severity='low', tags=[])
    conditional = dict(other, algorithm='BACKUP-EXAMPLE', severity='high',
                       tags=['conditional-default'])
    ranked = render_report([low, conditional, high])
    assert ranked.index('HIGH-EXAMPLE') < ranked.index('BACKUP-EXAMPLE')
    assert ranked.index('BACKUP-EXAMPLE') < ranked.index('LOW-EXAMPLE')
    assert '仅备用值（当前是否生效待核实）' in ranked
    try:
        render_report({'not': 'a list'})
        raise AssertionError('non-array input accepted')
    except ValueError:
        pass
    print('PASS: offline HTML report privacy, escaping, evidence, stage status')


if __name__ == '__main__':
    main()
