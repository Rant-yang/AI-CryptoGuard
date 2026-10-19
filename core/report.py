"""Generate a self-contained Chinese HTML audit report from v0.2 findings.

Only allowlisted normalized fields are rendered. Never include evidence.raw,
source snippets, credential fingerprints, or unsanitized model output.
"""
import argparse
import collections
import html
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai.redact import scrub


RISK = {'shor': '量子直接威胁', 'broken': '经典攻击已破',
        'grover': '量子搜索削弱', 'review': '待评估',
        'safe': '无已知量子威胁', 'not_applicable': '非算法问题'}
SEVERITY = {'critical': '严重', 'high': '高', 'medium': '中',
            'low': '低', 'info': '提示'}
STAGE = {'scan': '快速扫描', 'deep_java': 'Java 深度证据',
         'quantum_assessment': '量子风险评估', 'ai': 'AI 解释'}
STATUS = {'completed': '已完成', 'skipped': '已跳过', 'failed': '失败',
          'timeout': '超时', 'pending': '等待中', 'running': '运行中'}


def _subject(finding):
    if finding.get('rule_id') == 'PY-RSA-KEYSIZE-LT2048':
        return 'RSA 密钥长度不足'
    if finding.get('rule_id') == 'PY-CBC-FIXED-IV-DIRECT':
        return 'CBC 加密使用固定 IV'
    if finding.get('rule_id') == 'PY-GCM-FIXED-NONCE-DIRECT':
        return 'GCM 加密使用固定 Nonce'
    return finding.get('algorithm') or finding.get('rule_id') or finding.get('finding_kind', '')


def _text(value, limit=600):
    """Escape every variable value after conservative secret/path scrubbing."""
    value = '' if value is None else str(value)
    return html.escape(scrub(value)[:limit], quote=True)


def _file(value):
    value = str(value or '').replace('\\', '/')
    if value.startswith('/') or re.match(r'^[A-Za-z]:/', value) or '..' in value.split('/'):
        value = value.rsplit('/', 1)[-1]
    return _text(value, 250)


def render_report(findings, task=None):
    if not isinstance(findings, list) or not all(isinstance(f, dict) for f in findings):
        raise ValueError('Report input must be a findings array')
    task = task if isinstance(task, dict) else {}
    counts = collections.Counter(f.get('severity') for f in findings)
    explained = sum(f.get('stage') == 'explained' for f in findings)
    severity_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    ordered = sorted(findings, key=lambda f: (
        severity_rank.get(f.get('severity'), 5),
        'conditional-default' in (f.get('tags') or []),
        -(f.get('confidence') or 0),
        str(f.get('file') or ''), str(f.get('finding_id') or '')))
    blocks = []
    for i, finding in enumerate(ordered, 1):
        evidences = finding.get('evidence') or []
        evidence_html = []
        for n, ev in enumerate(evidences, 1):
            if not isinstance(ev, dict):
                continue
            lines = ', '.join(str(v) for v in ev.get('lines', []) if isinstance(v, int))
            flow = ev.get('flow') or {}
            completeness = flow.get('completeness') if isinstance(flow, dict) else None
            flow_note = (' · 数据流：%s' % _text(completeness, 50)) if completeness else ''
            evidence_html.append('<li><b>E%d</b> %s / %s · 行 %s%s</li>' %
                                 (n, _text(ev.get('tool'), 60), _text(ev.get('kind'), 40),
                                  _text(lines or '未知', 100), flow_note))
        qa = finding.get('quantum_assessment') or {}
        rem = finding.get('remediation') or {}
        ai_done = finding.get('stage') == 'explained'
        kind = finding.get('finding_kind', 'algorithm')
        conditional = 'conditional-default' in (finding.get('tags') or [])
        refs = ', '.join(finding.get('evidence_refs') or []) if ai_done else ''
        explanation = ('凭据类解释可能包含敏感上下文；离线报告仅保留规则编号、证据位置与整改步骤。'
                       if kind == 'credential' else
                       _text(finding.get('explanation'), 1000)
                       if ai_done and finding.get('explanation') else
                       '尚无 AI 解释；请依据证据及规则结果人工复核。')
        steps = []
        for step in (finding.get('remediation_steps') or []) if ai_done and kind != 'credential' else []:
            if not isinstance(step, dict):
                continue
            step_refs = ', '.join(step.get('evidence_refs') or [])
            steps.append('<li>%s <small>证据 %s · 执行状态 %s</small></li>' %
                         (_text(step.get('action'), 400), _text(step_refs or '未标注', 70),
                          _text(step.get('execution_status', 'not_run'), 30)))
        pqc = ', '.join(x.get('route_id', '') for x in qa.get('migration_candidates', [])
                        if isinstance(x, dict) and x.get('route_id'))
        blocks.append('''<section class="finding">
          <h2>%d. %s <span class="sev">%s</span></h2>
          <p class="loc">%s:%s · %s · %s%s</p>
          <p><b>风险成因：</b>%s · <b>量子评估：</b>%s</p>
          <p><b>迁移 / 加固：</b>%s%s</p>
          <p><b>解释：</b>%s%s</p>
          <p><b>证据：</b></p><ol>%s</ol>
          %s
        </section>''' %
                      (i, _text(_subject(finding), 150),
                       _text(SEVERITY.get(finding.get('severity'), '未分级'), 20),
                       _file(finding.get('file')), _text(finding.get('line'), 20),
                       _text(kind, 30), _text(finding.get('usage', 'unknown'), 35),
                       ' · 仅备用值（当前是否生效待核实）' if conditional else '',
                       _text(RISK.get(finding.get('risk'), '未知'), 40),
                       _text(qa.get('status', '未运行'), 45),
                       ('请在授权环境中复核并轮换/撤销暴露凭据；报告不展示凭据原文。'
                        if kind == 'credential' else _text(rem.get('action') or '未给出具体方案', 600)),
                       (' · 路线编号：' + _text(pqc, 180)) if pqc else '',
                       explanation,
                       (' <small>引用 %s</small>' % _text(refs, 70)) if refs else '',
                       ''.join(evidence_html) or '<li>无可显示证据</li>',
                       ('<p><b>整改步骤：</b></p><ol>%s</ol>' % ''.join(steps)) if steps else ''))
    stages = []
    for stage in task.get('stages', []):
        if isinstance(stage, dict):
            stages.append('<li>%s：%s%s</li>' %
                          (_text(STAGE.get(stage.get('name'), stage.get('name', '未知')), 60),
                           _text(STATUS.get(stage.get('status'), stage.get('status', '未知')), 30),
                           ('（%s）' % _text(stage.get('reason'), 120)) if stage.get('reason') else ''))
    top = []
    for row in ordered[:5]:
        kind = row.get('finding_kind', 'algorithm')
        label = _subject(row)
        conditional = 'conditional-default' in (row.get('tags') or [])
        top.append('<li>%s · %s · %s:%s%s</li>' %
                   (_text(SEVERITY.get(row.get('severity'), '未分级'), 20),
                    _text(label or kind, 120), _file(row.get('file')),
                    _text(row.get('line'), 20), ' · 仅备用值' if conditional else ''))
    return '''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>AI-CryptoGuard 审计报告</title><style>
body{font:15px/1.7 system-ui,"Microsoft YaHei",sans-serif;color:#17212b;max-width:960px;margin:36px auto;padding:0 24px;background:#f6f8fa}
header,.finding{background:white;border:1px solid #dce2e8;border-radius:8px;padding:22px;margin-bottom:16px}
h1{margin:0 0 8px}h2{font-size:19px;margin:0 0 8px}.muted,.loc,small{color:#566474}
.finding{break-inside:avoid}.sev{float:right;background:#263f58;color:white;font-size:12px;padding:2px 8px;border-radius:4px}
ol{margin:4px 0 8px;padding-left:28px}li{padding:2px 0}small{font-size:12px}
@media print{body{background:white;margin:0}.finding,header{border-color:#ccd5dd;box-shadow:none}}
</style></head><body><header><h1>AI-CryptoGuard 审计报告</h1>
<p class="muted">本报告是扫描线索与规则/AI 辅助解释，不是已验证的整改或正式密码测评结论。</p>
<p>发现 <b>%d</b> 条 · 严重 %d · 高 %d · AI 已解释 %d · AI 未解释 %d</p>
<h2>优先复核（前 5 条）</h2><ol>%s</ol>
<p class="muted">仅按严重程度、条件性标记和置信度初排；实际整改顺序需结合业务影响与项目测试人工确认。</p>
<h2>执行阶段</h2><ol>%s</ol>
<p class="muted">证据编号 E1、E2 … 仅指向同一发现中的证据项。未运行/跳过的阶段不能视为阴性结论。
候选迁移算法需核对用途、规则依据和实施环境；整改步骤默认未执行。</p></header>
%s</body></html>''' % (
         len(findings), counts['critical'], counts['high'], explained,
         len(findings) - explained,
         ''.join(top) or '<li>无待复核发现</li>',
         ''.join(stages) or '<li>未提供任务状态；不能确认各阶段是否运行</li>',
         ''.join(blocks) or '<section class="finding">本次没有发现条目；请核对扫描阶段状态。</section>')


def main(argv=None):
    parser = argparse.ArgumentParser(description='生成离线中文 HTML 审计报告')
    parser.add_argument('findings', type=Path)
    parser.add_argument('-o', '--output', required=True, type=Path)
    parser.add_argument('--task', type=Path, help='可选的 task.json，显示阶段运行状态')
    args = parser.parse_args(argv)
    rows = json.loads(args.findings.read_text(encoding='utf-8-sig'))
    task = json.loads(args.task.read_text(encoding='utf-8-sig')) if args.task else None
    body = render_report(rows, task)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(body, encoding='utf-8')
    print('HTML report: %s (%d findings)' % (args.output, len(rows)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
