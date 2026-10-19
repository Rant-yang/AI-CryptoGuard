"""Evidence-linked project action list. No new model call or safety score."""
from ai.redact import scrub

SEVERITY = {'critical': '严重', 'high': '高', 'medium': '中', 'low': '低', 'info': '提示'}
RANK = {key: i for i, key in enumerate(SEVERITY)}


def _text(value, limit=360):
    return scrub(str(value or ''))[:limit]


def build_overview(rows, task=None):
    """Return presentation data; evidence IDs are scoped to each finding."""
    actions = []
    for row in sorted(rows, key=lambda f: (
            RANK.get(f.get('severity'), 5),
            'conditional-default' in (f.get('tags') or []),
            str(f.get('file') or ''), str(f.get('finding_id') or ''))):
        fid = row.get('finding_id')
        if not fid:
            continue
        refs = ['E%d' % i for i in range(1, len(row.get('evidence') or []) + 1)]
        conditional = 'conditional-default' in (row.get('tags') or [])
        credential = row.get('finding_kind') == 'credential'
        unknown = row.get('usage', 'unknown') == 'unknown'
        rem = row.get('remediation') or {}
        title = ('复核凭据暴露并安排轮换' if credential else
                 '核实用途后确定迁移路线' if unknown else
                 '处理 %s 的加固或迁移' % _text(row.get('algorithm') or row.get('rule_id'), 100))
        if conditional:
            title = '确认备用配置是否实际生效'
        action = ('确认该凭据是否有效及暴露范围；若有效，轮换/撤销并移除硬编码。不要复制凭据原文。'
                  if credential else
                  '检查运行配置是否启用了该备用值，再决定是否整改。' if conditional else
                  '跟踪调用方，确认承担签名、加密或密钥交换中的哪种用途，再选择迁移路线。' if unknown else
                  _text(rem.get('action')) or '结合调用证据核查参数与使用方式，确认整改方案。')
        source = '规则建议'
        if row.get('stage') == 'explained' and not credential and not conditional and not unknown:
            for step in row.get('remediation_steps') or []:
                cited = step.get('evidence_refs') or []
                if step.get('action') and cited and all(ref in refs for ref in cited):
                    action = _text(step['action'])
                    refs = list(dict.fromkeys(cited))
                    source = '逐项 AI 建议'
                    break
        reason = ('仅发现备用值，尚未确认运行时生效' if conditional else
                  '缺少足以确定用途的证据' if unknown and not credential else
                  '按现有严重程度优先复核；风险是否可触发仍需结合实际环境确认')
        path = str(row.get('file') or '').replace('\\', '/')
        if path.startswith('/') or ':' in path or '..' in path.split('/'):
            path = path.rsplit('/', 1)[-1]
        actions.append({'finding_id': fid, 'title': title,
                        'severity': SEVERITY.get(row.get('severity'), '未分级'),
                        'file': _text(path, 240), 'line': row.get('line'),
                        'action': action, 'why': reason, 'source': source,
                        'evidence_refs': refs, 'status': '待执行 / 待验证'})
    explained = sum(r.get('stage') == 'explained' for r in rows)
    unknown = sum(r.get('usage', 'unknown') == 'unknown' and
                  r.get('finding_kind') != 'credential' for r in rows)
    severe = sum(r.get('severity') in ('critical', 'high') for r in rows)
    timelines = [(r.get('quantum_assessment') or {}).get('quantum_timeline') or {} for r in rows]
    immediate = sum(t.get('urgency') == 'immediate' for t in timelines)
    stages = (task or {}).get('stages') or []
    gaps = []
    for stage in stages:
        if stage.get('status') != 'completed':
            names = {'scan': '基础扫描', 'deep_java': 'Java 深度分析',
                     'quantum_assessment': '量子风险评估', 'ai': 'AI 解释'}
            gaps.append('%s未完成或未启用，不能视为已检查通过。' % names.get(stage.get('name'), '某执行阶段'))
    if not stages:
        gaps.append('未提供执行阶段记录，无法确认扫描覆盖范围。')
    if unknown:
        gaps.append('%d 条用途仍待确认，暂不指定具体迁移算法。' % unknown)
    if any(t.get('status') == 'not_configured' for t in timelines):
        gaps.append('未配置量子时间窗口；目前只判断机制风险，不推算迁移截止时间。')
    return {'summary': '本次发现 %d 条线索，其中 %d 条为高或严重级别；已解释 %d 条，另有 %d 条用途待确认。' %
            (len(rows), severe, explained, unknown),
            'basis': '依据当前发现与证据汇总，按严重程度初排；不代表已验证漏洞或已经完成整改。',
            'timeline_summary': ('按你填写的时间情景，%d 条发现需尽快启动迁移准备；这不是 Q-Day 预测。' % immediate
                                 if immediate else '迁移时机请结合每项量子时间评估；未配置时不推算期限。'),
            'actions': actions, 'gaps': gaps,
            'counts': {'findings': len(rows), 'high_or_critical': severe,
                       'explained': explained, 'usage_unknown': unknown}}
