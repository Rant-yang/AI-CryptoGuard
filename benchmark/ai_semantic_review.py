"""Summarize independent human review of ai/semantic_eval.py score output.

The four review_* fields are deliberately human judgments. This program does
not infer them from model output or count schema validity as semantic success.
"""
import argparse
import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from ai.redact import basename, redact_evidence, scrub  # noqa: E402


CRITERIA = (
    'review_usage_supported',
    'review_refs_support_claims',
    'review_explanation_correct',
    'review_steps_actionable',
)


def make_packet(score, assessed):
    """Create a blinded-to-history packet with safe evidence summaries.

    The reviewer sees model claims and source locations, but not the scanner's
    prior usage guess, earlier failure notes, or any evidence.raw content.
    """
    source = {f.get('finding_id'): f for f in assessed}
    cases = score.get('cases') if isinstance(score, dict) else None
    if not isinstance(cases, list) or not cases:
        raise ValueError('Expected semantic_eval score cases')
    if len(source) != len(assessed) or len(cases) != len(assessed):
        raise ValueError('Review cohort must match assessed findings exactly')
    score_ids = [c.get('finding_id') for c in cases]
    if any(not fid for fid in score_ids) or len(set(score_ids)) != len(score_ids):
        raise ValueError('Score case IDs must be unique and nonempty')
    rows = []
    for c in cases:
        fid = c.get('finding_id')
        f = source.get(fid)
        if not f or f.get('finding_kind') == 'credential':
            raise ValueError('Missing or credential review case')
        evidences = []
        for i, ev in enumerate(f.get('evidence') or [], 1):
            safe = redact_evidence(ev, 'shape')
            # The reviewer must judge source support independently; upstream
            # purpose/risk fields are previous tool opinions, not evidence.
            safe.pop('upstream', None)
            evidences.append({'ref': 'E%d' % i, **safe,
                              'lines': [n for n in ev.get('lines', []) if isinstance(n, int)]})
        steps = []
        for step in c.get('steps') or []:
            if isinstance(step, dict):
                steps.append(scrub({key: step.get(key) for key in
                                    ('action', 'evidence_refs', 'rule_refs',
                                     'prerequisites', 'verification')}))
        row = {'finding_id': fid, 'file': basename(c.get('file')),
               'algorithm': c.get('algorithm'), 'model_usage': c.get('usage_after'),
               'usage_reason': scrub(c.get('reason') or ''),
               'explanation': scrub(c.get('explanation') or ''),
               'evidence_refs': c.get('evidence_refs') or [],
               'evidence': evidences, 'remediation_steps': steps,
               'review_notes': None}
        row.update({key: None for key in CRITERIA})
        rows.append(row)
    return {'review_protocol': 'AI-v0.2-public-cohort-human-review-v1',
            'instructions': ('先查公开原始源码与每条 E 编号对应证据，再独立填写四个 '
                             'review_* 为 true/false；证据不足标 false 并写 review_notes。'
                             '不要依据历史评语或模型措辞打分。'),
            'cases': rows}


def summarize(data):
    cases = data.get('cases') if isinstance(data, dict) else None
    if not isinstance(cases, list) or not cases:
        raise ValueError('Expected a nonempty semantic_eval review case list')
    declared = data.get('expected_cases')
    if declared is not None and (type(declared) is not int or declared != len(cases)):
        raise ValueError('Review case count does not match the frozen cohort declaration')
    ids = [c.get('finding_id') for c in cases]
    if any(not item for item in ids) or len(set(ids)) != len(ids):
        raise ValueError('Finding IDs must be unique and nonempty')
    result = {'total': len(cases), 'by_criterion': {}, 'fully_reviewed': 0,
              'all_four_supported': 0, 'unreviewed_ids': []}
    for key in CRITERIA:
        values = [c.get(key) for c in cases]
        if any(type(v) not in (bool, type(None)) for v in values):
            raise ValueError(key + ' must be true, false, or null')
        counter = collections.Counter('pass' if v is True else
                                      'fail' if v is False else 'pending' for v in values)
        result['by_criterion'][key] = {name: counter[name]
                                        for name in ('pass', 'fail', 'pending')}
    for c in cases:
        marks = [c.get(key) for key in CRITERIA]
        if all(type(v) is bool for v in marks):
            result['fully_reviewed'] += 1
            if all(marks):
                result['all_four_supported'] += 1
        else:
            result['unreviewed_ids'].append(c['finding_id'])
    result['complete'] = result['fully_reviewed'] == result['total']
    result['reviewed_subset_rate'] = (round(result['all_four_supported'] /
                                            result['fully_reviewed'], 4)
                                      if result['fully_reviewed'] else None)
    # A partial review cannot be published as the cohort's semantic rate.
    result['semantic_rate'] = (result['reviewed_subset_rate']
                               if result['complete'] else None)
    result['note'] = ('仅当全部样本已人工审阅时提供 semantic_rate；未完成时仅有明确标注的'
                      ' reviewed_subset_rate。模型输出结构通过率与此无关。')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('review', type=Path, help='人工填写 review_* 的私有 JSON')
    parser.add_argument('--assessed', type=Path,
                        help='提供固定 assessed 数组时生成盲审包，不计算分数')
    parser.add_argument('-o', '--output', type=Path, help='盲审包输出路径')
    parser.add_argument('--require-complete', action='store_true')
    parser.add_argument('--expect-cohort', help='预登记的 cohort 标识；缺失或不符则拒绝计分')
    parser.add_argument('--expect-sha', help='预登记 assessed 输入 SHA-256；缺失或不符则拒绝计分')
    args = parser.parse_args(argv)
    if args.assessed:
        if not args.output:
            parser.error('--assessed 需要 -o/--output')
        packet = make_packet(
            json.loads(args.review.read_text(encoding='utf-8-sig')),
            json.loads(args.assessed.read_text(encoding='utf-8-sig')))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(packet, ensure_ascii=False, indent=2),
                               encoding='utf-8')
        print('Blind review packet: %d cases' % len(packet['cases']))
        return 0
    review = json.loads(args.review.read_text(encoding='utf-8-sig'))
    if args.expect_cohort and review.get('cohort') != args.expect_cohort:
        raise ValueError('盲审包 cohort 与预登记批次不一致')
    if args.expect_sha and review.get('assessed_sha256') != args.expect_sha:
        raise ValueError('盲审包 assessed SHA-256 与预登记输入不一致')
    result = summarize(review)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if args.require_complete and result['fully_reviewed'] != result['total'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
