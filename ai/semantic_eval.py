"""Fixed 30-case AI semantic evaluation on public CryptoScan demo sources.

The input and model outputs live under gitignored out/. Case IDs are frozen
before model execution; this script never selects examples by model success.
Credential findings are excluded because v0.2 processes those locally.
"""
import argparse
import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.schema.validate_v02 import errors


CASE_IDS = (
    '9a4632be9dda', 'e5c9eac2c407', '51124c92c737', 'd237aa074764',
    '6b07bc9ac613', '21263589807c', 'b0e3b0bde0fc', '7b98a1f949d2',
    'dfa3e1916665', '8c3780fa5108', 'aaa8faf26a8f', '498e14516e1d',
    '54c17850691d', 'af9a744c7b13', '406c73671c45', 'a988cad7823b',
    '5e22cfba2980', '5dc6e3beed3b', 'f4d36e0417db', 'de8ee0f89b41',
    '95bbb1df584f', '97877ebd8b69', '1a9011cb1fdd', '3469dedc0ca4',
    'b2aa0fbfd0a6', 'f400e98068ac', '60d2658c7363', '8753236ab053',
    'c4f6dce47faa', '6d2be4fccb31',
)


def _load(path):
    rows = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    if not isinstance(rows, list):
        raise ValueError('输入必须是 Finding 数组')
    ids = [r.get('finding_id') for r in rows]
    if len(ids) != len(set(ids)):
        raise ValueError('Finding ID 重复')
    return rows


def prepare(assessed_path, output_path):
    rows = _load(assessed_path)
    by_id = {r['finding_id']: r for r in rows}
    missing = sorted(set(CASE_IDS) - by_id.keys())
    if missing:
        raise ValueError('固定样本缺失 %d 条；请重新用公开 crypto-samples 生成 assessed'
                         % len(missing))
    selected = [by_id[fid] for fid in CASE_IDS]
    for row in selected:
        if row.get('stage') != 'assessed' or row.get('finding_kind') == 'credential':
            raise ValueError('固定样本包含未评估项或凭据项')
        if errors(row):
            raise ValueError('固定样本未通过 v0.2 契约')
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(selected, ensure_ascii=False, indent=2), encoding='utf-8')
    return selected


def score(assessed_path, explained_path, report_path):
    before, after = _load(assessed_path), _load(explained_path)
    if [r['finding_id'] for r in before] != list(CASE_IDS) or \
            [r['finding_id'] for r in after] != list(CASE_IDS):
        raise ValueError('结果与预先固定的 30 条 ID/顺序不一致')
    rows = []
    for old, new in zip(before, after):
        invalid = errors(new)
        refs = new.get('evidence_refs') or []
        rows.append({
            'finding_id': old['finding_id'],
            'file': Path(old['file']).name,
            'algorithm': old['algorithm'],
            'usage_before': old.get('usage'),
            'usage_after': new.get('usage'),
            'stage': new.get('stage'),
            'schema_errors': invalid,
            'evidence_refs': refs,
            'n_evidence': len(old.get('evidence') or []),
            'explanation': new.get('explanation'),
            'reason': (new.get('usage_assessment') or {}).get('reason'),
            'steps': new.get('remediation_steps'),
            # A human must judge these against the actual public source. A
            # schema validator cannot tell whether an E1 citation is truthful.
            'review_usage_supported': None,
            'review_refs_support_claims': None,
            'review_explanation_correct': None,
            'review_steps_actionable': None,
            'review_notes': None,
        })
    summary = {
        'cohort': 'public-crypto-samples-semantic-30-v1',
        'total': len(rows),
        'explained': sum(r['stage'] == 'explained' for r in rows),
        'schema_invalid': sum(bool(r['schema_errors']) for r in rows),
        'usage_changed': sum(r['usage_before'] != r['usage_after'] for r in rows),
        'usage_after': dict(collections.Counter(r['usage_after'] for r in rows)),
        'semantic_review_completed': 0,
        'note': '语义正确率需逐条人工复核；格式通过不等于结论正确。',
    }
    output = {'summary': summary, 'cases': rows}
    path = Path(report_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding='utf-8')
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description='固定 30 条公开样本的 AI 语义验收')
    sub = ap.add_subparsers(dest='command', required=True)
    p = sub.add_parser('prepare')
    p.add_argument('assessed')
    p.add_argument('-o', '--output', required=True)
    s = sub.add_parser('score')
    s.add_argument('assessed')
    s.add_argument('explained')
    s.add_argument('-o', '--output', required=True)
    args = ap.parse_args(argv)
    if args.command == 'prepare':
        rows = prepare(args.assessed, args.output)
        print('固定 AI 语义样本: %d 条；输出 %s' % (len(rows), args.output))
    else:
        result = score(args.assessed, args.explained, args.output)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
