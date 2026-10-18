"""Score and blind-review every algorithm from the frozen current pipeline run.

This is an integration/semantic-review cohort, not an independent P/R set.
Raw scan outputs and model explanations remain in private local paths; the
blind packet contains only redacted evidence summaries, not credential cases.
"""
import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from ai import semantic_eval
from benchmark.ai_semantic_review import make_packet
from core.schema.validate_v02 import errors


FROZEN_INPUT_SHA256 = '4675eca5c270422d8be26fc58cc0a4e39e0c20b17bb5913a9661746e527a4584'
COHORT = 'public-crypto-samples-current-pipeline-20261018-v1'
TLS_REVIEW_INPUT_SHA256 = '429d80ffd2ebe2e00ca03b3297ffa7cec7a3e733c62ce42b0714b5cd28526257'
TLS_REVIEW_COHORT = 'public-crypto-samples-tls-rule-review-20261018-v2'
TLS_REF5_COHORT = 'public-crypto-samples-tls-rule-review-20261018-ref5-v3'
TLS_REF6_COHORT = 'public-crypto-samples-tls-rule-review-20261019-ref6-v4'
DESFIX_INPUT_SHA256 = 'b8f5e8372457692d5f372918eec80a775050d2f0b68f5ceae113e17338d71212'
DESFIX_COHORT = 'public-crypto-samples-desede-correction-20261019-v5'
ECDH_GATE_COHORT = 'public-crypto-samples-ecdh-use-gate-20261019-v6'


def evaluate(assessed_path, explained_path, score_path, packet_path,
             cohort='original'):
    if cohort not in ('original', 'tls-review', 'tls-ref5', 'tls-ref6',
                      'desfix', 'ecdh-gate'):
        raise ValueError('未知的公开 AI 复验批次')
    expected_sha = (FROZEN_INPUT_SHA256 if cohort == 'original' else
                    DESFIX_INPUT_SHA256 if cohort in ('desfix', 'ecdh-gate') else
                    TLS_REVIEW_INPUT_SHA256)
    total_expected, algorithm_expected, credential_expected = (
        (44, 29, 15) if cohort in ('desfix', 'ecdh-gate') else (35, 28, 7))
    cohort_id = {
        'original': COHORT,
        'tls-review': TLS_REVIEW_COHORT,
        'tls-ref5': TLS_REF5_COHORT,
        'tls-ref6': TLS_REF6_COHORT,
        'desfix': DESFIX_COHORT,
        'ecdh-gate': ECDH_GATE_COHORT,
    }[cohort]
    assessed_path, explained_path = Path(assessed_path), Path(explained_path)
    score_path, packet_path = Path(score_path), Path(packet_path)
    if score_path == packet_path or score_path.exists() or packet_path.exists():
        raise FileExistsError('结果路径必须不同且为全新文件；不得覆盖首次记录')
    content = assessed_path.read_bytes()
    if hashlib.sha256(content).hexdigest() != expected_sha:
        raise ValueError('当前 assessed 输入与预登记 SHA-256 不同')
    assessed = json.loads(content.decode('utf-8-sig'))
    explained = json.loads(explained_path.read_text(encoding='utf-8-sig'))
    if not isinstance(assessed, list) or not isinstance(explained, list):
        raise ValueError('输入和输出均须为 Finding 数组')
    if len(assessed) != len(explained) or len(assessed) != total_expected:
        raise ValueError('预登记的 %d 条 Finding 数量不符' % total_expected)
    if [f.get('finding_id') for f in assessed] != [f.get('finding_id') for f in explained]:
        raise ValueError('模型结果与冻结输入的 ID/顺序不同')
    algorithms = [f for f in assessed if f.get('finding_kind') == 'algorithm']
    credentials = [f for f in explained if f.get('finding_kind') == 'credential']
    if len(algorithms) != algorithm_expected or len(credentials) != credential_expected:
        raise ValueError('预登记的 %d 算法 + %d 凭据组成不符' %
                         (algorithm_expected, credential_expected))
    invalid = sum(bool(errors(f)) for f in explained)
    if invalid or any(f.get('stage') != 'explained' for f in explained):
        raise ValueError('存在未解释或不合 v0.2 契约的结果；不得生成盲审包')
    if any((f.get('analysis_provenance') or {}).get('model_id') != 'local-rule-base'
           for f in credentials):
        raise ValueError('凭据必须由本地规则处理，不能进入云 AI')

    algo_out = [f for f in explained if f.get('finding_kind') == 'algorithm']
    expected_prompt = {
        'tls-ref5': 'ai-v02-2026-10-18.5',
        'tls-ref6': 'ai-v02-2026-10-19.6',
        'desfix': 'ai-v02-2026-10-19.6',
        'ecdh-gate': 'ai-v02-2026-10-19.7',
    }.get(cohort)
    if expected_prompt and any(
            (f.get('analysis_provenance') or {}).get('prompt_version') !=
            expected_prompt for f in algo_out):
        raise ValueError('新盲审批次混入旧提示词版本')
    with tempfile.TemporaryDirectory(prefix='acg-current-ai-') as temporary:
        tmp = Path(temporary)
        old_path, new_path, result_path = (tmp / n for n in
                                           ('assessed.json', 'explained.json', 'score.json'))
        old_path.write_text(json.dumps(algorithms, ensure_ascii=False), encoding='utf-8')
        new_path.write_text(json.dumps(algo_out, ensure_ascii=False), encoding='utf-8')
        summary = semantic_eval.score(
            old_path, new_path, result_path,
            case_ids=[f['finding_id'] for f in algorithms], cohort=cohort_id,
            prompt_version=expected_prompt)
        if (summary['total'] != algorithm_expected or
                summary['explained'] != algorithm_expected or
                summary['schema_invalid']):
            raise ValueError('算法结果未完成结构验收')
        score = json.loads(result_path.read_text(encoding='utf-8'))
        packet = make_packet(score, algorithms)
        # Preserve the pre-registered input identity in the private review
        # packet. The 28-case v2 cohort must not be mistaken for the earlier
        # 30-case review or the pre-TLS-rule 28-case cohort.
        packet['cohort'] = cohort_id
        packet['assessed_sha256'] = expected_sha
        packet['expected_cases'] = algorithm_expected
    if len(packet['cases']) != algorithm_expected:
        raise ValueError('盲审包数量错误')
    score_path.parent.mkdir(parents=True, exist_ok=True)
    packet_path.parent.mkdir(parents=True, exist_ok=True)
    score_path.write_text(json.dumps(score, ensure_ascii=False, indent=2), encoding='utf-8')
    packet_path.write_text(json.dumps(packet, ensure_ascii=False, indent=2), encoding='utf-8')
    return {'cohort': cohort_id, 'total': total_expected,
            'algorithm_cloud': algorithm_expected,
            'credential_local': credential_expected,
            'explained': total_expected, 'schema_invalid': 0,
            'algorithm_usage_after': summary['usage_after'],
            'blind_review_pending': len(packet['cases'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('assessed')
    parser.add_argument('explained')
    parser.add_argument('--score', required=True)
    parser.add_argument('--packet', required=True)
    parser.add_argument('--cohort', choices=('original', 'tls-review', 'tls-ref5',
                                            'tls-ref6', 'desfix', 'ecdh-gate'),
                        default='original', help='选择预登记的输入 SHA；默认旧批次')
    args = parser.parse_args()
    print(json.dumps(evaluate(args.assessed, args.explained,
                              args.score, args.packet, args.cohort),
                     ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
