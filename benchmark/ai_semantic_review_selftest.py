"""The review counter must never invent human judgments from empty fields."""
from benchmark.ai_semantic_review import make_packet, summarize


def main():
    empty = {'cases': [
        {'finding_id': 'one'}, {'finding_id': 'two'},
    ]}
    first = summarize(empty)
    assert first['fully_reviewed'] == 0 and first['semantic_rate'] is None
    assert all(v['pending'] == 2 for v in first['by_criterion'].values())
    reviewed = {'cases': [
        {'finding_id': 'one', 'review_usage_supported': True,
         'review_refs_support_claims': True, 'review_explanation_correct': True,
         'review_steps_actionable': True},
        {'finding_id': 'two', 'review_usage_supported': True,
         'review_refs_support_claims': False, 'review_explanation_correct': True,
         'review_steps_actionable': True},
    ]}
    result = summarize(reviewed)
    assert result['fully_reviewed'] == 2
    assert result['all_four_supported'] == 1
    assert result['semantic_rate'] == 0.5
    assert result['by_criterion']['review_refs_support_claims']['fail'] == 1
    partial = summarize({'cases': [reviewed['cases'][0], {'finding_id': 'two'}]})
    assert partial['fully_reviewed'] == 1
    assert partial['reviewed_subset_rate'] == 1.0
    assert partial['semantic_rate'] is None and not partial['complete']
    try:
        summarize({'cases': reviewed['cases'], 'expected_cases': 28})
        raise AssertionError('declared cohort size mismatch accepted')
    except ValueError:
        pass
    try:
        summarize({'cases': [reviewed['cases'][0], reviewed['cases'][0]]})
        raise AssertionError('duplicate ID accepted')
    except ValueError:
        pass
    scored = {'cases': [{'finding_id': 'one', 'file': 'C:\\private\\demo.py',
                         'algorithm': 'RSA', 'usage_before': 'signing',
                         'usage_after': 'unknown', 'reason': '需确认消费点',
                         'explanation': '不能判断', 'evidence_refs': ['E1'],
                         'steps': []}]}
    assessed = [{'finding_id': 'one', 'finding_kind': 'algorithm',
                 'evidence': [{'tool': 'cbom-scan', 'kind': 'pattern',
                               'lines': [3], 'raw': {'secret': 'TEST-DO-NOT-LEAK',
                                                     'risk': 'quantum_vulnerable',
                                                     'algo': 'RSA'}}]}]
    packet = make_packet(scored, assessed)
    raw = str(packet)
    assert 'TEST-DO-NOT-LEAK' not in raw and 'usage_before' not in raw
    assert 'quantum_vulnerable' not in raw
    assert packet['cases'][0]['evidence'][0]['ref'] == 'E1'
    assert packet['cases'][0]['file'] == 'demo.py'
    assert packet['cases'][0]['review_usage_supported'] is None
    try:
        make_packet({'cases': [scored['cases'][0], scored['cases'][0]]},
                    [assessed[0], {'finding_id': 'two', 'finding_kind': 'algorithm'}])
        raise AssertionError('duplicate score case ID accepted')
    except ValueError:
        pass
    print('PASS: AI semantic review requires actual human marks')


if __name__ == '__main__':
    main()
