"""An old prompt must never become a current 30-case blind-review packet."""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai import semantic_eval
from ai.enrich_v02 import PROMPT_VERSION


def main():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        assessed = root / 'assessed.json'
        explained = root / 'explained.json'
        review = root / 'review.json'
        before = [{'finding_id': 'synthetic-only', 'file': 'sample.py',
                   'algorithm': 'RSA', 'usage': 'unknown', 'evidence': [{}]}]
        after = [{**before[0], 'stage': 'explained', 'explanation': 'synthetic',
                  'evidence_refs': ['E1'], 'remediation_steps': [],
                  'analysis_provenance': {'prompt_version': 'older-prompt'}}]
        assessed.write_text(json.dumps(before), encoding='utf-8')
        explained.write_text(json.dumps(after), encoding='utf-8')
        original_errors = semantic_eval.errors
        try:
            semantic_eval.errors = lambda _: []
            try:
                semantic_eval.score(assessed, explained, review,
                                    case_ids=('synthetic-only',))
            except ValueError as exc:
                assert '提示词版本' in str(exc)
            else:
                raise AssertionError('Older prompt was accepted for review')
            assert not review.exists(), 'Rejected result created a review file'

            after[0]['analysis_provenance']['prompt_version'] = PROMPT_VERSION
            explained.write_text(json.dumps(after), encoding='utf-8')
            summary = semantic_eval.score(
                assessed, explained, review, case_ids=('synthetic-only',),
                cohort='synthetic-current-v1')
            assert summary['total'] == summary['explained'] == 1
            assert summary['cohort'] == 'synthetic-current-v1'
            assert review.exists(), 'Current prompt did not create review file'
        finally:
            semantic_eval.errors = original_errors
    print('PASS: semantic review rejects stale prompt output')


if __name__ == '__main__':
    main()
