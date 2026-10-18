r"""Reproduce a *file-level diagnostic* on OWASP Benchmark Java v1.2.

This is an external corpus. Never commit source copies, labels, or scan output.
The official crypto/hash truth describes weakness of the executed program; it
is not the same unit as our main (file, algorithm, usage) inventory benchmark.

Examples (Windows cmd):
  python benchmark/owasp_holdout.py prepare D:\_benchmarks\OWASP-BenchmarkJava D:\_holdout\source
  python scanner/scan.py D:\_holdout\source --tools-dir D:\_smoke -o D:\_holdout\findings.json --no-raw
  python benchmark/owasp_holdout.py score D:\_benchmarks\OWASP-BenchmarkJava D:\_holdout\source D:\_holdout\findings.json
"""

import argparse
import collections
import csv
import json
import shutil
from pathlib import Path

CATEGORIES = frozenset({'crypto', 'hash'})
SOURCE_SUBDIR = Path('src/main/java/org/owasp/benchmark/testcode')


def labels_for(repo):
    csv_path = repo / 'expectedresults-1.2.csv'
    with csv_path.open(encoding='utf-8', newline='') as stream:
        rows = list(csv.reader(stream))
    labels = {}
    for row in rows[1:]:
        if len(row) < 4 or row[1] not in CATEGORIES:
            continue
        if row[2] not in ('true', 'false'):
            raise ValueError('Unexpected official truth: %r' % row[2])
        name = row[0] + '.java'
        if name in labels:
            raise ValueError('Duplicate official test: ' + name)
        labels[name] = (row[1], row[2] == 'true')
    if not labels:
        raise ValueError('No crypto/hash labels in official CSV')
    return labels


def prepare(repo, dest):
    labels = labels_for(repo)
    if dest.exists():
        raise FileExistsError('Destination must be new; refusing overwrite: %s' % dest)
    source = repo / SOURCE_SUBDIR
    missing = sorted(name for name in labels if not (source / name).is_file())
    if missing:
        raise FileNotFoundError('%d labeled Java files missing; first: %s' %
                                (len(missing), missing[0]))
    dest.mkdir(parents=True)
    for name in sorted(labels):
        shutil.copy2(source / name, dest / name)
    print('Staged %d numbered Java files from both official categories.' % len(labels))
    print('Labels and category directory names were not copied to the scan tree.')


def _counts(labels, found, category):
    names = [n for n, (c, _) in labels.items() if category is None or c == category]
    tp = sum(n in found for n in names if labels[n][1])
    fn = sum(n not in found for n in names if labels[n][1])
    fp = sum(n in found for n in names if not labels[n][1])
    tn = sum(n not in found for n in names if not labels[n][1])
    return dict(tp=tp, fp=fp, fn=fn, tn=tn,
                precision=round(tp / (tp + fp), 4) if tp + fp else None,
                recall=round(tp / (tp + fn), 4) if tp + fn else None)


def score(repo, source, findings_path):
    labels = labels_for(repo)
    staged = {p.name for p in source.glob('*.java')}
    if staged != set(labels):
        raise ValueError('Scan tree does not exactly match the fixed official cohort: '
                         'missing=%d extra=%d' %
                         (len(set(labels) - staged), len(staged - set(labels))))
    with findings_path.open(encoding='utf-8') as stream:
        findings = json.load(stream)
    if not isinstance(findings, list):
        raise ValueError('Expected a findings JSON array')
    found = set()
    by_name = collections.Counter()
    for item in findings:
        name = Path(str(item['file']).replace('\\', '/')).name
        if name not in labels:
            raise ValueError('Finding outside fixed cohort: ' + name)
        found.add(name)
        by_name[name] += 1
    totals = {category: _counts(labels, found, category)
              for category in ('crypto', 'hash')}
    totals['all'] = _counts(labels, found, None)
    print(json.dumps({'cohort_size': len(labels), 'finding_count': len(findings),
                      'files_with_finding': len(found), 'by_category': totals},
                     ensure_ascii=False, indent=2))
    print('Caution: official truth is per test file and executed-program misuse; '
          'these numbers are not interchangeable with our file+algorithm+usage metric.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    prep = sub.add_parser('prepare')
    prep.add_argument('repo', type=Path)
    prep.add_argument('destination', type=Path)
    evaluate = sub.add_parser('score')
    evaluate.add_argument('repo', type=Path)
    evaluate.add_argument('source', type=Path)
    evaluate.add_argument('findings', type=Path)
    args = parser.parse_args()
    if args.action == 'prepare':
        prepare(args.repo, args.destination)
    else:
        score(args.repo, args.source, args.findings)


if __name__ == '__main__':
    main()
