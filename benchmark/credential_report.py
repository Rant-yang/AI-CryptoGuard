"""单独汇报凭据检测线的 benchmark 指标与漏检类别。

只打印类别和计数，不打印源码、变量值、指纹或任何凭据材料。
"""
import argparse
import collections
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from benchmark import eval as beval  # noqa: E402


def report(label_dir, findings_path, scanned):
    labels_by_bench = beval.load_labels(label_dir)
    findings = [f for f in beval.load_findings(findings_path)
                if f.get('finding_kind') == 'credential']
    scanned = set(scanned)

    agg_tp = agg_fp = agg_fn = 0
    print('凭据检测专项评测（不输出任何凭据材料）')
    print('=' * 72)
    print('%-18s %8s %8s %8s %8s %8s' %
          ('benchmark', '正样本', '检出', 'TP', 'P', 'R'))
    print('-' * 72)
    for name in sorted(labels_by_bench):
        if name not in scanned:
            continue
        labels = [r for r in labels_by_bench[name]
                  if str(r.get('category', '')).lower()
                  in beval.CREDENTIAL_RULES_BY_CATEGORY]
        mine = [f for f in findings
                if any(beval._same_file(f.get('file', ''), r['file'])
                       for r in labels_by_bench[name])]
        m = beval.match(labels, mine)
        p, r, _ = beval.prf(m['tp'], m['fp'], m['fn'])
        print('%-18s %8d %8d %8d %7.1f%% %7.1f%%' %
              (name, m['n_pos_in_scope'], m['n_reported'], m['tp'],
               p * 100, r * 100))
        agg_tp += m['tp']; agg_fp += m['fp']; agg_fn += m['fn']

        missed = collections.Counter(str(x.get('category', '')).lower()
                                     for x in m['pos_in'])
        for _, label in m['tp_detail']:
            cat = str(label.get('category', '')).lower()
            missed[cat] -= 1
        missed = +missed
        if missed:
            print('  未命中: ' + ' / '.join('%s=%d' % item
                                             for item in missed.most_common()))

    p, r, f1 = beval.prf(agg_tp, agg_fp, agg_fn)
    print('-' * 72)
    print('合计 TP=%d FP=%d FN=%d  P=%.1f%% R=%.1f%% F1=%.1f%%'
          % (agg_tp, agg_fp, agg_fn, p * 100, r * 100, f1 * 100))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('findings')
    ap.add_argument('--labels', default='benchmark/labels')
    ap.add_argument('--scanned', required=True,
                    help='逗号分隔的已扫描 benchmark')
    args = ap.parse_args(argv)
    return report(args.labels, args.findings,
                  [x.strip() for x in args.scanned.split(',') if x.strip()])


if __name__ == '__main__':
    raise SystemExit(main())
