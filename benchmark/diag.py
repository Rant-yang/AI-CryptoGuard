"""诊断脚本：dump 每个 benchmark 的 FP 明细与 FN 明细，按维度聚合。

用法: python benchmark/diag.py out/bench/all.json [cryptoapi-bench|llmcmt|...]
"""
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmark import eval as beval


def _algo_of(f):
    return f.get('algorithm_normalized') or f.get('algorithm') or ''


def _rule_of(f):
    return f.get('rule_id') or '?'


def main(findings_path, only=None):
    label_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'labels')
    labels = beval.load_labels(label_dir)
    findings = beval.load_findings(findings_path)

    for name in sorted(labels):
        if only and name != only:
            continue
        recs = labels[name]
        mine = [f for f in findings
                if any(beval._same_file(f.get('file', ''), r['file']) for r in recs)]
        m = beval.match(recs, mine)
        p, r, f1 = beval.prf(m['tp'], m['fp'], m['fn'])
        lines = []
        lines.append('%s  TP=%d FP=%d FN=%d  P=%.1f%% R=%.1f%%' %
                     (name, m['tp'], m['fp'], m['fn'], p * 100, r * 100))

        # ---- FP 明细（按 rule_id + algorithm 聚合，附文件列表）----
        lines.append('')
        lines.append('== FP 明细 (%d) ==' % len(m['fp_detail']))
        fp_groups = defaultdict(list)
        for f in m['fp_detail']:
            key = (_rule_of(f), _algo_of(f))
            fp_groups[key].append(f.get('file', ''))
        for (rule, algo), files in sorted(
                fp_groups.items(), key=lambda kv: -len(kv[1])):
            lines.append('  [%s|%s] x%d' % (rule, algo, len(files)))
            for ff in sorted(set(files))[:12]:
                lines.append('      %s' % ff)

        # ---- FN 明细（正确的单位级）----
        lines.append('')
        lines.append('== FN 明细 (%d) ==' % m['fn'])
        # 已命中的 algo 单位与凭据标签
        used_algo = set()
        used_cred = set()
        for f, r in m['tp_detail']:
            if _rule_of(f) in beval.CREDENTIAL_ALL_RULES:
                used_cred.add(id(r))
            else:
                for a in beval._label_algos(r):
                    used_algo.add((r['file'], a))
        # 重建 pos_in 记录
        pos_in = [r for r in recs
                  if r.get('expect_misuse') and r['verdict'] in ('in', 'partial')]
        fn_list = []
        for r in pos_in:
            cred = beval._label_credential_rules(r)
            if cred:
                if id(r) not in used_cred:
                    fn_list.append((r, 'credential'))
            else:
                for a in beval._label_algos(r):
                    if (r['file'], a) not in used_algo:
                        fn_list.append((r, a))
        fn_groups = defaultdict(list)
        for r, a in fn_list:
            key = (r.get('category') or '?', a)
            fn_groups[key].append(r['file'])
        for (cat, a), files in sorted(fn_groups.items(), key=lambda kv: -len(kv[1])):
            lines.append('  [%s | %s] x%d' % (cat, a, len(files)))
            for ff in sorted(set(files))[:12]:
                lines.append('      %s' % ff)

        out_path = 'out/bench/diag_%s.txt' % name
        with open(out_path, 'w', encoding='utf-8') as fh:
            fh.write('\n'.join(lines))
        print('wrote %s' % out_path)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'out/bench/all.json',
         sys.argv[2] if len(sys.argv) > 2 else None)
