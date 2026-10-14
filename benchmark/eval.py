"""算 Precision / Recall / F1。

**口径先定死，再看数字。** 这个文件里最要紧的不是公式，是下面三条约定 ——
数字好不好看是次要的，口径说不清才是致命的。

约定一：分母只算**范围内的**正样本
----------------------------------
`scope.py` 把 79 个类别判成范围外（参数、凭据、TLS 配置……）。
它们**不进 Recall 的分母** —— 我们的规则库压根不建模这些，
拿它们算召回率等于拿尺子量体重。

但**必须如实报出来**：`--report` 会把范围外的清单和条数打出来。
把 79 个类别藏起来只报好看的数字，就是造假。

约定二：范围外的**负样本**仍然算数
----------------------------------
负样本（benchmark 说是干净代码）不参与 Recall，但**参与误报统计**。
哪怕类别是范围外的，只要我们在一个「公认干净」的位置报了问题，
那就是一次误报 —— 这条不能豁免。

约定三：匹配单位 = (文件, 算法)
-------------------------------
与 `benchmark/README.md` 里定的口径一致。行号能对就额外算一档
「行级命中」（CamBench_Real 有精确行号），但**主指标用文件和算法**
—— 因为大多数 benchmark 只标到文件，标不到行，混着算就成了两套分母。

    Precision = 报出的里面，落在标签上的
    Recall    = 范围内正样本里面，我们报出来的
"""

import argparse
import glob
import json
import os
import re
import sys


# Benchmark 类别到我方凭据规则的**可接受集合**。这是标签词汇翻译，不是检测器
# 实现；一个 benchmark 的 generic "hardcoded" 可以由多个更细的我方规则命中。
CREDENTIAL_RULES_BY_CATEGORY = {
    'predictablepbepassword': {'CRED-HARDCODED-PASSWORD', 'CRED-DEFAULT-WEAK'},
    'predictablekeystorepassword': {'CRED-HARDCODED-PASSWORD', 'CRED-DEFAULT-WEAK'},
    'credentialinstring': {
        'CRED-HARDCODED-PASSWORD', 'CRED-HARDCODED-TOKEN',
        'CRED-HARDCODED-CRYPTO-KEY', 'CRED-DEFAULT-WEAK',
        'CRED-HIGH-ENTROPY-SECRET',
    },
    'hardcoded': {
        'CRED-HARDCODED-PASSWORD', 'CRED-HARDCODED-TOKEN',
        'CRED-HARDCODED-CRYPTO-KEY', 'CRED-EMBEDDED-PRIVATE-KEY',
        'CRED-DEFAULT-WEAK', 'CRED-HIGH-ENTROPY-SECRET', 'CRED-IN-URL',
    },
    'hardcode': {
        'CRED-HARDCODED-PASSWORD', 'CRED-HARDCODED-TOKEN',
        'CRED-HARDCODED-CRYPTO-KEY', 'CRED-EMBEDDED-PRIVATE-KEY',
        'CRED-DEFAULT-WEAK', 'CRED-HIGH-ENTROPY-SECRET', 'CRED-IN-URL',
    },
    'insecure key storage': {'CRED-HARDCODED-CRYPTO-KEY',
                             'CRED-EMBEDDED-PRIVATE-KEY'},
    'token': {'CRED-HARDCODED-TOKEN', 'CRED-HIGH-ENTROPY-SECRET'},
}


# ------------------------------------------------------------------ 载入

def load_labels(label_dir):
    """读 `benchmark/labels/*.json`，返回按 benchmark 分组的记录。"""
    out = {}
    for path in sorted(glob.glob(os.path.join(label_dir, '*.json'))):
        name = os.path.splitext(os.path.basename(path))[0]
        with open(path, 'r', encoding='utf-8') as f:
            out[name] = json.load(f)
    return out


def load_findings(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


# ------------------------------------------------------------------ 匹配

def _basename(p):
    return p.replace('\\', '/').rsplit('/', 1)[-1]


def _same_file(a, b):
    """两个文件路径指同一个文件吗？

    扫描产出的 `file` 可能是相对路径、也可能只剩 basename
    （取决于扫的时候传的是什么），所以退到 basename 比较。
    """
    a, b = a.replace('\\', '/'), b.replace('\\', '/')
    if a == b:
        return True
    if a.endswith('/' + b) or b.endswith('/' + a):
        return True
    return _basename(a) == _basename(b)


def _norm_algo(s):
    """算法名归一：**去掉所有非字母数字**。

    只去掉 `-` 和 `_` 是不够的 —— 上游会给合并名 `DES / 3DES`，
    空格和斜杠留着就永远匹配不上单算法标签 `DES`。
    """
    return ''.join(ch for ch in s.upper() if ch.isalnum())


def _algo_set(finding):
    """一个 finding 可能报**多个**算法（`DES / 3DES`、`RSA/EC 混合`）。

    拆开成集合，只要命中其中任何一个就算匹配 —— 否则一条
    「报了 DES 也报了 3DES」的检出，会因为名字拼在一起而被判成没报 DES。
    """
    raw = finding.get('algorithm_normalized') or finding.get('algorithm') or ''
    parts = re.split(r'[/,、|+]|\s+或\s+|\s+and\s+', raw)
    return {_norm_algo(p) for p in parts if _norm_algo(p)}


def _label_algos(rec):
    return {_norm_algo(a) for a in (rec.get('algorithms') or []) if _norm_algo(a)}


def _label_credential_rules(rec):
    return CREDENTIAL_RULES_BY_CATEGORY.get(str(rec.get('category', '')).lower(), set())


def match(labels, findings):
    """把 findings 与 labels 对上。

    Returns:
        dict，含 tp / fp / fn / tn 与明细。分母的口径见文件头。
    """
    # 只保留范围内的正样本进 Recall 分母
    pos_in = [r for r in labels
              if r.get('expect_misuse') and r['verdict'] in ('in', 'partial')]
    pos_out = [r for r in labels
               if r.get('expect_misuse') and r['verdict'] == 'out']
    neg = [r for r in labels if not r.get('expect_misuse')]

    # 只评价落在「范围内正样本」或「明确负样本」上的输出。
    # 只落在范围外正样本上的 finding 不该成为本任务的 FP：同一批样本既已从
    # Recall 分母排除，就必须从 Precision 分母对称排除。
    eligible = []
    excluded_out = []
    for f in findings:
        ffile = f.get('file', '')
        touches_in = any(_same_file(ffile, r['file']) for r in pos_in)
        touches_neg = any(_same_file(ffile, r['file']) for r in neg)
        touches_out = any(_same_file(ffile, r['file']) for r in pos_out)
        if touches_in or touches_neg or not touches_out:
            eligible.append(f)
        else:
            excluded_out.append(f)

    used = set()
    used_findings = set()
    tp_detail, line_hits = [], 0

    for finding_index, f in enumerate(eligible):
        ffile, falgs, fline = f.get('file', ''), _algo_set(f), f.get('line')
        frule = f.get('rule_id')
        hit = None
        for i, r in enumerate(pos_in):
            if i in used:
                continue
            if not _same_file(ffile, r['file']):
                continue
            algos = _label_algos(r)
            credential_rules = _label_credential_rules(r)
            if credential_rules:
                if frule not in credential_rules:
                    continue
            # 算法对得上，或者标签没给算法（部分可比类别有时给不出）
            # 标签给了算法就必须对上；合并名拆开后命中任一即可
            if algos and not credential_rules:
                # 标签明确给了算法时，finding 也必须给出算法且能相交。
                # 旧逻辑会把「无算法线索」仅凭文件名算成 TP。
                if not falgs or not (algos & falgs):
                    continue
            hit = i
            if r.get('line') and fline and int(r['line']) == int(fline):
                line_hits += 1
            break
        if hit is not None:
            used.add(hit)
            used_findings.add(finding_index)
            tp_detail.append((f, pos_in[hit]))

    # 落在「公认干净」位置上的 finding = 误报
    fp_on_neg = [f for f in eligible
                 if any(_same_file(f.get('file', ''), r['file']) for r in neg)]

    tp = len(tp_detail)
    reported = len(eligible)
    fn = len(pos_in) - tp

    return {
        'tp': tp,
        'fp': reported - tp,
        'fp_on_negatives': len(fp_on_neg),
        'fn': fn,
        'n_reported': reported,
        'n_excluded_out_of_scope': len(excluded_out),
        'n_pos_in_scope': len(pos_in),
        'n_pos_out_of_scope': len(pos_out),
        'n_negative': len(neg),
        'line_hits': line_hits,
        'tp_detail': tp_detail,
        # 供专项报告按规则/类别解释误报。这里只返回 Finding 对象，
        # 调用方仍不得打印 raw 中的凭据材料。
        'fp_detail': [f for i, f in enumerate(eligible)
                      if i not in used_findings],
        'pos_in': pos_in,
    }


def prf(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f


def _selftest():
    labels = [
        {'file': 'in.java', 'algorithms': ['DES'], 'expect_misuse': True,
         'verdict': 'in'},
        {'file': 'out.java', 'algorithms': ['AES'], 'expect_misuse': True,
         'verdict': 'out'},
        {'file': 'clean.java', 'algorithms': [], 'expect_misuse': False,
         'verdict': 'out'},
        {'file': 'cred.py', 'category': 'hardcoded', 'algorithms': [],
         'expect_misuse': True, 'verdict': 'in'},
    ]
    findings = [
        {'file': 'in.java', 'algorithm': 'DES'},
        {'file': 'in.java', 'algorithm': ''},
        {'file': 'out.java', 'algorithm': 'AES'},
        {'file': 'clean.java', 'algorithm': 'RSA'},
        {'file': 'cred.py', 'algorithm': 'Credential',
         'rule_id': 'CRED-HARDCODED-TOKEN'},
    ]
    got = match(labels, findings)
    checks = {
        '算法与凭据真值分别命中': got['tp'] == 2,
        '无算法线索不能仅凭文件名成为 TP': got['fp'] == 2,
        '范围外正样本输出对称排除': got['n_excluded_out_of_scope'] == 1,
        '范围内正样本没有漏报': got['fn'] == 0,
    }
    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        print('[FAIL] eval.py 自检: ' + '；'.join(failed))
        return 1
    empty = match(labels, [])
    if empty['fn'] != 2:
        print('[FAIL] eval.py 自检: 零检出必须保留 FN')
        return 1
    if len(got['fp_detail']) != got['fp']:
        print('[FAIL] eval.py 自检: fp_detail 数量必须与 fp 一致')
        return 1
    print('[PASS] eval.py 自检通过（算法匹配 / 范围对称 / 零检出）')
    return 0


# ------------------------------------------------------------------ 汇报

def report(label_dir, findings_path, verbose=False, scanned_names=None):
    labels = load_labels(label_dir)
    if not labels:
        print('没有标签 —— 先跑 `python -m benchmark.adapters`')
        return 1
    findings = load_findings(findings_path)

    print('benchmark 评测')
    print('=' * 72)
    print('标签: %s' % label_dir)
    print('检出: %s  (%d 条)' % (findings_path, len(findings)))
    print()
    print('%-18s %6s %6s %6s %6s %8s %8s' %
          ('benchmark', '标签', '范围内', '范围外', '负样本', 'P', 'R'))
    print('-' * 72)

    agg_tp = agg_fp = agg_fn = 0
    scope_note = []

    scanned_names = set(scanned_names) if scanned_names is not None else None
    skipped = []
    for name in sorted(labels):
        recs = labels[name]
        # findings 里属于这个 benchmark 的部分：靠文件名能否对上标签来判断
        mine = [f for f in findings
                if any(_same_file(f.get('file', ''), r['file']) for r in recs)]
        m = match(recs, mine)
        p, r, f1 = prf(m['tp'], m['fp'], m['fn'])

        # **没扫过的 benchmark 不进合计。** 早先不区分，于是没扫的那几家
        # 全部贡献 FN，合计 Recall 被压到 6.4% —— 那个数字是**口径错误**，
        # 不是我们做得差。判据是「有没有任何一条 finding 落在这个 benchmark 的
        # 标签文件上」；没有就说明这次没扫它。
        # 正式跑分应由调用方显式声明扫过哪些 benchmark。仅凭“是否有检出”
        # 无法区分「没扫描」和「扫描成功但零检出」，后者必须贡献 FN。
        scanned = (name in scanned_names) if scanned_names is not None else bool(mine)
        if not scanned:
            skipped.append((name, len(recs)))
            print('%-18s %6d %6d %6d %6d %8s %8s' %
                  (name, len(recs), m['n_pos_in_scope'],
                   m['n_pos_out_of_scope'], m['n_negative'],
                   '未扫描', '未扫描'))
            continue

        print('%-18s %6d %6d %6d %6d %7.1f%% %7.1f%%' %
              (name, len(recs), m['n_pos_in_scope'],
               m['n_pos_out_of_scope'], m['n_negative'],
               p * 100, r * 100))
        agg_tp += m['tp']
        agg_fp += m['fp']
        agg_fn += m['fn']
        scope_note.append((name, m))

    p, r, f1 = prf(agg_tp, agg_fp, agg_fn)
    print('-' * 72)
    print('%-18s %6s %6s %6s %6s %7.1f%% %7.1f%%' %
          ('合计', '', '', '', '', p * 100, r * 100))
    print()
    print('  TP=%d  FP=%d  FN=%d   F1=%.1f%%' % (agg_tp, agg_fp, agg_fn, f1 * 100))

    # ---- 口径声明：必须跟着数字一起出现，不许只报好看的 ----
    print()
    print('口径')
    print('----')
    print('  · Recall 的分母**只含范围内的正样本** —— 范围外类别（参数、凭据、')
    print('    TLS 配置等）我们的规则库不建模，不计入。')
    print('  · 范围外正样本合计 %d 条，**未计入**上面任何指标。'
          % sum(m['n_pos_out_of_scope'] for _, m in scope_note))
    print('  · 其中仅落在范围外正样本上的检出 %d 条，也从 Precision 分母对称排除。'
          % sum(m['n_excluded_out_of_scope'] for _, m in scope_note))
    print('  · 负样本 %d 条用于误报统计，不参与 Recall。'
          % sum(m['n_negative'] for _, m in scope_note))
    print('  · 匹配单位 = (文件, 算法)，与 benchmark/README.md 一致 ——'
          '上游的合并名（`DES / 3DES`）拆开后命中任一即算匹配。')
    if skipped:
        print('  · 本次**未扫描**的 benchmark 未计入合计: %s'
              % '、'.join('%s(%d 条)' % (n, c) for n, c in skipped))
    if scanned_names is None:
        print('  · ⚠ 未传 --scanned：本次以「有检出」推断是否扫描，只适合排查；')
        print('    正式指标必须显式声明，避免零检出语料被错误排除。')
    print('  · 行级命中 %d 次（仅 CamBench_Real 有精确行号，未单独计指标）。'
          % sum(m['line_hits'] for _, m in scope_note))

    if verbose:
        print()
        print('漏掉的范围内正样本（前 25 条）:')
        for name, m in scope_note:
            missed = [r for r in m['pos_in']]
            hit_files = {f.get('file', '') for f, _ in m['tp_detail']}
            left = [r for r in missed
                    if not any(_same_file(r['file'], hf) for hf in hit_files)]
            for r in left[:25]:
                print('  [%s] %s  %s  (%s)' %
                      (name, r['file'], r.get('algorithm'), r['category']))
    return 0


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description='benchmark 评测')
    ap.add_argument('findings', nargs='?',
                    default=os.path.join(os.path.dirname(here),
                                         'out', 'findings.json'),
                    help='scanner 的产出 JSON')
    ap.add_argument('--labels', default=os.path.join(here, 'labels'))
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='列出漏报明细')
    ap.add_argument('--scanned', default=None,
                    help='正式跑分时显式列出已扫描 benchmark，逗号分隔；'
                         '例如 cryptoapi-bench,cambench-cap,llmcmt')
    ap.add_argument('--selftest', action='store_true', help='运行口径回归自检')
    args = ap.parse_args()

    if args.selftest:
        return _selftest()

    if not os.path.exists(args.findings):
        print('找不到检出文件: %s' % args.findings)
        return 2
    scanned = None
    if args.scanned is not None:
        scanned = [x.strip() for x in args.scanned.split(',') if x.strip()]
    return report(args.labels, args.findings, args.verbose, scanned)


if __name__ == '__main__':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except (AttributeError, OSError):
        pass
    sys.exit(main())
