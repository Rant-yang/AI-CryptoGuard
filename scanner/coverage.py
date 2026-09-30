"""覆盖差异审计 —— 一家报了、另一家没报的地方。

价值（benchmark/README.md 的口径）: Recall 的分母是标签，但**两个工具
互相之间的覆盖差异**是最直接的漏报线索 —— 上游工具自己漏的地方，
我们的融合结果必然也漏（第一版没有第三个独立来源）。
这份报告不评判谁对谁错，只把差异摆出来供人工复核与标注。

两个视角，刻意分开:
    行级   同一文件同一行，A 报了 B 没报。**不受算法粒度影响**
           （就是"这行代码你没报我报了"），是漏报的最强信号。
    算法级 A 清点出的算法种类里，B 全项目一个都没报的（反向亦然）。
           受粒度差异干扰（cbom 的 'NIST PQC' 大类 vs CryptoScan 的
           ML-KEM 细分天然对不上），只做参考、不算结论。

输入用**吸收前的原始 ToolGroup**（merge 前留存），反映工具各自看到了什么，
而不是融合层归并后的样子。

当前实现假设**恰好两个工具**（第一版即 cbom-scan + cryptoscan）；
接入第三个工具（CrySentry）时本模块需泛化，不在第一版范围。
"""


def coverage_diff(groups_by_tool):
    """对比各工具的原始分组，返回差异报告 dict（可直接 json.dump）。"""
    tools = sorted(groups_by_tool)
    report = {
        'tools': tools,
        'by_file': {},
        'algorithm_coverage': {},
        'summary': {},
    }
    if len(tools) < 2:
        return report

    # ---- 行级对比：按文件求各工具的命中行集合 -----------------------------
    lines_by_tool_file = {}   # (tool) -> {file: {line: alg}}
    algs_by_tool = {}         # (tool) -> set(alg_norm)
    for tool, groups in groups_by_tool.items():
        m = {}
        for g in groups:
            algs_by_tool.setdefault(tool, set()).add(g['alg_norm'])
            fm = m.setdefault(g['file'], {})
            for ln in g['lines']:
                fm.setdefault(ln, g['algorithm'])
        lines_by_tool_file[tool] = m

    files = sorted({f for m in lines_by_tool_file.values() for f in m})
    a, b = tools[0], tools[1]
    tot = {'both': 0, '%s_only' % a: 0, '%s_only' % b: 0}
    for f in files:
        la = lines_by_tool_file[a].get(f, {})
        lb = lines_by_tool_file[b].get(f, {})
        both = sorted(set(la) & set(lb))
        a_only = [{'line': ln, 'algorithm': la[ln]} for ln in sorted(set(la) - set(lb))]
        b_only = [{'line': ln, 'algorithm': lb[ln]} for ln in sorted(set(lb) - set(la))]
        tot['both'] += len(both)
        tot['%s_only' % a] += len(a_only)
        tot['%s_only' % b] += len(b_only)
        if a_only or b_only:
            report['by_file'][f] = {
                '%s_only' % a: a_only,
                '%s_only' % b: b_only,
            }

    # ---- 算法级对比（受粒度差异干扰，仅参考） -----------------------------
    sa, sb = algs_by_tool.get(a, set()), algs_by_tool.get(b, set())
    report['algorithm_coverage'] = {
        '%s_only' % a: sorted(sa - sb),
        '%s_only' % b: sorted(sb - sa),
        'both': sorted(sa & sb),
    }
    report['summary'] = {
        'files_compared': len(files),
        'lines_total': tot['both'] + tot['%s_only' % a] + tot['%s_only' % b],
        **tot,
        'note': '行级差异不受算法粒度影响，是漏报复核的主要线索；'
                '算法级差异受两家粒度不同的干扰（如 NIST PQC 大类 vs ML-KEM 细分），仅参考。',
    }
    return report
