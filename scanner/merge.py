"""多源证据融合 —— 把各 adapter 的 ToolGroup 融合成统一 Finding。

计数单位（core/schema/finding.v0.1.json 定死的口径）:
    一条 finding = 一个 (file, algorithm_normalized, usage) 组合。
    同组多处命中收进 evidence[].lines；同一算法同一文件、用途不同 = 两条。

两阶段融合:
    阶段一 分桶: 所有 ToolGroup 按 (file, alg_norm, usage) 入桶。
        两个工具同键的组天然落进同一桶 —— 这就是「多源证据挂一条」。

    阶段二 行号吸收: 同一 (file, alg_norm) 下，unknown 桶的行号若与某个
        具体用途桶的行号**精确重合**，说明那一行其实存在更细的用途判定
        （另一工具在同一行给出了 signing / encryption ...）。
        把这些行迁入对应具体桶，剩余行留在 unknown 桶。
        为什么需要这一步: cbom-scan 的 prim 粒度粗（RSA 只标 pke），
        不吸收的话同一行代码会被 unknown 和 signing 各算一遍；
        吸收后 unknown 桶只剩「两个工具都判不出用途」的行 —— 忠实且不重复。
        刻意用**精确行号匹配**（不做 ±1 模糊匹配）: 两个工具都是逐行扫描，
        行号对不上就是证据对不上，模糊匹配会把不同调用点错误合并。

字段合并规则（schema README 定死，不许改）:
    severity    取最大   真实使用不该被注释提及拉低。
                         「取最大」只作用于**上游给出的** severity；risk->severity
                         兜底仅在整桶都没有上游 severity 时使用（见下方注释）
    risk        取最严重 shor/broken > grover > review > safe（平级取 shor）
    confidence  取最大   有一个高置信源就值得人看
    usage       ——      用途不同根本不会进同一个桶

risk 裁决顺序（不透传上游结论）:
    1. cbom-scan 的 risk（模式证据主源，三个工具里唯一分类正确的）
    2. CryptoScan 的 type 查 RISK_BY_TYPE（zh_map 初版口径）
    3. 都没有 -> review（不猜）
CryptoScan 的 quantumRisk 只做字面对照，与最终裁决不一致时打
upstream-risk-corrected 标记 —— 「上游工具不可信、必须经融合层复核」
的显式证据（MD5 被它标成 Shor 可破就是这一档）。

关于克隆组的 raw: 行号吸收中给目标用途桶新建同工具组时，raw 与原组共享。
raw 是「该工具在该 (file, alg) 的判定材料」，用途归组是行号级的，
共享是如实反映「同一份上游记录被拆到两个用途桶」。
"""
import hashlib

from scanner.normalize import (
    RISK_BY_TYPE,
    SEVERITY_FROM_RISK,
    max_severity,
    most_severe_risk,
    usage_contradicts_algorithm,
)

#: evidence 排序：主源在前
_TOOL_ORDER = {'cbom-scan': 0, 'cryptoscan': 1}

TAG_NEEDS_USAGE_REVIEW = 'needs-usage-review'
TAG_UPSTREAM_RISK_CORRECTED = 'upstream-risk-corrected'


def merge(all_groups):
    """融合全部 ToolGroup，返回统一 Finding 列表（已排序，输出可复现）。

    行号吸收会重排组内行号，因此这里先浅拷贝每个组 ——
    **不污染调用方手里的原始数据**（coverage 差异审计需要吸收前的原始命中）。
    """
    by_key = {}
    for g in all_groups:
        g = dict(g)               # 浅拷贝；lines 后续都是整列替换，不会牵连原组
        by_key.setdefault((g['file'], g['alg_norm'], g['usage']), []).append(g)

    _absorb_unknown_lines(by_key)

    findings = []
    for (file, alg, usage), groups in sorted(by_key.items()):
        groups = [g for g in groups if g['lines']]
        if not groups:
            continue
        groups.sort(key=lambda g: _TOOL_ORDER.get(g['tool'], 9))

        evidences = [{
            'tool': g['tool'],
            'kind': 'pattern',
            'lines': sorted(set(g['lines'])),   # 去重设防：adapter 契约已去重，
            'raw': g['raw'],                    # 但克隆/吸收路径不该带出重复行号
        } for g in groups]

        all_lines = sorted(ln for g in groups for ln in g['lines'])

        # ---- risk 裁决（主源 cbom-scan 优先，其次 type 表，否则 review）
        risks = [g['risk'] for g in groups if g.get('risk') in
                 ('shor', 'broken', 'grover', 'review', 'safe')]
        if not risks:
            types = [t for g in groups for t in g.get('risk_types', [])]
            risks = [RISK_BY_TYPE[t] for t in types if t in RISK_BY_TYPE]
        risk = most_severe_risk(risks)

        # ---- severity / confidence
        # 「取最大」只作用于**上游给出的** severity（真实使用不该被注释提及拉低）。
        # risk->severity 兜底仅在整桶都没有上游 severity（cbom-only）时使用，
        # 不参与 max 竞争 —— 否则会把 CryptoScan 按上下文给出的打分系统性抬高
        # （实测: TLS 配置线索被它打 info，兜底 medium 会把整条抬到 medium）。
        severities = [g['severity'] for g in groups if g.get('severity')]
        if severities:
            severity = max_severity(severities)
        else:
            severity = SEVERITY_FROM_RISK[risk]

        confidences = [g['confidence'] for g in groups
                       if g.get('confidence') is not None]
        confidence = max(confidences) if confidences else None

        # ---- algorithm 保留上游原始写法，主源的写法优先
        algorithm = next((g['algorithm'] for g in groups
                          if g['tool'] == 'cbom-scan' and g.get('algorithm')), None)
        if not algorithm:
            algorithm = next((g['algorithm'] for g in groups
                              if g.get('algorithm')), alg)

        # ---- tags
        tags = []
        if usage == 'unknown':
            tags.append(TAG_NEEDS_USAGE_REVIEW)
        elif usage_contradicts_algorithm(alg, usage):
            # 上游 purpose 与算法大类确定性矛盾（如 RSA/hashing）——不改值，
            # 交 ai/ 模块复核，但必须显式标出来
            tags.append(TAG_NEEDS_USAGE_REVIEW)
        as_seen = {q for g in groups for q in g.get('quantum_as_seen', [])}
        if any(q != risk for q in as_seen):
            tags.append(TAG_UPSTREAM_RISK_CORRECTED)

        finding = {
            'schema_version': '0.1',
            'finding_id': _finding_id(file, alg, usage),
            'file': file,
            'line': all_lines[0],
            'algorithm': algorithm,
            'algorithm_normalized': alg,
            'usage': usage,
            'risk': risk,
            'severity': severity,
            'evidence': evidences,
        }
        if confidence is not None:
            finding['confidence'] = confidence
        if tags:
            finding['tags'] = sorted(tags)
        findings.append(finding)
    return findings


def _absorb_unknown_lines(by_key):
    """行号吸收（见模块 docstring 的阶段二）。就地修改 by_key。"""
    by_falg = {}
    for (file, alg, usage), groups in by_key.items():
        by_falg.setdefault((file, alg), {})[usage] = groups

    for usage_map in by_falg.values():
        spec_usages = [u for u in usage_map if u != 'unknown']
        if not spec_usages or 'unknown' not in usage_map:
            continue

        # 具体用途桶的行 -> 用途（同 (file, alg) 范围内）
        line_to_usage = {}
        for u in spec_usages:
            for g in usage_map[u]:
                for ln in g['lines']:
                    line_to_usage.setdefault(ln, u)

        for g in list(usage_map['unknown']):
            stay, moved = [], {}
            for ln in g['lines']:
                u = line_to_usage.get(ln)
                if u is not None:
                    moved.setdefault(u, []).append(ln)
                else:
                    stay.append(ln)
            for u, lns in moved.items():
                tg = next((x for x in usage_map[u]
                           if x['tool'] == g['tool']), None)
                if tg is None:
                    tg = dict(g)          # 克隆元数据，raw 共享（见模块 docstring）
                    tg['lines'] = []
                    tg['usage'] = u       # 归属已迁到具体用途桶，usage 随之更正
                    usage_map[u].append(tg)
                tg['lines'] = tg['lines'] + lns
            if stay:
                g['lines'] = stay
            else:
                usage_map['unknown'].remove(g)


def _finding_id(file, alg, usage):
    """schema 规定: sha1(file|algorithm_normalized|usage)[:12]，可复现。"""
    basis = '%s|%s|%s' % (file, alg, usage)
    return hashlib.sha1(basis.encode('utf-8')).hexdigest()[:12]
