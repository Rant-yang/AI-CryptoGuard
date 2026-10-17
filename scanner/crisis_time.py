"""危机时间双轨标注 —— 确定性规则，不调用 LLM，不预测 Q-Day。

A 在 scanner 侧实现、位于扫描之后 / 量子评估之前（团队 2026-10 新分工）。
两条轨道：

轨道一 · 静态算法时间线
    按 finding.risk 五档给出权威机构的迁移窗口建议（crisis_class），附权威
    出处与建议迁移年份。**crisis_class 由逐 finding 的 risk 决定，而非算法名
    单独决定** —— 实测同一算法（RSA）短密钥时 broken、正常长度时 shor，用算法
    名固定 crisis_class 会自相矛盾。算法名只补充年份锚点与出处。

轨道二 · X/Y/Z Mosca 窗口
    复用 core.quantum_timeline.assess，公式仍来自 core（A 不重写、不编造）。
    quantum_effect 由 risk 映射，口径与 core/quantum_assessment.RISK_RULE
    完全一致，保证 C 后续把 window 直接搬进 quantum_assessment.quantum_timeline
    时结构逐键对齐。

红线（仓库约定，必须守住）:
    - 系统不预测 Q-Day；advisory_deadline_year 只引用权威机构的公开建议
      （NIST IR 8547 / BSI 对传统公钥给出的 2030 迁移节点）。
    - 不代填 X/Y/Z；三个数字缺一即 window.status=not_configured。
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.quantum_timeline import assess as _assess_timeline   # noqa: E402
from scanner.normalize import canon_algorithm                   # noqa: E402

#: crisis_class 唯一真源：risk 五档 → crisis_class。
#: 见模块 docstring —— 不查算法名判 class，避免同一算法多 risk 时矛盾。
CRISIS_CLASS_BY_RISK = {
    'broken': 'imminent',        # 经典已破（SP 800-131A 已禁用），立即整改
    'shor': 'near',              # Shor 直接威胁，权威建议近期（2030 前）迁移
    'grover': 'distant',         # Grover 折半，不直接破解，远期
    'safe': 'none',              # 健全 / 后量子，无危机
    'review': 'unknown',         # 拿不准，如实 unknown
    'not_applicable': 'none',    # 凭据/配置类，无量子危机
}

#: 权威出处按 crisis_class（量子危机维度）。
REFERENCE_BY_CLASS = {
    'imminent': ['NIST SP 800-131A Rev.2'],
    'near': ['NIST IR 8547', 'BSI'],
    'distant': ['NIST PQC Security Evaluation Criteria'],
    'none': [],
    'unknown': [],
}

#: 传统公钥（Shor 直接威胁）的权威迁移年份锚点。只作带出处的锚点，
#: 不是系统预测 Q-Day —— NIST IR 8547 / BSI 建议 2030 年前完成迁移。
ADVISORY_DEADLINE_YEAR_BY_ALGO = {
    'RSA': 2030, 'ECC': 2030, 'ECDSA': 2030, 'ECDH': 2030,
    'DSA': 2030, 'DH': 2030, 'DIFFIEHELLMAN': 2030,
    'ED25519': 2030, 'X25519': 2030, 'ED25519X25519': 2030,
}
#: risk=shor 但算法名表外时的兜底年份（仍取权威 2030 节点）。
SHOR_MIGRATION_YEAR = 2030

#: risk → quantum_effect，口径与 core/quantum_assessment.RISK_RULE 完全一致
#: （review 走 assess_one 的 else 分支 quantum_effect='unknown'；
#:  not_applicable 走 credential/not_applicable 分支 'not_applicable'）。
_RISK_TO_QUANTUM_EFFECT = {
    'shor': 'shor',
    'grover': 'quantum_search',
    'broken': 'no_known_quantum_break',
    'safe': 'no_known_quantum_break',
    'review': 'unknown',
    'not_applicable': 'not_applicable',
}

#: 静态轨道的固定假设说明（写进每条 finding 的 assumptions）。
STATIC_ASSUMPTIONS = [
    '静态时间线为权威机构公开迁移建议（NIST IR 8547 / BSI / SP 800-131A Rev.2），'
    '不是系统对 Q-Day 的预测。',
]


def static_crisis(finding):
    """轨道一：静态算法时间线（不依赖 X/Y/Z，永远能算）。

    返回 dict: crisis_class / advisory_deadline_year / references / assumptions。
    crisis_class 由 finding.risk 决定；advisory_deadline_year 仅 near 档
    （传统公钥）给 2030 锚点，其余为 None。
    """
    risk = finding.get('risk', 'review')
    crisis_class = CRISIS_CLASS_BY_RISK.get(risk, 'unknown')
    year = None
    if crisis_class == 'near':
        alg = canon_algorithm(finding.get('algorithm_normalized')
                              or finding.get('algorithm') or '')
        year = ADVISORY_DEADLINE_YEAR_BY_ALGO.get(alg, SHOR_MIGRATION_YEAR)
    return {
        'crisis_class': crisis_class,
        'advisory_deadline_year': year,
        'references': list(REFERENCE_BY_CLASS.get(crisis_class, [])),
        'assumptions': list(STATIC_ASSUMPTIONS),
    }


def _window(finding, profile):
    """轨道二：X/Y/Z Mosca 窗口，复用 core.quantum_timeline.assess。"""
    effect = _RISK_TO_QUANTUM_EFFECT.get(finding.get('risk'), 'unknown')
    usage = finding.get('usage', 'unknown')
    return _assess_timeline(effect, usage, profile)


def annotate(finding, profile=None):
    """为一条 finding 计算 crisis_time（双轨），返回 crisis_time dict。"""
    return {
        'static': static_crisis(finding),
        'window': _window(finding, profile),
    }


def annotate_all(findings, profile=None):
    """就地给每条算法类 finding 加 crisis_time 字段（凭据类跳过）。"""
    for f in findings:
        if f.get('finding_kind') == 'credential':
            continue
        f['crisis_time'] = annotate(f, profile)
    return findings


def profile_from_args(data_lifetime_years, migration_lead_years,
                      threat_horizon_years, hndl_exposure='unknown'):
    """从 CLI 参数构造 quantum_timeline profile（复用 core，不重写）。

    三个数字必须同时提供或同时省略（core.quantum_timeline.make_profile 已校验，
    缺一则抛 ValueError）。缺省时 source='not-provided'，window 落 not_configured，
    静态轨道仍生效。
    """
    from core.quantum_timeline import make_profile
    return make_profile(
        data_lifetime_years, migration_lead_years, threat_horizon_years,
        hndl_exposure,
        'user-input' if data_lifetime_years is not None else 'not-provided')


def _selftest():
    from core.quantum_timeline import assess as _a, make_profile

    # 静态轨道：risk 五档 → crisis_class
    assert static_crisis({'risk': 'broken'})['crisis_class'] == 'imminent'
    assert static_crisis({'risk': 'shor'})['crisis_class'] == 'near'
    assert static_crisis({'risk': 'grover'})['crisis_class'] == 'distant'
    assert static_crisis({'risk': 'safe'})['crisis_class'] == 'none'
    assert static_crisis({'risk': 'review'})['crisis_class'] == 'unknown'
    assert static_crisis({'risk': 'not_applicable'})['crisis_class'] == 'none'

    # 年份锚点：near 给 2030，其余 None
    assert static_crisis({'risk': 'shor', 'algorithm_normalized': 'RSA'})[
        'advisory_deadline_year'] == 2030
    assert static_crisis({'risk': 'broken'})['advisory_deadline_year'] is None

    # 权威出处
    assert static_crisis({'risk': 'broken'})['references'] == \
        ['NIST SP 800-131A Rev.2']
    assert static_crisis({'risk': 'shor'})['references'] == ['NIST IR 8547', 'BSI']

    # 同一算法不同 risk 不矛盾（实测 RSA 双档）
    assert static_crisis({'risk': 'shor', 'algorithm_normalized': 'RSA'})[
        'crisis_class'] == 'near'
    assert static_crisis({'risk': 'broken', 'algorithm_normalized': 'RSA'})[
        'crisis_class'] == 'imminent'

    # 轨道二：与 core.quantum_timeline.assess 完全一致
    prof = make_profile(10, 3, 8, 'yes')
    got = _window({'risk': 'shor', 'usage': 'encryption'}, prof)
    assert got == _a('shor', 'encryption', prof)
    assert got['urgency'] == 'immediate'
    assert got['hndl_status'] == 'at_risk'
    assert _window({'risk': 'grover', 'usage': 'hashing'}, prof)['status'] == \
        'not_applicable'
    assert _window({'risk': 'broken', 'usage': 'hashing'}, prof)['status'] == \
        'not_applicable'

    # 缺 profile → not_configured，静态轨道仍出结果
    out = annotate({'risk': 'shor', 'usage': 'encryption'})
    assert out['static']['crisis_class'] == 'near'
    assert out['window']['status'] == 'not_configured'
    assert out['window']['source'] == 'not-provided'

    # 结构契约：static + window 两键齐全，static 四键齐全
    assert set(out.keys()) == {'static', 'window'}
    assert set(out['static'].keys()) == {
        'crisis_class', 'advisory_deadline_year', 'references', 'assumptions'}

    # annotate_all：算法类加字段、凭据类跳过
    rows = [{'risk': 'broken', 'usage': 'hashing'},
            {'risk': 'not_applicable', 'finding_kind': 'credential'}]
    annotate_all(rows)
    assert 'crisis_time' in rows[0]
    assert 'crisis_time' not in rows[1]

    # profile_from_args：缺省 → not-provided
    p = profile_from_args(None, None, None)
    assert p['source'] == 'not-provided'
    print('PASS: crisis_time dual-track annotation')


if __name__ == '__main__':
    _selftest()
