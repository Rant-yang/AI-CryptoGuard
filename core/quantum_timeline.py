"""量子危机时间窗口评估（确定性规则，不调用 LLM）。

使用 Mosca 风险不等式：数据/安全有效期 X + 迁移准备期 Y >=
量子威胁时间窗 Z 时，应立即启动迁移。Z 必须由用户或组织策略提供；
本模块绝不预测所谓 Q-Day，也不替用户编造业务保密期限。
"""
import math

PROFILE_VERSION = "2026.10.15.1"
DIRECT_EFFECT = "shor"
CONFIDENTIALITY_USAGES = {"encryption", "key_exchange"}


def make_profile(data_lifetime_years=None, migration_lead_years=None,
                 threat_horizon_years=None, hndl_exposure="unknown",
                 source="user-input"):
    """构造并校验任务级时间参数；三个数字必须同时提供或同时省略。"""
    values = (data_lifetime_years, migration_lead_years, threat_horizon_years)
    supplied = [value is not None for value in values]
    if any(supplied) and not all(supplied):
        raise ValueError("量子时间窗口需要同时提供 X、Y、Z 三个参数")
    checked = []
    for value in values:
        if value is None:
            checked.append(None)
            continue
        number = float(value)
        if not math.isfinite(number) or number < 0 or number > 200:
            raise ValueError("量子时间参数必须是 0 到 200 之间的有限数字")
        checked.append(number)
    if hndl_exposure not in ("yes", "no", "unknown"):
        raise ValueError("hndl_exposure 必须是 yes、no 或 unknown")
    return {
        "profile_version": PROFILE_VERSION,
        "data_lifetime_years": checked[0],
        "migration_lead_years": checked[1],
        "threat_horizon_years": checked[2],
        "hndl_exposure": hndl_exposure,
        "source": source,
    }


def assess(quantum_effect, usage, profile=None):
    """返回可直接写入 quantum_assessment.quantum_timeline 的记录。"""
    profile = profile or make_profile(source="not-provided")
    base = {
        "status": "not_configured",
        "urgency": "unknown",
        "data_lifetime_years": profile["data_lifetime_years"],
        "migration_lead_years": profile["migration_lead_years"],
        "threat_horizon_years": profile["threat_horizon_years"],
        "years_until_action": None,
        "hndl_exposure": profile["hndl_exposure"],
        "hndl_status": "unknown",
        "profile_version": profile["profile_version"],
        "source": profile["source"],
        "rule_refs": [],
        "assumptions": [],
    }
    if quantum_effect != DIRECT_EFFECT:
        base.update(status="not_applicable", urgency="not_applicable",
                    hndl_status="not_applicable",
                    assumptions=["时间窗口当前只用于受 Shor 直接威胁的传统公钥密码。"])
        return base

    x = profile["data_lifetime_years"]
    y = profile["migration_lead_years"]
    z = profile["threat_horizon_years"]
    if None in (x, y, z):
        base["assumptions"] = [
            "未提供完整 X/Y/Z；系统不预测 Q-Day，也不代填业务保密期限。"
        ]
        return base

    start_in = round(z - x - y, 3)
    base.update(
        status="assessed",
        urgency="immediate" if start_in <= 0 else "scheduled",
        years_until_action=max(0.0, start_in),
        rule_refs=["QT-MOSCA-WINDOW"],
        assumptions=["X/Y/Z 均来自任务输入；任一参数改变都必须重新评估。"],
    )

    exposure = profile["hndl_exposure"]
    if usage == "signing":
        base["hndl_status"] = "not_applicable"
        base["assumptions"].append("签名用途不按密文先收集后解密评估。")
    elif usage in CONFIDENTIALITY_USAGES:
        if exposure == "yes":
            base["hndl_status"] = "at_risk" if x >= z else "watch"
            base["rule_refs"].append("QT-HNDL-CONFIDENTIALITY")
        elif exposure == "no":
            base["hndl_status"] = "not_indicated"
        else:
            base["hndl_status"] = "unknown"
            base["assumptions"].append("尚未确认攻击者能否收集该密文流量或存档。")
    else:
        base["hndl_status"] = "unknown"
        base["assumptions"].append("实际用途未知，无法确定是否属于保密数据流。")
    return base


def _selftest():
    immediate = assess("shor", "encryption", make_profile(10, 3, 8, "yes"))
    assert immediate["urgency"] == "immediate"
    assert immediate["years_until_action"] == 0
    assert immediate["hndl_status"] == "at_risk"

    scheduled = assess("shor", "signing", make_profile(2, 2, 10, "no"))
    assert scheduled["urgency"] == "scheduled"
    assert scheduled["years_until_action"] == 6
    assert scheduled["hndl_status"] == "not_applicable"

    missing = assess("shor", "unknown")
    assert missing["status"] == "not_configured"
    assert missing["years_until_action"] is None
    assert assess("quantum_search", "encryption")["status"] == "not_applicable"
    try:
        make_profile(10, None, 8)
        raise AssertionError("incomplete profile accepted")
    except ValueError:
        pass
    print("PASS: quantum timeline window + HNDL rules")


if __name__ == "__main__":
    _selftest()
