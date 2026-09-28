"""PQC 迁移路线判定 —— 方案 §9.1 的落地实现。

方案硬性规定：
    **禁止简单的 `RSA -> 固定某一种 PQC` 的映射。**

为什么：公钥算法（RSA / ECC）在体系里承担两种完全不同的职责，
迁移路线完全不同 ——

    签名场景    ->  ML-DSA (FIPS 204) / SLH-DSA (FIPS 205)
    加密场景    ->  ML-KEM (FIPS 203)
    密钥交换    ->  ML-KEM (FIPS 203)

把 RSA 一律映射到 ML-KEM，会让所有签名场景给出错误建议。

所以本模块把「生成算法建议」这件事**从大模型手里拿走**：
    LLM 只负责判断用途（签名？加密？）  ->  本模块查表给出算法
用途判不出来时，本模块明确返回 decided=False（「暂不给出具体算法」），
**不允许猜**。

纯标准库，无依赖。可被 ai/ 与 core/ 直接 import。

用法:
    from core.rules.pqc_routing import route
    route('RSA', 'signing')
    # -> {'decided': True, 'action': '签名场景 -> ML-DSA ...', 'source': 'rule-base', ...}

自检:
    python core/rules/pqc_routing.py
"""

# ---------------------------------------------------------------- 用途分类

#: 需要按用途分派的算法（公钥类）
PURPOSE_DEPENDENT = frozenset({
    'RSA', 'ECC', 'ECDSA', 'ECDH', 'DSA', 'DH',
    'ED25519', 'X25519', 'EDDSA',
})

#: 用途取值 -> (建议文本, 标准依据)
#: 取值集合与 core/schema/finding.v0.1.json 的 usage enum 保持一致。
_BY_USAGE = {
    'signing': (
        '签名场景 -> ML-DSA (FIPS 204)；需保守时可选 SLH-DSA (FIPS 205)；'
        '过渡期用「RSA/ECC + ML-DSA」复合签名。',
        ['FIPS 204', 'FIPS 205'],
    ),
    'encryption': (
        '加密/密钥运输场景 -> ML-KEM (FIPS 203) + 对称加密 (AES-256/SM4)；'
        '过渡期用「RSA + ML-KEM」混合。',
        ['FIPS 203'],
    ),
    'key_exchange': (
        '密钥交换场景 -> ML-KEM (FIPS 203)；过渡期用「ECDHE + ML-KEM」混合。',
        ['FIPS 203'],
    ),
}

#: 用途未判定时的输出。注意：这是**正确的输出**，不是错误。
UNDECIDED = (
    '用途未能判定 -> 暂不给出具体算法。需先确认该公钥算法承担的是签名还是'
    '加密/密钥交换：签名 -> ML-DSA / SLH-DSA，加密或密钥交换 -> ML-KEM。'
    '两者迁移路线不同，不能套用固定映射。'
)

#: 非公钥类算法（对称/哈希）：量子风险性质不同，不走用途分派。
#: 这些算法不因用途改变迁移目标，直接给确定结论。
_BY_ALGORITHM = {
    'MD5': ('完整性校验改用 SHA-256 或 SHA-3；认证场景改用 HMAC。',
            ['NIST SP 800-131A Rev 2']),
    'SHA1': ('改用 SHA-256 或 SHA-3。', ['NIST SP 800-131A Rev 2']),
    'DES': ('立即改用 AES-256-GCM。', ['NIST SP 800-131A Rev 2']),
    '3DES': ('改用 AES-256-GCM。', ['NIST SP 800-131A Rev 2']),
    'AES': ('使用 AES-256 并配合 GCM 工作模式。', ['NIST SP 800-38D']),
    'SHA256': ('当前安全；长期建议向 SHA-3 迁移。', ['FIPS 180-4']),
    'SHA3': ('量子安全，无需迁移。', ['FIPS 202']),
    'CHACHA20': ('优秀选择，已被 TLS 1.3 采纳。', ['RFC 8439']),
}


def _norm(s):
    """归一化算法名：大写、去掉非字母数字。

    三个工具对同一算法叫法不同（'Ed25519 / X25519' / 'Ed25519' / 'ed25519'），
    不归一会导致查表失败。
    """
    if not s:
        return ''
    return ''.join(ch for ch in s.upper() if ch.isalnum())


def route(algorithm, usage, algorithm_normalized=None):
    """给出迁移/修复建议。

    Args:
        algorithm: 算法名，原始写法即可（如 'RSA', 'Ed25519 / X25519'）
        usage: 用途，取值见 schema 的 usage enum
        algorithm_normalized: 已归一化的算法名（可选，省一次计算）

    Returns:
        dict，可直接作为 schema 里 `remediation` 字段的值：
            decided  : bool   —— 是否已给出确定结论
            action   : str    —— 建议文本
            source   : str    —— 'rule-base'（确定性密码事实，不由大模型生成）
            references: list  —— 标准依据
    """
    key = _norm(algorithm_normalized or algorithm)

    # 1) 公钥类：必须按用途分派 —— 这是方案 §9.1 的核心
    if _is_public_key(key):
        hit = _BY_USAGE.get(usage)
        if hit is None:
            # 用途缺失 / unknown / 无法识别 —— 明确拒绝给出算法
            return _undecided()
        return {
            'decided': True,
            'action': hit[0],
            'source': 'rule-base',
            'references': hit[1],
        }

    # 2) 非公钥类：迁移目标不随用途改变，直接给确定结论
    hit = _BY_ALGORITHM.get(key)
    if hit:
        return {
            'decided': True,
            'action': hit[0],
            'source': 'rule-base',
            'references': hit[1],
        }

    # 3) 规则库未覆盖 —— 如实说不知道，不要编
    return {
        'decided': False,
        'action': '规则库未覆盖该算法，需人工确认。',
        'source': 'rule-base',
        'references': [],
    }


def _is_public_key(key):
    """公钥类判定。用前缀匹配兜住 'RSA2048' / 'ECDSA_P256' 这类写法。"""
    if key in PURPOSE_DEPENDENT:
        return True
    return any(key.startswith(p) for p in ('RSA', 'ECC', 'ECDSA', 'ECDH',
                                           'ED25519', 'X25519', 'EDDSA'))


def _undecided():
    return {
        'decided': False,
        'action': UNDECIDED,
        'source': 'rule-base',
        'references': ['FIPS 203', 'FIPS 204', 'FIPS 205'],
    }


# ---------------------------------------------------------------- 自检

def _selftest():
    """硬编码断言，不复述实现逻辑 —— 只断言真实的密码学约定。

    这些断言是**外部事实**（用途决定路线），不是"代码就是这么写的"。
    """
    fails = []

    def check(desc, got, want):
        if got != want:
            fails.append('%s\n     期望 %r\n     得到 %r' % (desc, want, got))

    # --- 同一个算法，不同用途，必须给出不同路线 ---
    sig = route('RSA', 'signing')
    enc = route('RSA', 'encryption')
    kex = route('RSA', 'key_exchange')

    check('RSA/签名 应给出 ML-DSA', 'ML-DSA' in sig['action'], True)
    check('RSA/加密 应给出 ML-KEM', 'ML-KEM' in enc['action'], True)
    check('RSA/密钥交换 应给出 ML-KEM', 'ML-KEM' in kex['action'], True)

    # 这是 §9.1 的核心：签名路线绝不能出现 ML-KEM
    check('RSA/签名 不得出现 ML-KEM（§9.1 禁止固定映射）',
          'ML-KEM' in sig['action'], False)
    # 反过来，加密路线也不该给签名算法
    check('RSA/加密 不得给出 ML-DSA 签名路线',
          'ML-DSA (FIPS 204)' in enc['action'], False)

    # --- 用途判不出来，必须 decided=False，不许猜 ---
    #     注意：未判定的文案里**会**提到 ML-DSA / ML-KEM —— 但那是并列解释
    #     「签名走哪条、加密走哪条」，不是在给结论。所以断言的是
    #     decided=False + 明说不给算法，而不是"文案里不出现算法名"。
    for bad_usage in ('unknown', None, '', 'general'):
        r = route('RSA', bad_usage)
        check('RSA/用途=%r 必须拒绝给出算法' % bad_usage, r['decided'], False)
        check('RSA/用途=%r 必须明说未给算法' % bad_usage,
              '暂不给出具体算法' in r['action'], True)
        check('RSA/用途=%r 必须要求先确认用途' % bad_usage,
              '签名' in r['action'] and '加密' in r['action'], True)

    # --- 非公钥类：结论不随用途改变 ---
    check('MD5 判为已攻破，与用途无关',
          route('MD5', 'hashing')['action'] == route('MD5', 'unknown')['action'],
          True)
    check('MD5 建议应指向 SHA-256 或 SHA-3',
          'SHA-256' in route('MD5', 'hashing')['action'], True)

    # --- 算法名归一化：三种写法必须命中同一规则 ---
    for name in ('Ed25519', 'ed25519', 'Ed25519 / X25519', 'EDDSA'):
        r = route(name, 'signing')
        check('算法名 %r 应被识别为公钥类并走签名路线' % name,
              'ML-DSA' in r['action'], True)

    # --- 签名场景永远不该出现 ML-KEM（跨所有公钥算法抽查）---
    for name in ('RSA', 'ECC', 'ECDSA', 'Ed25519', 'DSA'):
        check('%s/签名 不得出现 ML-KEM' % name,
              'ML-KEM' in route(name, 'signing')['action'], False)

    # --- 输出结构必须能直接填进 schema 的 remediation ---
    r = route('RSA', 'signing')
    for field in ('decided', 'action', 'source', 'references'):
        check('输出应含 schema 要求的 %r 字段' % field, field in r, True)

    if fails:
        print('[FAIL] %d 项断言未通过:' % len(fails))
        for f in fails:
            print('  - %s' % f)
        return 1

    print('[PASS] 全部断言通过')
    print()
    print('  演示 —— 同一算法、不同用途、不同路线:')
    for u in ('signing', 'encryption', 'key_exchange', 'unknown'):
        r = route('RSA', u)
        flag = 'OK ' if r['decided'] else '拒绝'
        print('    RSA / %-13s [%s] %s' % (u, flag, r['action'][:56]))
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(_selftest())
