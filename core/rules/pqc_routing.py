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

# A generic RSA/ECC inventory item does not identify the protocol role.  A
# named signature or agreement primitive does: never route an impossible
# (algorithm, usage) pair to an otherwise valid PQC standard.
_SIGNATURE_ONLY = ('ECDSA', 'ED25519', 'EDDSA', 'DSA')
_AGREEMENT_ONLY = ('ECDH', 'X25519', 'DH')


def usage_compatible(algorithm, usage, algorithm_normalized=None):
    """Whether a *specific* public-key primitive can serve the claimed role.

    This is only a rejection guard, not evidence that the role is actually used.
    Combined upstream family labels remain ambiguous and need call evidence.
    """
    if usage not in ('signing', 'encryption', 'key_exchange'):
        return True
    # The canonical scanner bucket may be generic ECC even when the raw name
    # identifies a narrower primitive.  A generic alias must not erase that
    # semantic restriction.
    raw = _norm(algorithm)
    key = raw if raw.startswith(_SIGNATURE_ONLY + _AGREEMENT_ONLY +
                                ('ED25519X25519', 'ECDSAEC')) else \
        _norm(algorithm_normalized or algorithm)
    if key.startswith(('ED25519X25519', 'ECDSAEC')):
        return usage != 'encryption' if key.startswith('ED25519X25519') else True
    if key.startswith(_SIGNATURE_ONLY):
        return usage == 'signing'
    if key.startswith(_AGREEMENT_ONLY):
        return usage == 'key_exchange'
    return True

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

#: 非公钥类算法（对称/哈希/PQC/KDF）：量子风险性质不同，不走用途分派。
#: 这些算法不因用途改变迁移目标，直接给确定结论。
#:
#: 2026-10-03 大幅扩充。起因是实测：91 条 finding 里 **56 条**命中「规则库未覆盖」，
#: 而其中大多数并不是「不知道」，是表里没写 —— 表原来只有 8 条，而数据里有 32 个
#: 算法名。最扎眼的是 **ML-KEM / ML-DSA 本身就在这张表里查不到**，
#: 于是建议别人迁移过去的目标算法，自己反而报「需人工确认」。
_BY_ALGORITHM = {
    # ---- 已被攻破 / 应淘汰 ----
    'MD5': ('完整性校验改用 SHA-256 或 SHA-3；认证场景改用 HMAC。',
            ['NIST SP 800-131A Rev 2']),
    'SHA1': ('改用 SHA-256 或 SHA-3。', ['NIST SP 800-131A Rev 2']),
    'DES': ('立即改用 AES-256-GCM。', ['NIST SP 800-131A Rev 2']),
    '3DES': ('改用 AES-256-GCM。', ['NIST SP 800-131A Rev 2']),
    'DESEDE': ('改用 AES-256-GCM。', ['NIST SP 800-131A Rev 2']),
    'RC4': ('立即停用，改用 AES-256-GCM 或 ChaCha20-Poly1305。',
            ['RFC 7465']),
    'RC2': ('立即停用，改用 AES-256-GCM。', ['NIST SP 800-131A Rev 2']),

    # ---- 已淘汰的分组密码：**64 位分组是共同死因** ----
    #      这批不是想出来的，是 2026-10-04 复核时从真实 benchmark 数据里发现的：
    #      LLM-CMT 的 716 条真实代码里它们都出现过，而当时的表查不到 ——
    #      答辩被问「MD4 呢」就是一句 `rule-missing`。见 benchmark/scope.py --gaps。
    #      64 位分组（Blowfish/CAST5/IDEA/RC5/TEA/XTEA）的迁移结论是同一条，
    #      因为风险同源：生日界只有 2^32，长连接下 Sweet32 可恢复明文。
    'BLOWFISH': ('64 位分组，长连接下存在 Sweet32 明文恢复风险'
                 '（CVE-2016-2183）。立即改用 AES-256-GCM。',
                 ['CVE-2016-2183 (Sweet32)', 'NIST SP 800-131A Rev 2']),
    'CAST': ('CAST5 为 64 位分组，同 Sweet32 风险。改用 AES-256-GCM。',
             ['RFC 2144', 'CVE-2016-2183 (Sweet32)']),
    'CAST5': ('CAST5 为 64 位分组，同 Sweet32 风险。改用 AES-256-GCM。',
              ['RFC 2144', 'CVE-2016-2183 (Sweet32)']),
    'IDEA': ('IDEA 为 64 位分组且已不在 NIST 批准列表内。改用 AES-256-GCM。',
             ['NIST SP 800-131A Rev 2']),
    'RC5': ('RC5 分组偏小（默认 64 位）、密钥调度弱，已不推荐。'
            '改用 AES-256-GCM。', ['RFC 2040']),
    'TEA': ('TEA 存在相关密钥攻击且为 64 位分组，已不推荐。'
            '改用 AES-256-GCM。', ['Needham & Wheeler, TEA (1994)']),
    'XTEA': ('XTEA 修补了 TEA 的密钥调度，但仍是 64 位分组，不推荐用于新系统。'
             '改用 AES-256-GCM。', ['Needham & Wheeler, XTEA (1998)']),
    'NULLCIPHER': ('NullCipher **完全不加密**（密文即明文），'
                   '出现它说明该处根本没有做加密。必须改为真实的 AEAD 加密。',
                   ['Java Cryptography Architecture (JCA) 参考指南']),

    # ---- 已淘汰的哈希：MD2 / MD4 早于 MD5 被攻破 ----
    'MD2': ('MD2 已完全不可用（校验和构造即被攻破）。'
            '完整性校验改用 SHA-256 / SHA-3。', ['RFC 1319']),
    'MD4': ('MD4 已被实际碰撞攻击攻破，远比 MD5 更早失效。'
            '完整性校验改用 SHA-256 / SHA-3，认证场景改用 HMAC。',
            ['RFC 6150（已列为 Historic）', 'RFC 1320']),

    # ---- 对称加密：Grover 使强度减半，256 位仍安全 ----
    'AES': ('使用 AES-256 并配合 GCM 工作模式。', ['NIST SP 800-38D']),
    'AES128': ('建议升到 AES-256：Grover 下 AES-128 有效强度约 64 位。'
               '工作模式改用 GCM。', ['NIST SP 800-38D']),
    'AES192': ('建议升到 AES-256，工作模式改用 GCM。', ['NIST SP 800-38D']),
    'AES256': ('AES-256 在 Grover 下仍有约 128 位有效强度，当前安全。'
               '确认使用 GCM 等 AEAD 模式，不要用 ECB。', ['NIST SP 800-38D']),
    'AESGCM': ('AES-GCM 是推荐用法，AES-256-GCM 在 Grover 下仍安全。',
               ['NIST SP 800-38D']),
    'AES256GCM': ('AES-256-GCM 是推荐用法，Grover 下仍安全。',
                  ['NIST SP 800-38D']),
    'AESCBC': ('CBC 无认证，改用 AES-256-GCM 等 AEAD 模式。',
               ['NIST SP 800-38D']),
    'AESCTR': ('CTR 无认证，改用 AES-256-GCM 等 AEAD 模式。',
               ['NIST SP 800-38D']),
    'AESECB': ('ECB 会泄露明文结构，必须立即改用 AES-256-GCM。',
               ['NIST SP 800-38A']),
    'CHACHA20': ('优秀选择，已被 TLS 1.3 采纳；Grover 下强度减半仍安全。',
                 ['RFC 8439']),
    'CHACHA20POLY1305': ('推荐的 AEAD，TLS 1.3 采纳；Grover 下强度减半仍安全。',
                         ['RFC 8439']),
    'POLY1305': ('一次性认证标签，须与 ChaCha20 搭配使用，不可单独用于加密。',
                 ['RFC 8439']),
    'CAMELLIA': ('可用；建议升到 256 位并配合 GCM。', ['RFC 3713']),
    'SM4': ('国密分组密码；建议升至 256 位强度并配合 GCM 类模式。',
            ['GB/T 32907-2016']),

    # ---- 哈希：Grover 只影响原像，不影响抗碰撞 ----
    'SHA256': ('当前安全；长期建议向 SHA-3 迁移。', ['FIPS 180-4']),
    'SHA384': ('当前安全；长期建议向 SHA-3 迁移。', ['FIPS 180-4']),
    'SHA512': ('当前安全；长期建议向 SHA-3 迁移。', ['FIPS 180-4']),
    'SHA224': ('建议改用 SHA-256 / SHA-384 或 SHA-3。', ['FIPS 180-4']),
    'SHA384512SHA2': ('SHA-384 / SHA-512 当前安全；长期建议向 SHA-3 迁移。',
                      ['FIPS 180-4']),
    'SHA3': ('量子安全，无需迁移。', ['FIPS 202']),
    'SHA3SHAKE': ('SHA-3 / SHAKE 量子安全，无需迁移。', ['FIPS 202']),
    'SHAKE128': ('SHAKE128 量子安全，无需迁移。', ['FIPS 202']),
    'SHAKE256': ('SHAKE256 量子安全，无需迁移。', ['FIPS 202']),
    'SM3': ('国密哈希；当前安全，长期建议向 SHA-3 迁移。',
            ['GB/T 32905-2016']),

    # ---- 口令哈希 / KDF：主要看参数，不看量子 ----
    'BCRYPT': ('口令哈希，量子威胁有限（Grover 对慢哈希影响很小）；'
               '建议 cost >= 12，新系统可考虑 Argon2id。', ['NIST SP 800-63B']),
    'SCRYPT': ('口令哈希，参数需满足内存与并行度要求；可考虑 Argon2id。',
               ['RFC 7914']),
    'ARGON2': ('当前推荐的口令哈希；确认参数满足 OWASP 建议，'
               '量子威胁有限。', ['RFC 9106']),
    'ARGON2ID': ('Argon2id 是当前推荐的口令哈希变体；确认参数满足 OWASP 建议，'
                 '量子威胁有限。', ['RFC 9106']),
    'ARGON2I': ('Argon2i 抗侧信道但不抗 GPU；口令哈希建议改用 Argon2id。',
                ['RFC 9106']),
    'ARGON2D': ('Argon2d 抗 GPU 但不抗侧信道；口令哈希建议改用 Argon2id。',
                ['RFC 9106']),
    'PBKDF2': ('口令派生；迭代次数需达标，新系统建议迁移 Argon2id。',
               ['NIST SP 800-132']),
    'HKDF': ('密钥派生函数，本身无量子弱点，安全性取决于底层哈希；'
             '底层建议 SHA-256 及以上或 SHA-3。', ['RFC 5869']),
    'KMAC': ('基于 SHA-3 的 MAC，量子安全。', ['NIST SP 800-185']),
    'HMAC': ('MAC，安全性取决于底层哈希；建议底层用 SHA-256 及以上。',
             ['RFC 2104']),
    # HMAC 的具体写法要单独收录，不能只写笼统的 `HMAC` ——
    # 实测上游报的是 `HmacMD5` / `HmacSHA1` / `HmacSHA256`，
    # 归一化后是 `HMACMD5` 这类整体名，只收 `HMAC` 会一条都对不上。
    'HMACMD5': ('HMAC 本身不是弱点，问题在底层 MD5 已被攻破。'
                '改用 HMAC-SHA-256。', ['RFC 2104', 'RFC 6151']),
    'HMACSHA1': ('HMAC 本身不是弱点，问题在底层 SHA-1 已被攻破。'
                 '改用 HMAC-SHA-256。', ['RFC 2104', 'RFC 6194']),
    'HMACSHA256': ('HMAC-SHA-256 是当前推荐用法；'
                   '量子威胁主要是 Grover，对 256 位哈希影响有限。',
                   ['RFC 2104', 'FIPS 180-4']),
    'CMAC': ('MAC，安全性取决于底层分组密码；建议底层用 AES-256。',
             ['NIST SP 800-38B']),

    # ---- 已经是 PQC：无需迁移，本表必须收录，否则会出现
    #      「建议迁移到 ML-KEM，而 ML-KEM 自己报规则库未覆盖」的荒谬情况 ----
    'MLKEM': ('ML-KEM 已是 NIST 标准化的 PQC 密钥封装算法（FIPS 203），'
              '量子安全，无需迁移。', ['FIPS 203']),
    'MLKEM512': ('ML-KEM-512 已是 PQC 标准算法；安全等级低于 768/1024，'
                 '通用场景建议至少 ML-KEM-768。', ['FIPS 203']),
    'MLKEM768': ('ML-KEM-768 已是 PQC 标准算法，量子安全，无需迁移。',
                 ['FIPS 203']),
    'MLKEM1024': ('ML-KEM-1024 已是 PQC 标准算法，量子安全，无需迁移。',
                  ['FIPS 203']),
    'KYBER': ('Kyber 已标准化为 ML-KEM（FIPS 203）；建议迁移到标准名称与参数。',
              ['FIPS 203']),
    'MLDSA': ('ML-DSA 已是 NIST 标准化的 PQC 签名算法（FIPS 204），'
              '量子安全，无需迁移。', ['FIPS 204']),
    'MLDSA44': ('ML-DSA-44 已是 PQC 标准算法；安全等级最低，'
                '通用场景建议至少 ML-DSA-65。', ['FIPS 204']),
    'MLDSA65': ('ML-DSA-65 已是 PQC 标准算法，量子安全，无需迁移。',
                ['FIPS 204']),
    'MLDSA87': ('ML-DSA-87 已是 PQC 标准算法，量子安全，无需迁移。',
                ['FIPS 204']),
    'DILITHIUM': ('Dilithium 已标准化为 ML-DSA（FIPS 204）；'
                  '建议迁移到标准名称与参数。', ['FIPS 204']),
    'SLHDSA': ('SLH-DSA 已是 NIST 标准化的 PQC 签名算法（FIPS 205），'
               '量子安全。签名体积大、速度慢，适合作为保守备选。',
               ['FIPS 205', 'NIST SP 800-208']),
    'SPHINCS': ('SPHINCS+ 已标准化为 SLH-DSA（FIPS 205）。',
                ['FIPS 205']),
    'LMS': ('LMS 是 NIST 认可的有状态哈希签名（SP 800-208），量子安全；'
            '注意签名状态不可回滚或重复使用。', ['NIST SP 800-208']),
    'XMSS': ('XMSS 是 NIST 认可的有状态哈希签名（SP 800-208），量子安全；'
             '注意签名状态不可回滚或重复使用。', ['NIST SP 800-208']),
    'HYBRIDKEM': ('混合密钥封装（经典 + PQC）是过渡期推荐做法，'
                  '在经典与 PQC 两侧都保持安全。', ['NIST SP 800-56C']),
    'COMPOSITESIGNATURE': ('复合签名（经典 + PQC）是过渡期推荐做法，'
                           '需两侧都验证通过。', ['IETF draft-ietf-lamps-pq-composite-sigs']),
}

#: 上游命中的是**库名 / Provider / 配置项**，不是具体算法。
#: 对这些如实说「这不是算法」，**不要硬套一条迁移建议** ——
#: 编一个建议比说「需要展开」更糟，因为它看起来像个结论。
_NOT_ALGORITHM = {
    'POSTQUANTUMCRYPTOLIBRARY': (
        '这是 BouncyCastle 的 PQC Provider 名称，不是具体算法。'
        '需展开到实际调用的算法（如 ML-KEM / ML-DSA）再判断。', []),
    'NISTPQC': ('这是 PQC Provider 的别名，不是具体算法。'
                '需展开到实际调用的算法再判断。', []),
    'LIBOQS': ('这是 liboqs 库的引用，不是具体算法。'
               '需展开到实际调用的算法再判断。', []),
    'OQS': ('这是 liboqs 库的引用，不是具体算法。'
            '需展开到实际调用的算法再判断。', []),
    'HARDCODEDKEYSIZE': (
        '这是「硬编码密钥长度」的配置项，不是算法。'
        '需人工确认对应算法与该长度是否满足要求。', []),
    'TLS': ('这是 TLS 配置线索，不是具体算法。'
            '需展开到实际协商的密码套件再判断。', []),
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
            decided   : bool  —— 是否已给出确定结论
            reason    : str   —— **为什么是这个结论**。主要取值：
                                 'decided'            已给出确定结论
                                 'usage-undetermined' 用途判不出来（§9.1）
                                 'usage-incompatible' 算法与声称的用途不相容
                                 'not-an-algorithm'   命中的是库名/配置项
                                 'rule-missing'       规则库确实没有这一条
            action    : str   —— 建议文本
            source    : str   —— 'rule-base'（确定性密码事实，不由大模型生成）
            references: list  —— 标准依据

    `reason` 存在的理由：`decided=False` 原先同时表示「用途判不出」和
    「规则库没这条」。但这两件事对用户是完全不同的消息 ——
    「我们不知道它是干嘛的」vs「我们知道，但没有对应规则」。
    前端与报告需要分开显示，不能都糊成一句「需人工确认」。
    不变量：`decided == (reason == 'decided')`。
    """
    key = _norm(algorithm_normalized or algorithm)

    # 1) 公钥类：必须按用途分派 —— 这是方案 §9.1 的核心
    if _is_public_key(key):
        if not usage_compatible(algorithm, usage, algorithm_normalized):
            return {
                'decided': False,
                'reason': 'usage-incompatible',
                'action': ('该具体算法与声称的用途不相容；先核对算法识别、调用点'
                           '与实际原语，暂不给出迁移目标。'),
                'source': 'rule-base',
                'references': [],
            }
        hit = _BY_USAGE.get(usage)
        if hit is None:
            # 用途缺失 / unknown / 无法识别 —— 明确拒绝给出算法
            return _undecided(key)
        return {
            'decided': True,
            'reason': 'decided',
            'action': hit[0],
            'source': 'rule-base',
            'references': hit[1],
        }

    # 2) 非公钥类：迁移目标不随用途改变，直接给确定结论
    hit = _BY_ALGORITHM.get(key)
    if hit:
        return {
            'decided': True,
            'reason': 'decided',
            'action': hit[0],
            'source': 'rule-base',
            'references': hit[1],
        }

    # 3) 命中的是库名 / Provider / 配置项，不是算法。
    #    如实说「这不是算法」，不要硬套一条建议 —— 编出来的建议比
    #    「需要展开」更糟，因为它看起来像个结论。
    hit = _NOT_ALGORITHM.get(key)
    if hit:
        return {
            'decided': False,
            'reason': 'not-an-algorithm',
            'action': hit[0],
            'source': 'rule-base',
            'references': hit[1],
        }

    # 4) 规则库确实没有这一条 —— 如实说不知道，不要编
    return {
        'decided': False,
        'reason': 'rule-missing',
        'action': '规则库未覆盖该算法，需人工确认。',
        'source': 'rule-base',
        'references': [],
    }


def _is_public_key(key):
    """公钥类判定。用前缀匹配兜住 'RSA2048' / 'ECDSA_P256' 这类写法。"""
    if key in PURPOSE_DEPENDENT:
        return True
    return any(key.startswith(p) for p in ('RSA', 'ECC', 'ECDSA', 'ECDH',
                                           'ED25519', 'X25519', 'EDDSA',
                                           'DSA', 'DH'))


def _undecided(key=''):
    if not key.startswith(('ED25519X25519', 'ECDSAEC')):
        if key.startswith(_SIGNATURE_ONLY):
            return {
                'decided': False, 'reason': 'usage-undetermined',
                'action': ('尚未证实该签名原语被实际调用，暂不给出具体迁移结论。'
                           '若核实执行签名，再按签名场景评估 ML-DSA / SLH-DSA；'
                           '不得把该原语当成加密或密钥交换。'),
                'source': 'rule-base', 'references': ['FIPS 204', 'FIPS 205'],
            }
        if key.startswith(_AGREEMENT_ONLY):
            return {
                'decided': False, 'reason': 'usage-undetermined',
                'action': ('尚未证实该密钥协商原语被实际调用，暂不给出具体迁移结论。'
                           '若核实执行密钥协商，再按该场景评估 ML-KEM；'
                           '不得把该原语当成签名。'),
                'source': 'rule-base', 'references': ['FIPS 203'],
            }
    return {
        'decided': False,
        'reason': 'usage-undetermined',
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

    # FIPS 186-5 specifies ECDSA/EdDSA as signature algorithms; SP 800-56A
    # and RFC 7748 specify ECDH/X25519 for key agreement.  An impossible
    # usage must never receive a plausible-looking migration target.
    for name, bad_usage in (('ECDSA', 'encryption'), ('ECDSA', 'key_exchange'),
                            ('Ed25519', 'encryption'), ('EdDSA', 'key_exchange'),
                            ('DSA', 'encryption'), ('ECDH', 'signing'),
                            ('X25519', 'signing'), ('DH', 'signing'),
                            ('Ed25519 / X25519', 'encryption')):
        wrong = route(name, bad_usage)
        check('%s/%s 不得给迁移目标' % (name, bad_usage),
              (wrong['decided'], wrong['reason']),
              (False, 'usage-incompatible'))
    check('Ed25519/X25519 混合名在归一化后也不得推出加密路线',
          route('Ed25519 / X25519', 'encryption', 'ED25519X25519')['reason'],
          'usage-incompatible')
    check('泛化 ECC 别名不得掩盖原始 Ed25519 签名限制',
          route('Ed25519', 'encryption', 'ECC')['reason'],
          'usage-incompatible')
    check('ECDSA 正常签名仍有路线', route('ECDSA', 'signing')['decided'], True)
    check('ECDH 正常协商仍有路线', route('ECDH', 'key_exchange')['decided'], True)
    check('ECDSA 用途未知时不误导为加密候选',
          'ML-KEM' in route('ECDSA', 'unknown')['action'], False)
    check('ECDH 用途未知时不误导为签名候选',
          'ML-DSA' in route('ECDH', 'unknown')['action'], False)

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
    for field in ('decided', 'reason', 'action', 'source', 'references'):
        check('输出应含 %r 字段' % field, field in r, True)

    # --- 不变式：规则库推荐的算法，自己必须被规则库覆盖 ---
    #     这是自指的，所以能逮住一整类坑：只要建议里出现某个算法名，
    #     它就必须查得到，否则就是「建议迁移到 X，而 X 报规则库未覆盖」。
    #     实测踩过 —— 2026-10-03 全量真跑，91 条里 56 条命中未覆盖，
    #     其中最扎眼的是 ML-KEM / ML-DSA 本身就在建议文本里被推荐着。
    for name in ('ML-KEM', 'ML-DSA', 'SLH-DSA', 'AES-256', 'AES-256-GCM',
                 'SHA-256', 'SHA-3', 'SHA-384', 'SHA-512',
                 'ChaCha20-Poly1305', 'Argon2id', 'HMAC'):
        r = route(name, 'encryption')
        check('规则库推荐的 %r 自己必须被规则库覆盖' % name, r['decided'], True)

    # --- 已经是 PQC 的算法，结论必须是「无需迁移」，不能是「需人工确认」---
    for name in ('ML-KEM', 'ML-KEM-768', 'ML-DSA', 'SLH-DSA', 'LMS', 'XMSS'):
        r = route(name, 'key_exchange')
        check('%r 应判为量子安全' % name, '量子安全' in r['action'], True)

    # --- 归一化后的变体名要能查到（这些正是实测里漏掉的）---
    for name in ('AES-128', 'AES-192', 'AES-256', 'AES-GCM', 'ChaCha20-Poly1305',
                 'SHA-384/512 (SHA-2)', 'SHA-3/SHAKE', 'bcrypt', 'scrypt',
                 'Argon2', 'HKDF', 'PBKDF2', 'KMAC', 'SM3', 'SM4'):
        check('变体名 %r 应被覆盖' % name, route(name, 'encryption')['decided'], True)

    # --- reason 必须区分三种「给不出结论」---
    check('用途判不出 -> usage-undetermined',
          route('RSA', 'unknown')['reason'], 'usage-undetermined')
    check('库名/Provider -> not-an-algorithm',
          route('NISTPQC', 'unknown')['reason'], 'not-an-algorithm')
    check('库名不当成算法给建议',
          route('NISTPQC', 'unknown')['decided'], False)
    check('规则库真没有 -> rule-missing',
          route('ZZZ_NOT_A_REAL_ALGO', 'encryption')['reason'], 'rule-missing')

    # --- 不变式：decided == (reason == 'decided')，全取值域上都要成立 ---
    for algo, usage in (('RSA', 'signing'), ('RSA', 'unknown'), ('RSA', 'hashing'),
                        ('MD5', 'hashing'), ('AES-256', 'encryption'),
                        ('NISTPQC', 'unknown'), ('TLS', 'tls_configuration'),
                        ('ZZZ_NOT_A_REAL_ALGO', 'encryption')):
        r = route(algo, usage)
        check('%s/%s 的 decided 与 reason 必须一致' % (algo, usage),
              r['decided'], r['reason'] == 'decided')

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
