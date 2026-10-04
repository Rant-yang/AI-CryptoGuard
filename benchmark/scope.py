"""benchmark 类别 → 我方口径 的判定表。

**这个文件回答一个问题：这些 benchmark 的标签，哪些我们能比、哪些压根不该比。**

起因
----
找到的 benchmark 都是「**加密 API 误用检测器**」的基准 —— 它们标注的是
「你把参数写错了」（静态 IV、可预测种子、没关流）。而本项目是「**PQC 迁移**」
工具 —— 我们回答的是「你的算法撑不过量子计算机」。

**这是两个不同的轴。** CryptoAPI-Bench 的 18 个类别里，只有 6 个落在我们的
轴上；剩下 12 个（参数、配置、凭据、TLS）我们的规则库根本不建模。

如果不加区分地算 Recall，数字会很难看 —— 但那不是我们做得差，
是**大部分类别本来就在声明范围之外**。所以范围必须显式写下来，
而不是让它在算指标时悄悄混进分母。

设计约束
--------
1. **每个类别都必须有裁定** —— `build()` 会检查覆盖完整性。
   漏一个就报错。这是为了防止「13 个类别被静默丢掉，
   然后 Recall 看起来很高」这种最坏情况。
2. **不许声称规则库覆盖了它其实没覆盖的算法** —— `selftest()` 会
   真的去 import 规则库核对。删掉规则库里的一条，这里就会炸。
   这是刻意的：范围表与规则库必须同生共死，不能各说各话。

裁定取值
--------
    IN   落在我们的轴上，可比
    PART 部分可比（类别里混着能比和不能比的，按可比的子集算，且如实标注）
    OUT  明确不在范围内，从指标分母里剔除，但在报告里必须列出来
"""

from typing import NamedTuple

# ------------------------------------------------------------------ 裁定取值

IN = 'in'
PART = 'partial'
OUT = 'out'

VERDICT_CN = {
    IN: '范围内',
    PART: '部分范围内',
    OUT: '范围外',
}


class Verdict(NamedTuple):
    """一个 benchmark 类别的裁定结果。

    algorithms : 该类别对应的算法名（用于与我们的 finding 对齐）。
                 OUT 的类别为空元组 —— 我们对它没有算法级结论。
    usage      : 我方 usage 轴取值；None 表示不适用。
    risk       : 我方 risk 轴取值；None 表示我们对它不下量子风险判断。
    why        : 为什么这么判。**这一栏会被原样输出到报告里**，
                 所以必须写成人话，能直接拿去答辩。
    """
    verdict: str
    algorithms: tuple
    usage: str
    risk: str
    why: str


# ------------------------------------------------------------------ 判定表

#: CryptoAPI-Bench —— 18 个类别，逐条裁定。
#: 类别名 = `src/main/java/org/cryptoapi/bench/` 下的目录名。
CRYPTOAPI_BENCH = {
    # ---------- 落在我们轴上的 ----------
    'brokencrypto': Verdict(
        IN, ('DES', '3DES', 'DESEDE', 'RC4', 'RC2'), 'encryption', 'broken',
        'DES/3DES/RC4/RC2 已被经典攻击攻破 —— 与量子无关。'
        '这正是本项目要纠正的核心误判：上游工具把这类问题标成「量子脆弱」。'),
    'brokenhash': Verdict(
        IN, ('MD5', 'SHA1'), 'hashing', 'broken',
        'MD5 / SHA-1 已被实际碰撞攻击攻破（SHAttered），属经典攻破，非量子威胁。'),
    'brokenmac': Verdict(
        IN, ('HMAC',), 'authentication', 'broken',
        'HMAC 本身不是弱点 —— 弱点在底层哈希（HmacMD5/HmacSHA1）。'
        '我们记 HMAC，但按底层哈希判风险，所以这条与规则库的 HMAC 条目对齐。'),
    'insecureasymmetriccrypto': Verdict(
        IN, ('RSA',), 'encryption', 'shor',
        'RSA 受 Shor 威胁。注意本类别里也有 RSA-1024 这类「经典已偏弱」的用例，'
        '两种风险性质不同，我们的规则库对二者下不同的结论。'),
    'ecbcrypto': Verdict(
        IN, ('AESECB',), 'encryption', 'review',
        'ECB 是**工作模式**问题，不是算法强度问题 —— 所以 risk 给 review 而不是 '
        'grover。规则库里有 AESECB 这一条，规则是「立即改用 AES-256-GCM」。'),
    'pbeiteration': Verdict(
        PART, ('PBKDF2',), None, 'grover',
        '迭代次数不足是**参数**问题，我们的规则库只对 PBKDF2 这个算法给建议'
        '（要求 ≥600,000 次），不校验具体迭代次数。'
        '所以只能部分比：算法层面可比，参数层面不可比。'),

    # ---------- 明确范围外 ----------
    'staticinitializationvector': Verdict(
        OUT, (), None, None,
        '静态 IV 是**调用方式**问题，与算法选择无关。'
        'IV 随机性与算法抗量子能力是两个正交的维度，我们不下结论。'),
    'staticsalts': Verdict(
        OUT, (), None, None,
        '静态盐同上 —— 属参数误用，非算法选择。'),
    'predictableseeds': Verdict(
        OUT, (), None, None,
        '可预测种子属**随机源**质量问题。本项目不建模随机源强度。'),
    'predictablecryptographickey': Verdict(
        OUT, (), None, None,
        '可预测密钥属密钥生成质量问题，非算法选择。'),
    'predictablepbepassword': Verdict(
        OUT, (), None, None,
        '可预测口令属输入质量问题，非算法选择。'),
    'predictablekeystorepassword': Verdict(
        OUT, (), None, None,
        '可预测密钥库口令同上。'),
    'credentialinstring': Verdict(
        OUT, (), None, None,
        '硬编码凭据属**机密管理**问题。方案 §2.2 里凭据检测是独立能力'
        '（≥8 类），不通过「算法选择」这条线评判 —— 两条线不能混算。'),
    'untrustedprng': Verdict(
        OUT, (), None, None,
        '不可信随机数源属随机源质量问题，非算法选择。'),
    'dummycertvalidation': Verdict(
        OUT, (), None, None,
        '证书校验被架空属 **TLS 配置**问题。我们只在算法层面看 TLS 用到的'
        '密钥交换算法，不校验校验逻辑是否被绕过。'),
    'dummyhostnameverifier': Verdict(
        OUT, (), None, None,
        '主机名校验被架空同上 —— 属 TLS 配置逻辑，非算法选择。'),
    'impropersslsocketfactory': Verdict(
        OUT, (), None, None,
        '自定义 SSLSocketFactory 属 TLS 配置问题。'),
    'http': Verdict(
        OUT, (), None, None,
        '明文 HTTP 属传输层协议选择问题，与密码算法无关。'),
}

#: CamBench_Cap —— 7 个类别。合成用例，目录名即类别。
#: 注意：CamBench_Cap 每个类别目录里都放了一个 `Corrected*` 文件，
#: 那是**明示的正确写法**（负样本）。适配器要把它们标成「期望不报」。
CAMBENCH_CAP = {
    'brokencrypto': Verdict(
        IN, ('DES', '3DES'), 'encryption', 'broken',
        '同 CryptoAPI-Bench 的 brokencrypto：经典攻破，非量子。'),
    'brokenhash': Verdict(
        IN, ('MD5', 'SHA1'), 'hashing', 'broken',
        '同 brokenhash：经典攻破。'),
    'ecbmode': Verdict(
        IN, ('AESECB',), 'encryption', 'review',
        'ECB 工作模式问题；规则库有对应条目。'),
    'smallkeysize': Verdict(
        PART, ('RSA',), None, 'shor',
        '密钥长度不足。RSA 部分我们按 Shor 判（算法层面可比），'
        '但「多小算小」这个阈值我们不校验 —— 只能部分比。'),
    'pbeparameters': Verdict(
        PART, ('PBKDF2',), None, 'grover',
        '同 pbeiteration：算法层面可比，参数层面不可比。'),
    'insecurerandom': Verdict(
        OUT, (), None, None,
        '随机源质量，非算法选择。'),
    'staticiv': Verdict(
        OUT, (), None, None,
        '静态 IV，非算法选择。'),
}

#: CamBench_Real —— 真实项目，标签是 yaml，**有精确行号**。
#:
#: ⚠️ 两条与最初假设不符的实测结论（都是读了真实 yaml 才发现的）：
#:
#: 1. **`FUM` 不是误用类别**，是「需要哪种分析能力」——
#:    `Argument_State` / `String_Format` / `Method_Call_Sequence` /
#:    `High-Level_Constraints` / `Argument_Type`。所以全部 **OUT**：
#:    它回答的是「工具得会什么才能判」，不是「这里错在哪」，
#:    跟我们「算法选择」的轴没有交集。
#: 2. **当前 34 条全部 `violation: false`** —— 全是**负样本**
#:    （名字都叫 "Secure Usage of ..."）。所以它贡献不了 Recall，
#:    但**是极好的误报测试集**：真实项目、精确到行。
#:
#: 保留这张表的价值在于：`violation=True` 的条目一旦补进来，
#: 适配器会自动按 FUM 归类，而不是崩掉。
CAMBENCH_REAL_FUM = {
    'No_constraint': Verdict(
        OUT, (), None, None,
        '该用法不触发任何分析约束 —— 即 benchmark 认为它没有问题。'),
    'Method_Call_Sequence': Verdict(
        OUT, (), None, None,
        '要判它得跟踪方法调用序列（如 init/update/doFinal 是否齐全）——'
        '属 API 使用顺序，非算法选择。'),
    'Argument_State': Verdict(
        OUT, (), None, None,
        '要判它得跟踪参数的状态（如这个 byte[] 是否已被消费）——'
        '属数据流状态，非算法选择。'),
    'Argument_State/String_Format': Verdict(
        OUT, (), None, None,
        '参数状态 + 字符串格式约束（如算法名拼写）—— 非算法选择。'),
    'Argument_Type': Verdict(
        OUT, (), None, None,
        '要判它得检查参数类型是否配对 —— 非算法选择。'),
    'High-Level_Constraints': Verdict(
        OUT, (), None, None,
        '跨调用的高层约束（需要项目级理解）—— 非算法选择。'),
}

#: LLM-CMT —— 标签是**自由文本**而且很乱。
#:
#: 实测：`labels.csv` 里共 **138 种不同写法、973 次出现**，
#: 同一件事有多种拼法（`sha1 used` / `SHA1 used`、`Hardcoded password` /
#: `Hardcode password` / `Hardcoded passwords`），还有拼错的（`RC4 uesd`）。
#: 所以这里**只能按子串匹配**（`_match_llmcmt_label` 取最长命中）。
#:
#: 键的选取原则：**够长、够独特**。写 `des` 会误命中别的词，
#: 所以写 `des used`；`3des` 比 `des` 长，最长命中会先拿到它。
#:
#: ⚠️ 带「缺口」字样的几条是**规则库真的没有收录**的算法 ——
#: 它们在真实 benchmark 数据里出现了，我们却答不出来。
#: 这不是理论问题，是 next action（见 `--gaps`）。
LLMCMT_LABEL_KEYWORDS = {
    # ---------- 已破哈希：范围内 ----------
    'md5': Verdict(IN, ('MD5',), 'hashing', 'broken', 'MD5 经典攻破。'),
    'sha1': Verdict(IN, ('SHA1',), 'hashing', 'broken', 'SHA-1 经典攻破。'),
    'sha-1': Verdict(IN, ('SHA1',), 'hashing', 'broken', 'SHA-1 经典攻破。'),
    'hmacmd5': Verdict(IN, ('MD5',), 'authentication', 'broken',
                       'HMAC-MD5 的弱点在底层 MD5。'),
    'hmacsha1': Verdict(IN, ('SHA1',), 'authentication', 'broken',
                        'HMAC-SHA1 的弱点在底层 SHA-1。'),
    'md4': Verdict(IN, ('MD4',), 'hashing', 'broken',
                   'MD4 早于 MD5 被攻破，应立即淘汰。'
                   '⚠️ 规则库未收录（已知缺口）。'),
    'md2': Verdict(IN, ('MD2',), 'hashing', 'broken',
                   'MD2 已完全不可用。⚠️ 规则库未收录（已知缺口）。'),

    # ---------- 已破分组密码：范围内 ----------
    '3des': Verdict(IN, ('3DES',), 'encryption', 'broken',
                    '3DES 实际强度仅 112 位，NIST 已废弃。'),
    'des used': Verdict(IN, ('DES',), 'encryption', 'broken', 'DES 经典攻破。'),
    'rc4': Verdict(IN, ('RC4',), 'encryption', 'broken',
                   'RC4 经典攻破（RFC 7465 明令禁止）。'),
    'rc2': Verdict(IN, ('RC2',), 'encryption', 'broken', 'RC2 经典攻破。'),
    'rc5': Verdict(IN, ('RC5',), 'encryption', 'broken',
                   'RC5 分组长度偏小、密钥调度弱，应淘汰。'
                   '⚠️ 规则库未收录（已知缺口）。'),
    'blowfish': Verdict(IN, ('BLOWFISH',), 'encryption', 'broken',
                        'Blowfish 64 位分组，存在 Sweet32 风险。'
                        '⚠️ 规则库未收录（已知缺口）。'),
    'idea': Verdict(IN, ('IDEA',), 'encryption', 'broken',
                    'IDEA 已过时，应改用 AES。⚠️ 规则库未收录（已知缺口）。'),
    'cast': Verdict(IN, ('CAST',), 'encryption', 'broken',
                    'CAST5 64 位分组，已不推荐。⚠️ 规则库未收录（已知缺口）。'),
    'tea used': Verdict(IN, ('TEA',), 'encryption', 'broken',
                        'TEA/XTEA 相关密钥攻击，已不推荐。'
                        '⚠️ 规则库未收录（已知缺口）。'),
    'xtea': Verdict(IN, ('XTEA',), 'encryption', 'broken',
                    'XTEA 已不推荐。⚠️ 规则库未收录（已知缺口）。'),
    'nullcipher': Verdict(IN, ('NULLCIPHER',), 'encryption', 'broken',
                          'NullCipher 是「什么都不做」的假加密，等于明文。'
                          '⚠️ 规则库未收录（已知缺口）。'),

    # ---------- 工作模式：范围内（规则库有 AESECB 等条目）----------
    'ecb': Verdict(IN, ('AESECB',), 'encryption', 'review',
                   'ECB 泄露明文结构；属工作模式问题，非算法强度问题，'
                   '所以风险档是 review 而不是 grover。'),
    'pkcs5padding': Verdict(IN, ('AESECB',), 'encryption', 'review',
                            'PKCS5/PKCS7 填充本身可接受，但它在本数据里'
                            '总是与 ECB 同现（`AES/ECB/PKCS5Padding`）——'
                            '问题在 ECB 而不在填充。'),
    'nopadding': Verdict(OUT, (), None, None,
                         '无填充是模式配错（如 CBC 需要填充），属参数配置。'),
    'no padding': Verdict(OUT, (), None, None, '同上：无填充属参数配置。'),

    # ---------- 弱曲线 / 弱签名参数：范围内 ----------
    'prime192v1': Verdict(IN, ('ECC',), 'signing', 'shor',
                          'P-192 已被 NIST 弃用，且 ECC 本身受 Shor 威胁。'),
    'secp256r1': Verdict(IN, ('ECC',), 'signing', 'shor',
                         'P-256 曲线本身受 Shor 威胁（强度足够但非量子安全）。'),
    'pkcs#1 v1.5': Verdict(OUT, (), None, None,
                           'RSA 填充方案问题（Bleichenbacher 类攻击），'
                           '属填充协议，非算法选择。'),
    'pkcs1v15': Verdict(OUT, (), None, None, '同上：RSA 填充方案问题。'),

    # ---------- 密钥长度：部分范围内 ----------
    'insufficient key length': Verdict(PART, ('RSA',), None, 'shor',
                                       '密钥长度不足。算法层面可比，'
                                       '但「多小算小」的阈值我们不校验。'),
    'insufficient key size': Verdict(PART, ('RSA',), None, 'shor', '同上。'),
    'insufficient key': Verdict(PART, ('RSA',), None, 'shor', '同上。'),
    'default key length': Verdict(PART, ('RSA',), None, 'shor',
                                  '用了默认密钥长度 —— 同「长度不足」。'),
    'insecure key length': Verdict(PART, ('RSA',), None, 'shor', '同上。'),

    # ---------- 迭代次数：部分范围内 ----------
    'iteration': Verdict(PART, ('PBKDF2',), None, 'grover',
                         'PBKDF2 迭代次数不足。算法层面可比'
                         '（规则库要求 ≥600,000），具体阈值我们不校验。'),
    'bcrypt cost': Verdict(PART, ('BCRYPT',), None, 'grover',
                           'bcrypt cost 参数偏低。算法层面可比，参数不校验。'),

    # ---------- 明确范围外：凭据管理 ----------
    'hardcoded': Verdict(OUT, (), None, None,
                         '硬编码密钥/口令/凭据属**机密管理**问题。'
                         '方案 §2.2 把凭据检测列为独立能力，'
                         '不通过「算法选择」这条线评判 —— 两条线不能混算。'),
    'hardcode': Verdict(OUT, (), None, None, '同上：硬编码凭据。'),
    'storing passwords in plain text': Verdict(OUT, (), None, None,
                                               '明文存口令，属凭据管理。'),
    'transmitting passwords in plain text': Verdict(OUT, (), None, None,
                                                    '明文传口令，属凭据管理。'),
    'insecure key storage': Verdict(OUT, (), None, None, '密钥存储，非算法选择。'),
    'token': Verdict(OUT, (), None, None, '令牌安全问题，非算法选择。'),
    'jwt': Verdict(OUT, (), None, None, 'JWT 安全问题，非算法选择。'),
    'password length': Verdict(OUT, (), None, None, '口令长度策略，非算法选择。'),
    'sha-256 for password hashing': Verdict(OUT, (), None, None,
                                            '用通用哈希当口令哈希是选型错误，'
                                            '但属「该用哪类工具」，非量子风险。'),

    # ---------- 明确范围外：随机源与参数质量 ----------
    'static iv': Verdict(OUT, (), None, None, '静态 IV 属参数质量，非算法选择。'),
    'static salt': Verdict(OUT, (), None, None, '静态盐同上。'),
    'static seed': Verdict(OUT, (), None, None, '静态种子属随机源质量。'),
    'constant seed': Verdict(OUT, (), None, None, '常量种子属随机源质量。'),
    'predictable iv': Verdict(OUT, (), None, None, '可预测 IV 属参数质量。'),
    'predictable seed': Verdict(OUT, (), None, None, '可预测种子属随机源质量。'),
    'predictable key': Verdict(OUT, (), None, None, '可预测密钥属生成质量。'),
    'no iv': Verdict(OUT, (), None, None, '缺 IV 属参数配置。'),
    'no salt': Verdict(OUT, (), None, None, '缺盐属参数配置。'),
    'short salt': Verdict(OUT, (), None, None, '盐过短属参数配置。'),
    'insufficient salt': Verdict(OUT, (), None, None, '盐长度不足属参数配置。'),
    'insufficient iv': Verdict(OUT, (), None, None, 'IV 长度不足属参数配置。'),
    'random': Verdict(OUT, (), None, None,
                      '随机源质量问题（PRNG / RAND_poll / 非密钥学随机）——'
                      '本项目不建模随机源强度。'),
    'prng': Verdict(OUT, (), None, None, '同上：随机源质量。'),
    'nonce': Verdict(OUT, (), None, None, 'nonce 生成质量，非算法选择。'),
    'seed': Verdict(OUT, (), None, None, '种子质量，非算法选择。'),

    # ---------- 明确范围外：TLS / 证书配置 ----------
    'ssl': Verdict(OUT, (), None, None,
                   'TLS 版本/套件/上下文配置问题。我们只在算法层看 TLS 用到的'
                   '密钥交换算法，不校验配置逻辑是否安全。'),
    'tls': Verdict(OUT, (), None, None, '同上：TLS 配置。'),
    'http': Verdict(OUT, (), None, None, '明文 HTTP 与密码算法无关。'),
    'certificate': Verdict(OUT, (), None, None, '证书校验逻辑，非算法选择。'),
    'cert verification': Verdict(OUT, (), None, None, '同上：证书校验。'),
    'certificates verification': Verdict(OUT, (), None, None, '同上。'),
    'hostname': Verdict(OUT, (), None, None, '主机名校验属 TLS 配置。'),
    'host verification': Verdict(OUT, (), None, None, '同上：主机名校验。'),
    'self-signed': Verdict(OUT, (), None, None, '自签证书属信任链配置。'),
    'cipher suit': Verdict(OUT, (), None, None, '密码套件配置，非算法选择。'),
    'ciphersuit': Verdict(OUT, (), None, None, '同上：密码套件配置。'),
    'server verification': Verdict(OUT, (), None, None, '服务端校验属 TLS 配置。'),

    # ---------- 明确范围外：工作模式与 API 使用 ----------
    'default mode': Verdict(OUT, (), None, None,
                            '用了默认工作模式 —— 属配置，且「默认是什么」'
                            '取决于实现，无法静态对齐到某一档风险。'),
    'default padding': Verdict(OUT, (), None, None, '默认填充属配置。'),
    'padding mechanism': Verdict(OUT, (), None, None, '填充机制选择属配置。'),
    'mode of operation': Verdict(OUT, (), None, None,
                                 '工作模式不安全，但我们只覆盖 ECB/CBC/CTR 三条。'),
    'non-stanard mode': Verdict(OUT, (), None, None,
                                '非标准工作模式（原文拼写即如此），定义不清。'),
    'cfb': Verdict(OUT, (), None, None, 'CFB 无认证属模式选择，非算法强度。'),
    'ofb': Verdict(OUT, (), None, None, 'OFB 属模式选择。'),
    'authentication': Verdict(OUT, (), None, None, '缺少认证属模式选择。'),
    'key generation method': Verdict(OUT, (), None, None, '密钥生成方式，非算法选择。'),
    'key derivation': Verdict(OUT, (), None, None, 'KDF 选型/参数，非量子风险。'),
    'dh group': Verdict(OUT, (), None, None, 'DH 群参数强度，非算法选择。'),
    'dh parameters': Verdict(OUT, (), None, None, '同上：DH 参数。'),
    'deprecated': Verdict(OUT, (), None, None,
                          '「用了废弃函数」—— 属 API 使用，非算法选择。'),
    'bignum': Verdict(OUT, (), None, None, '用了低层大数函数，属 API 使用。'),
    'bn_mod_exp': Verdict(OUT, (), None, None,
                          '直接调 OpenSSL 低层大数模幂函数（BN_mod_exp_simple），'
                          '属 API 使用方式，非算法选择。'),
    # 「弱加密」这种**没点名算法**的标签，我们**如实承认对不上** ——
    # 硬塞一个 risk 就是编结论。这也解释了为什么它的裁定理由是这句。
    'weak cipher': Verdict(OUT, (), None, None,
                           '标签只说「弱加密」但没给算法名 —— 无法对齐到'
                           '具体算法，所以不参与算法层比较。'
                           '（不是我们答不出，是标签本身没有信息量。）'),
    'openssl initialization': Verdict(OUT, (), None, None, '库初始化方式，非算法选择。'),
    'non-cryptographic hash': Verdict(OUT, (), None, None,
                                      '拿非密码学哈希做完整性校验 ——'
                                      '属选型错误，但不是量子风险。'),
}


# ------------------------------------------------------------------ 汇总

#: benchmark 名 -> 判定表。适配器按名字取。
TABLES = {
    'cryptoapi-bench': CRYPTOAPI_BENCH,
    'cambench-cap': CAMBENCH_CAP,
    'cambench-real': CAMBENCH_REAL_FUM,
    'llmcmt': LLMCMT_LABEL_KEYWORDS,
}


_LOWER_INDEX = {}


def verdict_for(benchmark, category):
    """取一个类别的裁定。**大小写不敏感。**

    **找不到就抛错，不返回默认值。** 默认值会让新出现的类别
    悄悄变成「范围外」并静默离开分母 —— 那正是我们要防的事。

    大小写为什么重要：表里的键是人写的，各家的惯例不一样 ——
    CryptoAPI-Bench 的目录名是全小写（`brokencrypto`），
    CamBench_Real 的 FUM 是驼峰（`No_constraint`）。
    早先这里只做 `.lower()` 再查表，驼峰那批就全部查不到，
    34 条 CamBench_Real 全被记成「未裁定」。
    """
    table = TABLES.get(benchmark)
    if table is None:
        raise KeyError('未知 benchmark: %r（可选：%s）'
                       % (benchmark, ', '.join(sorted(TABLES))))
    if benchmark not in _LOWER_INDEX:
        _LOWER_INDEX[benchmark] = {k.lower(): k for k in table}
    canon = _LOWER_INDEX[benchmark].get(category.strip().lower())
    if canon is None:
        raise KeyError(
            'benchmark %r 里出现未裁定的类别 %r。\n'
            '请到 benchmark/scope.py 的对应表里补一条裁定 —— '
            '不允许静默当作范围外处理。' % (benchmark, category))
    return table[canon]


def scope_report():
    """输出一份「范围内 / 范围外」清单，用于写进报告。"""
    lines = []
    for bench in sorted(TABLES):
        table = TABLES[bench]
        for verdict in (IN, PART, OUT):
            hits = sorted(k for k, v in table.items() if v.verdict == verdict)
            if not hits:
                continue
            lines.append('%s / %s (%d):' % (bench, VERDICT_CN[verdict], len(hits)))
            for k in hits:
                lines.append('    %-34s %s' % (k, table[k].why))
    return '\n'.join(lines)


def _rule_library():
    """import 规则库。单独抽出来，是因为下面两个函数都要用。"""
    import os
    import sys
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)
    from core.rules import pqc_routing
    return pqc_routing


def _answered_by_rules(alg, usage):
    """规则库对这个算法有话说吗？

    **直接调 route() 问，不去翻内部的表。** 早先的写法是查
    `pqc_routing._BY_ALGORITHM` 的键 —— 那个写法漏掉了公钥算法：
    RSA/ECC 不走 `_BY_ALGORITHM`，走 `_BY_USAGE` 按用途分派，
    于是自检把四条正确的裁定误判成了错误。教训：**别重新实现一遍
    被测代码的分派逻辑，去调它。**

    注意 'usage-undetermined' 算「有话说」—— 那正是 §9.1 要求的
    正确行为（用途判不出来就不给算法），不是规则库的缺口。
    """
    return _rule_library().route(alg, usage)['reason'] != 'rule-missing'


def coverage_gaps():
    """裁定表里声称「范围内」但规则库其实答不出来的算法。

    这是**真实缺口清单** —— 与其在报告里含糊，不如把它列出来：
    既是我们知道自己不知道什么，也是下一步补规则库的待办。
    """
    gaps = []
    for bench in sorted(TABLES):
        for cat, v in sorted(TABLES[bench].items()):
            if v.verdict == OUT:
                continue
            for alg in v.algorithms:
                if not _answered_by_rules(alg, v.usage):
                    gaps.append((bench, cat, alg))
    return gaps


# ------------------------------------------------------------------ 自检

def _selftest():
    """硬编码断言 —— 断言的是**真实约定**，不是复述本文件的实现。

    刻意做两件容易漏的事：
      1. 反向核对：判定表里出现的每个裁定值都必须是三个合法值之一。
      2. 交叉核对：声称范围内的算法，规则库必须真的有 —— 真去 import 核对。
    """
    fails = []

    # 1) 裁定值封闭
    legal = {IN, PART, OUT}
    for bench, table in TABLES.items():
        for cat, v in table.items():
            if v.verdict not in legal:
                fails.append('%s/%s 裁定值非法: %r' % (bench, cat, v.verdict))
            # 范围内就必须给出算法，否则比不了
            if v.verdict in (IN, PART) and not v.algorithms:
                fails.append('%s/%s 是%s但没给算法' % (bench, cat, VERDICT_CN[v.verdict]))
            # 范围外就不该给算法 —— 给了说明裁定自相矛盾
            if v.verdict == OUT and v.algorithms:
                fails.append('%s/%s 是范围外却给了算法 %r' % (bench, cat, v.algorithms))
            if not v.why.strip():
                fails.append('%s/%s 没写裁定理由' % (bench, cat))

    # 2) risk / usage 取值必须是 schema 的合法值
    usages = {'signing', 'encryption', 'key_exchange', 'hashing',
              'authentication', 'tls_configuration', 'unknown', None}
    risks = {'shor', 'broken', 'grover', 'review', 'safe', None}
    for bench, table in TABLES.items():
        for cat, v in table.items():
            if v.usage not in usages:
                fails.append('%s/%s usage 非法: %r' % (bench, cat, v.usage))
            if v.risk not in risks:
                fails.append('%s/%s risk 非法: %r' % (bench, cat, v.risk))
            # 声称可比，规则库就必须答得出来 —— 真去调 route() 核对。
            # 已知缺口（KNOWN_GAPS）单独记账，不算失败但也不掩盖。
            if (bench, cat) in KNOWN_GAPS:
                continue
            for alg in v.algorithms:
                if not _answered_by_rules(alg, v.usage):
                    fails.append('%s/%s 声称可比，但规则库答不出 %s'
                                 % (bench, cat, alg))

    if fails:
        print('[FAIL] scope.py 自检未通过:')
        for f in fails:
            print('  - ' + f)
        return False

    n_in = sum(1 for t in TABLES.values() for v in t.values() if v.verdict == IN)
    n_part = sum(1 for t in TABLES.values() for v in t.values() if v.verdict == PART)
    n_out = sum(1 for t in TABLES.values() for v in t.values() if v.verdict == OUT)
    print('[PASS] scope.py 自检通过  '
          '（范围内 %d / 部分 %d / 范围外 %d）' % (n_in, n_part, n_out))
    return True


#: 已知的、**故意留下**的覆盖缺口 —— 不掩盖，单独记账。
#: 这些不是 bug，是待办：要么补规则库，要么在报告里说明。
#:
#: **这批缺口是从真实 benchmark 数据里发现的，不是想出来的。**
#: LLM-CMT 的 716 条真实代码里，这些已淘汰算法都出现了，
#: 而我们的规则库答不出来 —— 一旦答辩被问「MD4 呢」，就是 `rule-missing`。
#: 补起来很便宜（`_BY_ALGORITHM` 加几行），但必须先知道有这回事。
KNOWN_GAPS = {
    ('llmcmt', 'md4'),
    ('llmcmt', 'md2'),
    ('llmcmt', 'rc5'),
    ('llmcmt', 'blowfish'),
    ('llmcmt', 'idea'),
    ('llmcmt', 'cast'),
    ('llmcmt', 'tea used'),
    ('llmcmt', 'xtea'),
    ('llmcmt', 'nullcipher'),
}


if __name__ == '__main__':
    import sys
    # Windows 控制台默认 GBK，中文会乱码成「锟斤拷」。显式切 UTF-8。
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except (AttributeError, OSError):
        pass
    if '--gaps' in sys.argv:
        g = coverage_gaps()
        print('规则库覆盖缺口（%d 条）:' % len(g))
        for bench, cat, alg in g:
            print('  %-16s %-22s %s' % (bench, cat, alg))
        sys.exit(0)
    if '--report' in sys.argv:
        print(scope_report())
        sys.exit(0)
    sys.exit(0 if _selftest() else 1)
