"""归一化与裁决表 —— scanner 的公共基础。

上游两个工具对同一件事的叫法全部不同（算法名 / 用途 / 严重程度 / 置信度 /
量子风险口径），本模块集中放所有「翻译」规则，adapter 和 merge 都只从这里查表，
不许各自散落一份映射 —— 改口径时只改这一个文件。

risk 五档的裁决依据（core/schema/finding.v0.1.json 的口径）:
    以 cbom-scan 为模式证据主源（三个工具里唯一分类正确的），
    CryptoScan 独有的发现按 core/rules/zh_map.json 的 quantum_class 初版判定，
    两边都没有的落到 review（不猜）。

关于 RISK_BY_TYPE 的出处: 直接读取 core/rules/zh_map.json 的
quantum_class.by_type；其中 classical_broken 归一为 schema 的 broken。
scanner 不再维护第二张手抄表，避免 CLI、Web 与规则评估互相打架。
"""

import json as _json
import os as _os

# ---------------------------------------------------------------- 算法名归一化

def norm_algorithm(name):
    """算法名归一化：大写、去掉非字母数字。

    三个工具对同一算法的写法不同（'SHA-1' / 'sha1' / 'SHA1'），
    不归一会导致跨工具对齐与去重全部失效。
    """
    if not name:
        return ''
    return ''.join(ch for ch in str(name).upper() if ch.isalnum())


#: 归一化后的别名表：把跨工具的不同叫法对齐到同一个规范名。
#: 只收「确定是同一算法」的别名；粒度不同的（如 cbom 的 'NIST PQC' 大类
#: 对 CryptoScan 的 ML-KEM / ML-DSA 细分）**刻意不合并** —— 融合层不做
#: 超出证据粒度的合并，那会制造「聪明的错误」。
ALIASES = {
    # cbom-scan 'ECDSA / EC'  ==  CryptoScan 'ECC'（椭圆曲线一族）
    'ECDSAEC': 'ECC',
    # cbom-scan 'DES / 3DES'  ==  CryptoScan 'DES' / '3DES'（cbom 本来就归一个 asset）
    'DES3DES': 'DES',
    '3DES': 'DES',
}


def canon_algorithm(name):
    """归一化 + 应用别名，返回规范名。"""
    key = norm_algorithm(name)
    return ALIASES.get(key, key)


# ---------------------------------------------------------------- 合并名拆词

#: 带括号的合并名形态（cbom-scan 的 asset.algo 实测值域）:
#:     "Legacy cipher (Blowfish/CAST5/IDEA/SEED)"  -> 4 个并列算法，必须拆
#:     "SSH (RSA/ECDSA/Ed25519)"                   -> 3 个并列算法，拆
#: 而这些**带括号但不是算法并列**的，必须原样放行:
#:     "PKCS#8 private key (alg unspecified)"      括号内是说明文字
#:     "JWT/multi (often RS256/ES256)"             段里含空格，不是算法 token
#:     "SHA-384/512 (SHA-2)"                       括号内是家族名单段
#: 纯斜杠的 "AES/GCM/NoPadding" 是「算法/模式/填充」参数写法，也不是并列，
#: 不带括号天然不进本函数的拆分分支。
import re as _re

_COMBINED_RE = _re.compile(r'^(.*?)\s*\(([^()]*)\)\s*$')


def split_combined_algorithm(name):
    """识别「前缀 (A/B/C)」多算法合并名，返回算法候选列表；其余原样返回。

    拆分的判定必须同时满足（缺一不拆，宁可不拆也不拆错）:
        - 整体是 `前缀 (内容)` 结构（带括号才拆，纯斜杠不拆）
        - 内容按 `/` 拆出 >= 2 段
        - 每段非空且**不含空格**（排除 "alg unspecified" / "often RS256" 类说明文）
    """
    name = str(name or '').strip()
    if not name:
        return ['']
    m = _COMBINED_RE.match(name)
    if not m:
        return [name]
    inner = m.group(2).strip()
    if not inner:
        return [name]
    parts = [p.strip() for p in inner.split('/')]
    if len(parts) >= 2 and all(p and ' ' not in p for p in parts):
        return parts
    return [name]


# ---------------------------------------------------------------- 用途映射

#: cbom-scan 的 prim -> schema usage enum
#: pke / kem 刻意映射到 unknown：公钥加密这个粒度分不出签名还是加密，
#: 而 cbom 的 'NIST PQC'（prim=kem）混含 ML-KEM 和 ML-DSA，判了就是猜。
CBOM_PRIM_TO_USAGE = {
    'signature': 'signing',
    'key-agree': 'key_exchange',
    'hash': 'hashing',
    'block-cipher': 'encryption',
    'stream-cipher': 'encryption',
    'pke': 'unknown',
    'kem': 'unknown',
}

#: CryptoScan 的 purpose -> schema usage enum（'general' 分不出用途，如实 unknown）
CRYPTOSCAN_PURPOSE_TO_USAGE = {
    'signing': 'signing',
    'encryption': 'encryption',
    'key-exchange': 'key_exchange',
    'hashing': 'hashing',
    'authentication': 'authentication',
    'tls-configuration': 'tls_configuration',
    'general': 'unknown',
}

# ---------------------------------------------------------------- 严重程度 / 置信度

#: CryptoScan findings[].severity 整数 -> schema severity
CRYPTOSCAN_SEVERITY_TO_ENUM = {
    4: 'critical', 3: 'high', 2: 'medium', 1: 'low', 0: 'info',
}

#: CryptoScan confidence 枚举 -> 0-1 浮点（schema 规定的映射）
CONFIDENCE_MAP = {
    'HIGH': 0.9, 'MEDIUM': 0.6, 'LOW': 0.3,
}

#: severity 全序（合并取最大用）
SEVERITY_ORDER = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

#: 只有 cbom-scan 证据、拿不到上游 severity 时的兜底推断。
#: 口径对齐 CryptoScan 对同类发现的实际打分（实测 crypto-samples 63 个双源条目）:
#:   shor/broken 类打 3(high) 居多; grover 类全打 0-1（量子仅折半安全位，非紧急）。
#: 故 grover 从 medium 下调 low; critical 只留给上下文明确的真实调用
#: （cs 对真实调用的 MD5 打 4），兜底分不出真实调用与提及，不越权打 critical。
SEVERITY_FROM_RISK = {
    'shor': 'high', 'broken': 'high', 'grover': 'low',
    'review': 'low', 'safe': 'info',
}

# ---------------------------------------------------------------- 量子风险裁决

def _load_risk_by_type():
    path = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)),
                         'core', 'rules', 'zh_map.json')
    with open(path, encoding='utf-8') as fh:
        raw = _json.load(fh)['quantum_class']['by_type']
    convert = {'classical_broken': 'broken'}
    return {name: convert.get(value, value) for name, value in raw.items()}


#: CryptoScan type -> 我们的五档。唯一真源是 core/rules/zh_map.json。
RISK_BY_TYPE = _load_risk_by_type()

#: risk 全序（合并取最严重用）。shor 与 broken 同级 —— 都属于「必须处理」，
#: 平级时取 shor（量子迁移是本作品的主叙事）。
RISK_ORDER = {'safe': 0, 'review': 1, 'grover': 2, 'broken': 3, 'shor': 3}

#: CryptoScan quantumRisk 的字面翻译，**仅用于与最终裁决对比、打出纠正标记**，
#: 绝不作为 risk 的取值来源（它把 MD5 这类经典攻破的算法也标 VULNERABLE）。
CRYPTOSCAN_QUANTUM_RISK_AS_SEEN = {
    'VULNERABLE': 'shor', 'PARTIAL': 'grover',
    'SAFE': 'safe', 'UNKNOWN': 'review',
}


def most_severe_risk(risks):
    """多个 risk 取最严重的一档。shor/broken 平级时取 shor。"""
    best = None
    for r in risks:
        if r not in RISK_ORDER:
            continue
        if best is None:
            best = r
            continue
        # 平级且当前 best 是 broken 时，shor 优先
        if RISK_ORDER[r] > RISK_ORDER[best] or (
                RISK_ORDER[r] == RISK_ORDER[best] and r == 'shor'):
            best = r
    return best or 'review'


def max_severity(severities):
    """多个 severity 取最大值（schema 合并规则：真实使用不被注释提及拉低）。"""
    vals = [SEVERITY_ORDER[s] for s in severities if s in SEVERITY_ORDER]
    if not vals:
        return None
    for name, order in SEVERITY_ORDER.items():
        if order == max(vals):
            return name
    return None


# ---------------------------------------------------------------- 用途矛盾判定

#: 纯哈希类算法的归一名 / 前缀 —— 它们不承担签名/加密/密钥交换
_HASH_ALGO_PREFIXES = ('MD5', 'SHA')

#: 对称密码的归一名 / 前缀 —— 数字签名需要非对称密钥，对称密码做不了签名
#: （它们能做的对称认证是 authentication / MAC，不是 signing）
_SYM_ALGO_PREFIXES = ('AES', 'DES', '3DES', 'CHACHA20', 'XCHACHA20', 'RC4',
                      'BLOWFISH')

#: 公钥类算法的归一名 / 前缀 —— 它们不承担哈希用途
_PUBKEY_ALGO_PREFIXES = (
    'RSA', 'ECC', 'ECDSA', 'ECDH', 'ED25519', 'X25519', 'EDDSA', 'DSA', 'DH',
    'MLKEM', 'MLDSA', 'FNDSA', 'SLHDSA', 'XMSS', 'LMS', 'HYBRIDKEM',
    'COMPOSITESIGNATURE', 'NISTPQC', 'POSTQUANTUMCRYPTOLIBRARY',
)


def usage_contradicts_algorithm(alg_norm, usage):
    """用途与算法大类是否构成确定性逻辑矛盾。

    上游的 purpose 判定会出错（实测: import 语句被 CryptoScan 判成
    RSA/hashing）。usage 的**复核**是 ai/ 模块的职责，scanner 不改值，
    但确定性的矛盾可以由规则判出 —— 打 needs-usage-review 让 AI 优先处理。
    只放确定无疑的密码学事实，不搞启发式：
        公钥/后量子公钥算法 x hashing        （公钥算法不做哈希）
        纯哈希算法   x signing/encryption/key_exchange（哈希不签名不加密）
        对称密码     x signing               （数字签名需要非对称密钥）
    """
    if not alg_norm:
        return False
    if usage == 'hashing' and alg_norm.startswith(_PUBKEY_ALGO_PREFIXES):
        return True
    if usage in ('signing', 'encryption', 'key_exchange') \
            and alg_norm.startswith(_HASH_ALGO_PREFIXES):
        return True
    if usage == 'signing' and alg_norm.startswith(_SYM_ALGO_PREFIXES):
        return True
    return False


# ---------------------------------------------------------------- 路径

def to_relative_path(path, target_root):
    """上游文件路径 -> 项目内相对路径、正斜杠；目标外/无法归位的返回 ''。

    CryptoScan 输出绝对路径（信息泄露 + 不可移植，必须剥）；
    cbom-scan 已经给相对路径 —— 相对输入直接规范斜杠即可，
    千万不能再做一次 relpath（那会相对 cwd 计算，得出错误结果）。

    返回 '' 的两种情形（adapter 侧见 '' 即丢弃该命中）:
        - 归位后发现以 '..' 开头: 命中在目标目录之外（工具扫到了模块
          缓存 / 系统路径），'../' 形式照样泄露路径、不可移植，不带进来
        - relpath 抛 ValueError: Windows 跨盘（C: vs D:）等无法相对化
    """
    import os
    if path is None:
        return ''
    if not os.path.isabs(str(path)):
        p = str(path).replace('\\', '/')
        # Windows「驱动器相对路径」（D:foo\bar）: isabs 判它为相对，但它
        # 既不是项目内路径也不可移植 —— 按目标外处理，不带进来
        if len(p) >= 2 and p[1] == ':':
            return ''
        return p
    try:
        rel = os.path.relpath(os.path.abspath(path), os.path.abspath(target_root))
    except ValueError:
        return ''
    if rel == '..' or rel.startswith('..' + os.sep) or rel.startswith('../'):
        return ''
    return rel.replace('\\', '/')
