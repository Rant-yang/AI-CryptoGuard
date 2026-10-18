"""本地凭据管理缺陷检测器。

目标不是收集某几家云厂商的 token 格式，而是识别 8 类可解释的管理缺陷。
任何输出都不包含凭据原文：仅保存遮蔽长度和使用进程内随机密钥计算的 HMAC
指纹。随机密钥不落盘，因此短弱口令也不能通过离线字典反查。
"""
import hashlib
import hmac
import math
import os
import re


TOOL_NAME = 'credential-scan'

RULES = {
    'CRED-HARDCODED-PASSWORD': ('硬编码口令', 'high',
        '把口令移出源码，改由环境变量或密钥管理服务在运行时注入。', 'CWE-259'),
    'CRED-HARDCODED-TOKEN': ('硬编码 API Key / Token / Secret', 'critical',
        '立即轮换该凭据，并改由密钥管理服务或受控环境变量注入。', 'CWE-798'),
    'CRED-HARDCODED-CRYPTO-KEY': ('硬编码密码学密钥', 'critical',
        '轮换密钥；使用 KMS/HSM 或受控密钥文件加载，不在源码中保存密钥材料。', 'CWE-321'),
    'CRED-EMBEDDED-PRIVATE-KEY': ('源码内嵌私钥材料', 'critical',
        '立即吊销并轮换私钥；从版本历史中清除，改由 KMS/HSM 或受控挂载提供。', 'CWE-321'),
    'CRED-IN-URL': ('URL / 连接串中包含凭据', 'high',
        '移除 URL 中的用户名和口令，改用独立凭据注入与安全连接配置。', 'CWE-598'),
    'CRED-IN-LOG': ('凭据被写入日志或标准输出', 'high',
        '删除敏感值日志；只记录不可逆审计标识，并对现有日志执行清理与访问审计。', 'CWE-532'),
    'CRED-DEFAULT-WEAK': ('默认或弱口令', 'critical',
        '禁止默认口令；首次启动强制生成或设置唯一强凭据，并提供轮换机制。', 'CWE-521'),
    'CRED-HIGH-ENTROPY-SECRET': ('敏感变量中的高熵秘密', 'high',
        '确认该值是否为真实凭据；若是，立即轮换并迁移到密钥管理服务。', 'CWE-798'),
}

_EXTS = {'.py', '.java', '.js', '.jsx', '.ts', '.tsx', '.go', '.c', '.cc',
         '.cpp', '.h', '.hpp', '.cs', '.php', '.rb', '.rs', '.kt', '.kts',
         '.scala', '.swift', '.dart', '.yaml', '.yml', '.json', '.toml',
         '.properties', '.ini', '.conf', '.config', '.env', '.xml'}
_SKIP_DIRS = {'.git', '.svn', '.hg', 'node_modules', 'vendor', 'dist', 'build',
              'target', '.venv', 'venv', '__pycache__', '.idea', '.gradle'}
_MAX_FILE = 2 * 1024 * 1024

_ASSIGN_RE = re.compile(
    r'(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,80})'
    r'(?:\s*\[[^\]\r\n]{0,40}\])?\s*(?::=|=)\s*'
    # 允许 C/C++ cast、Go []byte(...)、Java helper(...) 包住字面量；
    # 仍要求左侧变量名敏感或文件内存在密码学 sink，不能仅凭任意字符串报警。
    r'(?P<prefix>[^;"\'\r\n]{0,96})(?P<quote>["\'])'
    r'(?P<value>[^"\'\r\n]{1,4096})(?P=quote)')
_ARRAY_ASSIGN_RE = re.compile(
    r'(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,80})'
    r'(?:\s*\[[^\]\r\n]{0,40}\])?\s*(?::=|=)\s*'
    r'(?:\[[^\]\r\n]*\](?:byte)?\s*)?\{(?P<value>[0-9xXa-fA-F,\s-]{7,1024})\}')
_CHAR_ARRAY_ASSIGN_RE = re.compile(
    r'(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,80})'
    r'(?:\s*\[[^\]\r\n]{0,40}\])?\s*(?::=|=)\s*'
    r'\{(?P<value>(?:\s*["\'][^"\'\r\n]{1,4}["\']\s*,?){1,256})\}')
_DIRECT_KEY_LITERAL_RE = re.compile(
    r'(?i)(?:SecretKeySpec|PBEKeySpec|Fernet|AES\.new|DES(?:3)?\.new|'
    r'algorithms\.(?:AES|TripleDES|ChaCha20)|aes\.NewCipher)\s*\('
    r'\s*(?:\[\]byte\s*\(|bytes\s*\()?\s*(?:b|u|r|br|rb)?'
    r'(?P<quote>["\'])(?P<value>[^"\'\r\n]{1,4096})(?P=quote)')
_URL_RE = re.compile(r'\b[a-zA-Z][a-zA-Z0-9+.-]*://([^\s/:@]+):([^\s/@]+)@')
_PEM_RE = re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----')
_LOG_RE = re.compile(r'(?i)\b(?:print|println|printf|console\.log|log\.(?:trace|debug|info|warn|error)|logger\.(?:trace|debug|info|warn|error))\s*\((.*)')
# 去掉字符串字面量后剩的部分才是「被输出/插值的变量」。
# `logger.info("Dumping LSA Secrets")` 只在消息文本里提到 secret，不是输出
# 凭据值；`logger.info(secret)` 输出的才是变量 secret。
_STRING_LITERAL_RE = re.compile(r'(["\'])(?:\\.|(?!\1).)*\1')

_PASSWORD = re.compile(r'(?i)(?:pass(?:word|wd|phrase)?|pwd|keystorepass|storepass)')
_TOKEN = re.compile(r'(?i)(?:api[_-]?(?:key|token)|access[_-]?token|auth[_-]?token|bearer|jwt[_-]?secret|client[_-]?secret|secret[_-]?key|credential)')
_CRYPTO_KEY = re.compile(r'(?i)(?:aes|des|rsa|hmac|crypto|cipher|encrypt|decrypt)[_.-]*(?:key|secret)|(?:private|master|signing)[_.-]*key')
_SENSITIVE = re.compile(r'(?i)(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)')
_PLACEHOLDER = re.compile(
    r'(?i)^(?:example|sample|dummy|placeholder|replace[_-]?me|changeme|'
    r'some[_-]?(?:password|pwd|pass|token|key|secret)|'
    r'new[_-]?(?:password|pwd|pass|token|key|secret)|'
    r'your[_-].*|<.*>|\$\{.*\}|%\w+%)$')
_WEAK = {'admin', 'admin123', 'password', 'password1', 'passw0rd', '123456',
         '12345678', 'root', 'guest', 'test', 'default', 'changeme',
         'changeit', 'secret'}
_CRYPTO_CONTEXT_RE = re.compile(
    r'(?i)(?:SecretKeySpec|PBE(?:KeySpec|ParameterSpec)|KeyStore|javax\.crypto|'
    r'java\.security\.(?:KeyStore|Key)|Crypto\.Cipher|cryptography\.hazmat|'
    r'golang\.org/x/crypto|crypto/(?:aes|des|rsa|hmac)|openssl/|'
    r'aes\.NewCipher|AES\.new|DES(?:3)?\.new|algorithms\.(?:AES|TripleDES|ChaCha20)|'
    r'Fernet|EVP_|AES_set_(?:encrypt|decrypt)_key|NewCipher|_set_key|setKey\s*\(|'
    r'privateKey|signingKey|encryptionKey|ucryptolib|SecretBox|nacl)')
_PASSWORD_CONTEXT_RE = re.compile(
    r'(?i)(?:PBE(?:KeySpec|ParameterSpec)|KeyStore(?:\.load|\.getInstance|\b))')
_GENERIC_KEY_NAME = re.compile(
    r'(?i)^(?:g[_-])?(?:default[_-]?)?(?:crypto[_-]?)?'
    r'key(?:bytes?|fernet|\d+)?$')
#: 纯算法 / 原语名。`String key = "DES"` 的 "DES" 是算法名，不是密钥材料；
#: 密钥不会是一个短算法名。只对「密钥类变量名」（_CRYPTO_KEY / 通用 key）生效。
_ALGO_NAME_VALUES = frozenset({
    'DES', 'DESEDE', 'TRIPLEDES', '3DES',
    'AES', 'AES128', 'AES192', 'AES256',
    'BLOWFISH', 'RC2', 'RC4', 'RC5', 'RC6', 'IDEA',
    'CAST5', 'CAST6', 'CHACHA20', 'CHACHA', 'XTEA', 'TEA', 'SEED',
    'CAMELLIA', 'SERPENT', 'TWOFISH',
    'RSA', 'DSA', 'ECDSA', 'DH', 'ECDH', 'EC', 'ECC', 'ED25519', 'X25519',
    'MD5', 'MD4', 'MD2', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512',
    'HMAC', 'HMACMD5', 'HMACSHA1', 'HMACSHA256', 'HMACSHA512',
    'PBKDF2', 'BCRYPT', 'SCRYPT', 'ARGON2',
})
_RUNTIME_SOURCE_RE = re.compile(
    r'(?i)(?:getenv|environ|getProperty|process\.env|config\.|vault|secretManager)')
#: 方法调用实参：`key.getBytes("UTF-8")` 的 "UTF-8" 是编码参数，不是密钥。
#: 只认 `.方法(` —— `[]byte("...")` / `bytes("...")` 是类型转换，字面量就是
#: 密钥本身，不能跳过。见 _scan_line 的 `_ASSIGN_RE` 循环。
_METHOD_CALL_RE = re.compile(r'\.[A-Za-z_]\w*\s*\(')


def scan(root):
    """扫描目录并返回 schema v0.1 Finding；结果不含任何凭据原文。"""
    root = os.path.abspath(root)
    pepper = os.urandom(32)
    findings = []
    for path in _walk(root):
        rel = os.path.relpath(path, root).replace('\\', '/')
        try:
            with open(path, encoding='utf-8-sig', errors='replace') as fh:
                text = fh.read()
            context = {
                'generic_key_sensitive': bool(_CRYPTO_CONTEXT_RE.search(text)),
                'generic_key_rule': ('CRED-HARDCODED-PASSWORD'
                                     if _PASSWORD_CONTEXT_RE.search(text)
                                     else 'CRED-HARDCODED-CRYPTO-KEY'),
            }
            for line_no, line in enumerate(text.splitlines(), 1):
                findings.extend(_scan_line(rel, line_no, line, pepper, context))
        except OSError:
            continue
    findings.sort(key=lambda f: (f['file'], f['line'], f['rule_id']))
    return findings


def _walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            ext = os.path.splitext(name)[1].lower()
            if ext not in _EXTS:
                continue
            try:
                if os.path.getsize(path) <= _MAX_FILE:
                    yield path
            except OSError:
                continue


def _scan_line(rel, line_no, line, pepper, context=None):
    out = []
    stripped = line.strip()
    if not stripped:
        return out
    # 注释示例不是运行时凭据；避免 README 风格代码和已注释旧代码制造误报。
    if stripped.startswith(('#', '//', '/*', '*', '<!--')):
        return out

    if _PEM_RE.search(line):
        out.append(_finding(rel, line_no, 0, 'CRED-EMBEDDED-PRIVATE-KEY',
                            'private-key-material', pepper, kind='pattern'))

    for m in _URL_RE.finditer(line):
        material = m.group(1) + ':' + m.group(2)
        out.append(_finding(rel, line_no, m.start(), 'CRED-IN-URL', material,
                            pepper, kind='pattern'))

    log = _LOG_RE.search(line)
    if log and _SENSITIVE.search(_STRING_LITERAL_RE.sub(' ', log.group(1))):
        # 指纹只基于位置和规则，不保存或散列整行源码。
        out.append(_finding(rel, line_no, log.start(), 'CRED-IN-LOG',
                            '%s:%s' % (rel, line_no), pepper, kind='ast',
                            value_length=0))

    # 字面量直接进入明确的密钥构造/加密 API，不依赖变量名猜测。
    for m in _DIRECT_KEY_LITERAL_RE.finditer(line):
        out.append(_finding(rel, line_no, m.start(),
                            'CRED-HARDCODED-CRYPTO-KEY', m.group('value'),
                            pepper, kind='pattern'))

    for m in _ASSIGN_RE.finditer(line):
        name, value = m.group('name'), m.group('value')
        prefix = m.group('prefix')
        if _RUNTIME_SOURCE_RE.search(prefix):
            continue
        if _PLACEHOLDER.match(value.strip()):
            continue
        # In `spec = new SecretKeySpec(keyBytes, "DES")`, the quoted second
        # argument names an algorithm; it is not credential material.  The
        # first argument, when literal, is handled by _DIRECT_KEY_LITERAL_RE.
        # Checking the constructor's argument boundary also works when the
        # assigned variable is unfortunately named `secretKeySpec`.
        if (re.search(r'\b(?:SecretKeySpec|PBEKeySpec)\s*\(', prefix)
                and prefix.rstrip().endswith(',')):
            continue
        # 字面量落在「方法调用实参」或「下标」位置时不是赋值右值：
        # `key.getBytes("UTF-8")` 的 "UTF-8" 是编码、`record['Secret']` 的
        # 'Secret' 是键。只认 `.方法(` 与未配平 `[`；`[]byte("…")` / `bytes("…")`
        # 是类型转换，字面量就是密钥，必须保留。
        if _METHOD_CALL_RE.search(prefix) or prefix.count('[') > prefix.count(']'):
            continue
        # 字符串拼接片段：`key := "Login:" + …` 或 URL 参数误匹配（value 内
        # 混入 ` + `）。真凭据字面量不是拼接中间件。
        if ' + ' in value or line[m.end():m.end() + 2].lstrip().startswith('+'):
            continue
        rule = _assignment_rule(name, value, context)
        is_weak = value.lower() in _WEAK and _SENSITIVE.search(name)
        # 同一字面量只给一个主结论：弱口令比泛化的“硬编码口令”更具体。
        if is_weak:
            out.append(_finding(rel, line_no, m.start(), 'CRED-DEFAULT-WEAK',
                                value, pepper, kind='pattern'))
        elif rule:
            out.append(_finding(rel, line_no, m.start(), rule, value, pepper,
                                kind='pattern'))
        # 高熵规则只兜底未知敏感变量，避免与 token/key 确定规则重复上报。
        if (not rule and not is_weak and _SENSITIVE.search(name)
                and len(value) >= 20
                and _entropy(value) >= 3.5):
            out.append(_finding(rel, line_no, m.start(),
                                'CRED-HIGH-ENTROPY-SECRET', value, pepper,
                                kind='entropy'))
    for m in _ARRAY_ASSIGN_RE.finditer(line):
        name, value = m.group('name'), m.group('value')
        rule = _assignment_rule(name, value, context)
        if rule:
            out.append(_finding(rel, line_no, m.start(), rule, value, pepper,
                                kind='pattern'))
    for m in _CHAR_ARRAY_ASSIGN_RE.finditer(line):
        name, value = m.group('name'), m.group('value')
        rule = _assignment_rule(name, value, context)
        if rule:
            out.append(_finding(rel, line_no, m.start(), rule, value, pepper,
                                kind='pattern'))
    return _dedup(out)


def _is_algo_name(value):
    return value.strip().upper() in _ALGO_NAME_VALUES


def _assignment_rule(name, value, context=None):
    v = value.strip()
    if _PASSWORD.search(name):
        # 纯数字开关值（"0" / "1" / "90"）是配置开关或周期，不是口令。
        if re.fullmatch(r'\d{1,3}', v):
            return None
        return 'CRED-HARDCODED-PASSWORD'
    if _TOKEN.search(name):
        return 'CRED-HARDCODED-TOKEN'
    if _CRYPTO_KEY.search(name):
        if _is_algo_name(v):
            return None
        # 已知默认/弱口令值（如 Java keytool 的 changeit）归口令，不归密钥。
        if v.lower() in _WEAK:
            return 'CRED-DEFAULT-WEAK'
        return 'CRED-HARDCODED-CRYPTO-KEY'
    if ((context or {}).get('generic_key_sensitive')
            and _GENERIC_KEY_NAME.fullmatch(name)):
        if _is_algo_name(v):
            return None
        if v.lower() in _WEAK:
            return 'CRED-DEFAULT-WEAK'
        return (context or {}).get('generic_key_rule',
                                   'CRED-HARDCODED-CRYPTO-KEY')
    return None


def _entropy(text):
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(text))
    return -sum((c / n) * math.log(c / n, 2) for c in counts.values())


def _finding(file, line, column, rule_id, material, pepper, kind,
             value_length=None):
    title, severity, action, reference = RULES[rule_id]
    fingerprint = hmac.new(pepper, material.encode('utf-8', 'replace'),
                           hashlib.sha256).hexdigest()
    length = len(material) if value_length is None else value_length
    # The HMAC key changes on every scan, so the fingerprint MUST NOT enter
    # finding_id: otherwise the same source finding receives a new ID each
    # time and report diffs / AI resume cannot line up. _dedup assigns an
    # ordinal if distinct hits share this source coordinate; no unhashed
    # credential material enters the stable ID.
    basis = '%s|%s|%s|%s' % (file, rule_id, line, column)
    finding_id = hashlib.sha1(basis.encode('utf-8')).hexdigest()[:12]
    raw = {
        'rule_id': rule_id,
        'fingerprint': 'hmac-sha256:' + fingerprint,
        'masked': '<REDACTED:length=%d>' % length,
    }
    return {
        'schema_version': '0.1',
        'finding_id': finding_id,
        'finding_kind': 'credential',
        'rule_id': rule_id,
        'file': file,
        'line': line,
        'algorithm': 'Credential',
        'algorithm_normalized': 'CREDENTIAL',
        'usage': 'authentication',
        'risk': 'not_applicable',
        'severity': severity,
        'confidence': 0.9 if kind == 'pattern' else 0.7,
        'evidence': [{
            'tool': TOOL_NAME,
            'kind': kind,
            'lines': [line],
            'raw': raw,
        }],
        'explanation': '检测到凭据管理问题：%s。检测结果未保存凭据原文。' % title,
        'evidence_refs': ['E1'],
        'remediation': {
            'decided': True,
            'reason': 'decided',
            'action': action,
            'source': 'rule-base',
            'references': [reference],
        },
        'tags': ['credential', rule_id.lower()],
    }


def _dedup(findings):
    seen, out, ordinals = set(), [], {}
    for f in findings:
        key = (f['rule_id'], f['line'], f['evidence'][0]['raw']['fingerprint'])
        if key not in seen:
            seen.add(key)
            base_id = f['finding_id']
            ordinal = ordinals.get(base_id, 0)
            if ordinal:
                f['finding_id'] = hashlib.sha1(
                    ('%s|%s' % (base_id, ordinal)).encode('ascii')).hexdigest()[:12]
            ordinals[base_id] = ordinal + 1
            out.append(f)
    return out
