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
    r'(?P<value>[^"\'\r\n]{3,4096})(?P=quote)')
_ARRAY_ASSIGN_RE = re.compile(
    r'(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,80})'
    r'(?:\s*\[[^\]\r\n]{0,40}\])?\s*(?::=|=)\s*'
    r'(?:\[[^\]\r\n]*\](?:byte)?\s*)?\{(?P<value>[0-9xXa-fA-F,\s-]{7,1024})\}')
_URL_RE = re.compile(r'\b[a-zA-Z][a-zA-Z0-9+.-]*://([^\s/:@]+):([^\s/@]+)@')
_PEM_RE = re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----')
_LOG_RE = re.compile(r'(?i)\b(?:print|println|printf|console\.log|log\.(?:trace|debug|info|warn|error)|logger\.(?:trace|debug|info|warn|error))\s*\((.*)')

_PASSWORD = re.compile(r'(?i)(?:pass(?:word|wd|phrase)?|pwd|keystorepass|storepass)')
_TOKEN = re.compile(r'(?i)(?:api[_-]?(?:key|token)|access[_-]?token|auth[_-]?token|bearer|jwt[_-]?secret|client[_-]?secret|secret[_-]?key|credential)')
_CRYPTO_KEY = re.compile(r'(?i)(?:aes|des|rsa|hmac|crypto|cipher|encrypt|decrypt)[_.-]*(?:key|secret)|(?:private|master|signing)[_.-]*key')
_SENSITIVE = re.compile(r'(?i)(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)')
_PLACEHOLDER = re.compile(r'(?i)^(?:example|sample|dummy|placeholder|replace[_-]?me|changeme|your[_-].*|<.*>|\$\{.*\}|%\w+%)$')
_WEAK = {'admin', 'admin123', 'password', 'password1', 'passw0rd', '123456',
         '12345678', 'root', 'guest', 'test', 'default', 'changeme', 'secret'}
_CRYPTO_CONTEXT_RE = re.compile(
    r'(?i)(?:SecretKeySpec|PBEKeySpec|KeyStore\.(?:load|setKeyEntry)|'
    r'NewCipher|_set_key|setKey\s*\(|privateKey|signingKey|encryptionKey)')
_RUNTIME_SOURCE_RE = re.compile(
    r'(?i)(?:getenv|environ|getProperty|process\.env|config\.|vault|secretManager)')


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
            context = {'generic_key_sensitive': bool(_CRYPTO_CONTEXT_RE.search(text))}
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
    if log and _SENSITIVE.search(log.group(1)):
        # 指纹只基于位置和规则，不保存或散列整行源码。
        out.append(_finding(rel, line_no, log.start(), 'CRED-IN-LOG',
                            '%s:%s' % (rel, line_no), pepper, kind='ast',
                            value_length=0))

    for m in _ASSIGN_RE.finditer(line):
        name, value = m.group('name'), m.group('value')
        if _RUNTIME_SOURCE_RE.search(m.group('prefix')):
            continue
        if _PLACEHOLDER.match(value.strip()):
            continue
        rule = _assignment_rule(name, value, context)
        if rule:
            out.append(_finding(rel, line_no, m.start(), rule, value, pepper,
                                kind='pattern'))
        if value.lower() in _WEAK and _SENSITIVE.search(name):
            out.append(_finding(rel, line_no, m.start(), 'CRED-DEFAULT-WEAK',
                                value, pepper, kind='pattern'))
        if (_SENSITIVE.search(name) and len(value) >= 20
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
    return _dedup(out)


def _assignment_rule(name, value, context=None):
    if _PASSWORD.search(name):
        return 'CRED-HARDCODED-PASSWORD'
    if _TOKEN.search(name):
        return 'CRED-HARDCODED-TOKEN'
    if _CRYPTO_KEY.search(name):
        return 'CRED-HARDCODED-CRYPTO-KEY'
    if (context or {}).get('generic_key_sensitive') and name.lower() in {
            'key', 'key2', 'defaultkey', 'default_key', 'encrypt_key'}:
        return 'CRED-HARDCODED-CRYPTO-KEY'
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
    seen, out = set(), []
    for f in findings:
        key = (f['rule_id'], f['line'], f['evidence'][0]['raw']['fingerprint'])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
