"""云 LLM 请求前的脱敏 —— 方案 §19 的落地实现。

方案 §19 原文：**用户原始代码默认本地。**

上游 scanner 产出的 `evidence[].raw` 里逐字保留着 CryptoScan 的原始记录，
其中两个字段直接就是用户源码：

    "context": "KeyPairGenerator keyGen = KeyPairGenerator.getInstance(\\"RSA\\");"
    "file":    "D:\\\\code_competition\\\\_smoke\\\\...\\\\CryptoSamples.java"

实测 91 条 finding 原样发出去是 **120,596 字符** —— 用户的源码行和本机目录结构
全部出网。这既违反方案 §19，也是答辩时答不上来的问题。

本模块的回答是：**不发代码，只发「代码的形状」。**

    "context": "KeyPairGenerator keyGen = KeyPairGenerator.getInstance(\\"RSA\\");"
        ↓  只抽方法链
    "call_shape": ["KeyPairGenerator.getInstance"]

为什么这样还够用：判用途靠的是**调用了哪个 API**，不是源码里写了什么数据。

    Signature.getInstance       -> 签名
    Cipher.getInstance          -> 加密
    KeyAgreement.getInstance    -> 密钥交换
    MessageDigest.getInstance   -> 哈希
    Mac.getInstance             -> 认证

这些信息全在方法名里。变量名、字符串字面量、注释、密钥 —— 一个都不需要，
所以一个都不发。

设计原则是 **allowlist（默认拒绝），不是 denylist（默认放行）**：
只有明确认识的上游字段才会被发送，上游将来新增字段**默认不会**跟着漏出去。
漏一个字段最多是少给模型一点线索；放行一个字段就是源码出网。
两种错误代价不对称，所以默认必须往「不发」这边倒。
"""
import re

#: 要发送的 cryptoscan 记录字段。**白名单**，新增字段须显式加入。
_SAFE_RECORD_KEYS = (
    'type', 'findingType', 'category', 'algorithm', 'primitive',
    'migrationStatus', 'quantumRisk', 'confidence', 'purpose',
    'severity', 'language',
)

#: 要发送的 cbom-scan 字段。cbom-scan 的记录本来就不含源码，同样走白名单。
_SAFE_CBOM_KEYS = ('id', 'algo', 'prim', 'risk')

#: 含源码的字段名 —— 这些**不发送**，只从里面抽调用形状。
_CODE_KEYS = ('context', 'match')

#: 方法链。只匹配标识符和点号，**匹配不到字符串字面量、数字、路径**。
#: 例："KeyPairGenerator.getInstance(\"RSA\")" -> KeyPairGenerator.getInstance
_CALL_SHAPE_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+')

#: 单条 evidence 最多回传多少个调用形状，防止长记录把 payload 撑爆。
_MAX_SHAPES = 12

#: context='full' 模式下，单条 evidence 最多回传几行源码、每行截多长。
_MAX_CONTEXT = 6
_MAX_CONTEXT_LEN = 200

#: 疑似密钥的形态。**分两条**，因为一刀切必然误伤。
#:
#: 踩过的两个坑，都是真实数据实测出来的：
#:
#:   坑1 纯 `[A-Za-z0-9+/]{20,}` 会把纯大写算法名（POSTQUANTUMCRYPTOLIBRARY）
#:       和驼峰方法名（GenerateFromPassword）当成密钥 —— 实测 7 条中招，
#:       把 `bcrypt.GenerateFromPassword` 啃成 `bcrypt.<REDACTED>`。
#:       -> 所以 alnum 那条要求大小写数字混排；真密钥三类都有，
#:          算法名/方法名单一命名风格。
#:
#:   坑2 base64 字符集**包含 `/`**，而密码学变换串也满是 `/`：
#:       `DES/ECB/PKCS5Padding` 正好 20 字符且大小写数字混排，被当成密钥抹掉 ——
#:       **而 ECB 和 GCM 的区别恰恰是判风险的关键信息**。
#:       -> 所以含 `+/` 的那条把门槛提到 40 字符；变换串普遍在 20 出头。
_ALNUM = r'[A-Za-z0-9]{20,}'
_ALNUM_MIXED = (r'(?=[A-Za-z0-9]*[a-z])(?=[A-Za-z0-9]*[A-Z])'
                r'(?=[A-Za-z0-9]*[0-9])')

#: 兜底：即便某个字符串被漏进 payload，也把这些形态抹掉。
_SECRET_RES = (
    re.compile(r'\b(?=' + _ALNUM + r'\b)' + _ALNUM_MIXED + _ALNUM + r'\b'),
    re.compile(r'\b[A-Za-z0-9+/]{40,}={0,2}\b'),
    re.compile(r'\b[0-9a-fA-F]{32,}\b'),
    # key=value 形态的凭据。**右侧必须是引号字面量或长随机串**。
    #
    #   坑3 `private_key\s*=\s*\S+` 会把**赋值语句**当成凭据：
    #       `private_key = rsa.generate_private_key(` 整行被抹成 <REDACTED> ——
    #       而这是「调用密钥生成函数」，恰好是判用途最关键的一条线索。
    #       -> 右侧限定为引号字面量或 20+ 位随机串；函数调用是代码，不抹。
    re.compile(r'(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|'
               r'access[_-]?key|private[_-]?key|credential)\b\s*[:=]\s*'
               r'(?:"[^"\n]*"|\'[^\'\n]*\'|[A-Za-z0-9+/=_-]{20,}\b(?!\s*\())'),
    # 绝对路径（Windows 盘符 / Unix 常见根），只留文件名
    re.compile(r'(?:[A-Za-z]:[\\/]|/(?:home|Users|root|var|opt|tmp)/)'
               r'[^\s"\']*[\\/]([^\s"\'\\/]+)'),
)


def call_shape(text):
    """从一段源码里抽出方法调用链（去重，保序）。

    >>> call_shape('KeyPairGenerator.getInstance("RSA")')
    ['KeyPairGenerator.getInstance']
    """
    if not isinstance(text, str):
        return []
    seen, out = set(), []
    for m in _CALL_SHAPE_RE.finditer(text):
        s = m.group(0)
        if s not in seen:
            seen.add(s)
            out.append(s)
        if len(out) >= _MAX_SHAPES:
            break
    return out


def basename(path):
    """只保留文件名，丢掉整条目录结构。

    用正斜杠和反斜杠一起切 —— 上游给的是 Windows 路径，
    但 os.path.basename 在 POSIX 上不认反斜杠。
    """
    if not isinstance(path, str):
        return None
    name = re.split(r'[\\/]', path.strip())[-1]
    return name or None


def scrub(value):
    """兜底清洗：把疑似凭据 / 绝对路径抹掉。对 dict / list 递归。"""
    if isinstance(value, dict):
        return {k: scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    if not isinstance(value, str):
        return value
    out = value
    for pat in _SECRET_RES[:-1]:
        out = pat.sub('<REDACTED>', out)
    # 路径那条有捕获组，单独处理：替换成捕获到的文件名
    out = _SECRET_RES[-1].sub(r'\1', out)
    return out


def redact_evidence(evidence, context='shape'):
    """把一条上游 evidence 压成「可安全出网」的形态。

    只保留：来源工具、证据类型、命中行数、调用形状、上游元数据白名单。
    **raw 整体不发送** —— 它正是源码所在的地方。

    Args:
        context: 'shape'（默认）只发方法链；'full' 额外发**脱敏后**的原始代码行。
                 注意：cbom-scan 的证据里本来就没有源码，两种模式对它没有区别。
    """
    out = {
        'tool': evidence.get('tool'),
        'kind': evidence.get('kind'),
        'n_hits': len(evidence.get('lines') or []),
        'call_shape': [],
        'upstream': {},
    }
    raw = evidence.get('raw')
    if not isinstance(raw, dict):
        return out

    tool = evidence.get('tool')
    if tool == 'cbom-scan':
        out['upstream'] = {k: raw[k] for k in _SAFE_CBOM_KEYS if k in raw}

    elif tool == 'cryptoscan':
        merged = {}
        ctx_lines = []
        for rec in (raw.get('records') or []):
            if not isinstance(rec, dict):
                continue
            for k in _SAFE_RECORD_KEYS:
                if k in rec and k not in merged:
                    merged[k] = rec[k]
            for k in _CODE_KEYS:
                if isinstance(rec.get(k), str):
                    out['call_shape'].extend(call_shape(rec[k]))
                    if k == 'context' and len(ctx_lines) < _MAX_CONTEXT:
                        ctx_lines.append(rec[k])
        out['upstream'] = scrub(merged)
        if context == 'full' and ctx_lines:
            # 仍要过 scrub：路径缩成文件名、疑似密钥抹掉。
            # 「发原文」不等于「发路径和密钥」—— 后者对判用途毫无帮助。
            out['call_context'] = [scrub(c)[:_MAX_CONTEXT_LEN] for c in ctx_lines]

    # 其它工具（含将来新增的）：默认不发 raw。
    # 少一条线索远好过漏一次源码 —— 见模块 docstring 的 allowlist 说明。
    seen, shapes = set(), []
    for s in out['call_shape']:
        if s not in seen:
            seen.add(s)
            shapes.append(s)
    out['call_shape'] = shapes[:_MAX_SHAPES]
    return out


def redact_finding(finding, context='shape'):
    """构造发往云端的 payload。

    Args:
        finding: scanner 层产出的统一 Finding（见 core/schema/）
        context: 'shape'（默认）只发方法链，零源码出网；
                 'full' 额外发脱敏后的原始代码行 —— 判用途更准，
                 但源码行确实出网，属于方案 §19 的口径放宽，需显式选择。

    Returns:
        dict，直接 json.dumps 后作为 user message 发送。
        两种模式下都**不含绝对路径、不含疑似凭据**。
    """
    evidence = finding.get('evidence') or []
    payload = {
        'finding_id': finding.get('finding_id'),
        'algorithm': finding.get('algorithm'),
        'algorithm_normalized': finding.get('algorithm_normalized'),
        'scanner_usage': finding.get('usage'),
        'risk': finding.get('risk'),
        'severity': finding.get('severity'),
        'confidence': finding.get('confidence'),
        # 只要文件名，不要目录 —— 目录会暴露本机结构
        'file_basename': basename(finding.get('file')),
        'evidence': [redact_evidence(e, context) for e in evidence],
    }
    if finding.get('tags'):
        payload['tags'] = list(finding['tags'])
    return scrub(payload)


# ------------------------------------------------------------------ 自检

#: 一段含源码、含密钥、含绝对路径的假 evidence —— 用它反证脱敏真的生效。
_FIXTURE = {
    'finding_id': 'deadbeef1234',
    'file': r'D:\code_competition\_smoke\cryptoscan-src\crypto-samples\CryptoSamples.java',
    'algorithm': 'RSA',
    'algorithm_normalized': 'RSA',
    'usage': 'unknown',
    'risk': 'shor',
    'severity': 'high',
    'tags': ['needs-usage-review'],
    'evidence': [{
        'tool': 'cryptoscan',
        'kind': 'pattern',
        'lines': [28],
        'raw': {'records': [{
            'id': 'RSA-001-28-64',
            'type': 'RSA Algorithm',
            'file': r'D:\code_competition\_smoke\crypto-samples\CryptoSamples.java',
            'line': 28,
            'match': 'KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA"',
            'context': 'KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");',
            'severity': 3, 'quantumRisk': 'VULNERABLE', 'confidence': 'MEDIUM',
            'purpose': 'general', 'language': 'java',
            'apiToken': 'sk-live-Aaa1Bbb2Ccc3Ddd4Eee5Fff6Ggg7Hhh8',
        }]},
    }],
}

#: 这些字符串**绝不允许**出现在 payload 里。是外部事实（用户源码），
#: 不是复述实现 —— 断言的是「源码没出去」，不是「代码这么写的」。
_FORBIDDEN = [
    'KeyPairGenerator keyGen',                 # 源码行
    'getInstance("RSA")',                      # 源码里的字面量
    r'D:\code_competition',                    # 绝对路径
    '_smoke',                                  # 目录名
    'Aaa1Bbb2Ccc3',                            # 凭据（混排 base64 形态）
    'RSA-001-28-64',                           # 上游记录 id
]

#: context='full' 模式下也**绝不允许**出现的东西。
#: 比 _FORBIDDEN 短 —— 因为 full 模式本来就会发代码行，
#: 但「发代码」不等于「发路径和密钥」，后者对判用途毫无帮助。
_FORBIDDEN_ALWAYS = [
    r'D:\code_competition',                    # 绝对路径
    '_smoke',                                  # 目录名
    'Aaa1Bbb2Ccc3',                            # 凭据
    'RSA-001-28-64',                           # 上游记录 id
    'apiToken',                                # 白名单外的上游字段
]

#: 必须**保留**的信息 —— 脱敏不能把判用途的线索也一起抹掉。
_REQUIRED = ['KeyPairGenerator.getInstance', 'RSA', 'java']


def _selftest():
    import json
    fails = []

    payload = redact_finding(_FIXTURE)
    blob = json.dumps(payload, ensure_ascii=False)

    for bad in _FORBIDDEN:
        if bad in blob:
            fails.append('泄露：payload 里出现了 %r' % bad)

    # --- context='full'：发代码行，但路径和密钥仍不许出去 ---
    full = redact_finding(_FIXTURE, context='full')
    fblob = json.dumps(full, ensure_ascii=False)
    for bad in _FORBIDDEN_ALWAYS:
        if bad in fblob:
            fails.append('full 模式泄露：%r' % bad)
    if 'call_context' not in full['evidence'][0]:
        fails.append("full 模式没有真的发出代码行 —— 那这个开关是假的")
    elif 'getInstance' not in fblob:
        fails.append('full 模式的 call_context 内容不对')
    if 'call_context' in payload['evidence'][0]:
        fails.append("shape 模式不该带 call_context")

    for good in _REQUIRED:
        if good not in blob:
            fails.append('过度脱敏：payload 里丢了 %r' % good)

    # 绝对路径不能以任何形式残留
    for marker in ('C:\\', 'D:\\', '/home/', '/Users/'):
        if marker in blob:
            fails.append('泄露：payload 里出现了绝对路径前缀 %r' % marker)

    # 只发文件名，不发目录
    if payload.get('file_basename') != 'CryptoSamples.java':
        fails.append('file_basename 应为 CryptoSamples.java，得到 %r'
                     % payload.get('file_basename'))

    # 上游白名单外的字段不能被带出去
    if 'apiToken' in blob:
        fails.append('泄露：白名单外的上游字段 apiToken 被发送')

    # 调用形状确实抽出来了（这是「不发代码但仍有判用途线索」的关键）
    shapes = payload['evidence'][0]['call_shape']
    if 'KeyPairGenerator.getInstance' not in shapes:
        fails.append('未抽出调用形状，得到 %r' % shapes)

    # 边界：空 / None / 非字符串不该炸
    for weird in (None, '', 123, []):
        call_shape(weird)
    if basename(None) is not None:
        fails.append('basename(None) 应为 None')

    # --- 回归：算法名 / 方法名不能被当成密钥抹掉 ---
    #     真实数据里 POSTQUANTUMCRYPTOLIBRARY x5、bcrypt.GenerateFromPassword x2
    #     曾被误伤，抹掉的恰好是判用途最需要的线索。
    for keep in ('POSTQUANTUMCRYPTOLIBRARY', 'bcrypt.GenerateFromPassword',
                 'GenerateFromPassword', 'SHA384512SHA2', 'CHACHA20POLY1305',
                 'NISTPQC', 'COMPOSITESIGNATURE',
                 # 变换串：含 `/`，曾被 base64 那条误伤。
                 # ECB 和 GCM 的区别是判风险的关键，丢了就是真丢信息。
                 'DES/ECB/PKCS5Padding', 'AES/GCM/NoPadding',
                 'RSA/ECB/PKCS1Padding', 'AES/CBC/PKCS5Padding'):
        got = scrub(keep)
        if got != keep:
            fails.append('过度脱敏：%r 被抹成 %r' % (keep, got))

    # --- 回归：赋值语句不能被当成凭据（右值是函数调用 = 代码，不是密钥）---
    for keep in ('private_key = rsa.generate_private_key(',
                 '# Hybrid shared secret = HKDF(x25519_shared || mlkem_shared)',
                 'privateKey, err := rsa.GenerateKey(rand.Reader, 2048)',
                 'password = getPasswordFromVault()'):
        got = scrub(keep)
        if got != keep:
            fails.append('过度脱敏：%r 被抹成 %r' % (keep, got))

    # --- 反过来：真正的密钥形态仍必须抹掉 ---
    for kill in ('Aaa1Bbb2Ccc3Ddd4Eee5Fff6Ggg7Hhh8',
                 'a3f5c9d1e7b204f86a1c3e5d7b9f0a2c4e6d8b0f1a3c5e7d9b2f4a6c8e0d1b3f',
                 'password = "hunter2"',
                 "api_key: 'sk-abcdefghijklmnopqrstuvwx'"):
        if scrub(kill) == kill:
            fails.append('漏抹：疑似密钥 %r 原样通过' % kill[:24])
        elif 'REDACTED' not in scrub(kill):
            fails.append('删掉了但没留 REDACTED 标记：%r' % kill[:24])

    if fails:
        print('[FAIL] %d 项断言未通过:' % len(fails))
        for f in fails:
            print('  - %s' % f)
        return 1

    print('[PASS] 全部断言通过')
    print()
    print('  脱敏后的 payload（这就是**全部**会发给云端的东西）:')
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(_selftest())
