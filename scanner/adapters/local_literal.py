"""本地字面量源 —— 第三层模式证据，不依赖任何外部工具。

为什么存在（2026-10-09 cryptoapi-bench 实测定量，203 个 Java 文件）:
    43 条范围内漏报里 24 条，算法名**以字符串字面量写在同一文件**，只是
    经变量/常量间接传入调用点:
        public static final String DEFAULT_CRYPTO = "IDEA";
        Cipher cipher = Cipher.getInstance(String.valueOf(crypto));
    cbom-scan 只认调用点字面量、cryptoscan 的算法表压根没有
    RC2/IDEA/MD2/MD4 —— 两个外部工具在结构上看不见这一类。
    本源补这个盲区；其余 19 条（算法名经方法参数传入、PBE 低迭代次数）
    文件里没有任何算法字面量，仍是无解的天花板，留给 ai/ 模块。

判定（双条件同时满足；实测新增误报 4 条/203 文件，且那 4 个
corrected 负样本文件里确实存在 `Cipher.getInstance("RC2")` 字面量调用，
报得不算冤）:
    1) 同文件存在密码学 API 汇点调用（JCE 的 Xxx.getInstance(...)）——
       只有算法名没有密码学用途的文件（测试资源/说明文档）不许触发
    2) 同文件存在词表内算法名的字符串字面量（"IDEA"），或转换串的
       首段命中（"DES/CBC/PKCS5Padding" 的 DES）

词表 = 已淘汰经典算法（风险统一 broken），刻意不收健全算法 ——
本源只补「经典弱点算法被间接使用」这一类；扩表归 C（与 core/rules
同步，benchmark/README.md 的覆盖缺口清单同源）。

usage 一律 unknown（用途不猜，交融合层复核打 needs-usage-review）。
与外部工具已有同 (file, alg) 分组时本源让位（merge 侧剔除）——
只补盲区，不与工具争同一个发现。

只扫 .java（三个 benchmark 语料都是 Java；Python/Go 的汇点形态不同，
后续按需扩）。
"""
import os
import re

from scanner.normalize import canon_algorithm, norm_algorithm, to_relative_path

TOOL_NAME = 'local-literal'

#: JCE 密码学汇点。SecureRandom 故意不收 —— 它的算法参数与弱点算法
#: 交集小，收了只添噪声。
_SINK_RE = re.compile(
    r'\b(Cipher|MessageDigest|KeyGenerator|KeyPairGenerator|'
    r'SecretKeyFactory|Mac|KeyAgreement)\s*\.\s*getInstance\s*\(')

#: Java 字符串字面量（含转义）。只认带引号的字面量 —— 注释/标识符里
#: 出现算法名不算（那不是「写死的算法选择」）。
_STRING_RE = re.compile(r'"((?:\\.|[^"\\])*)"')

#: 已淘汰经典算法词表（norm 形式）。全部 broken；扩表归 C。
BROKEN_ALGORITHMS = frozenset((
    'DES', '3DES', 'DESEDE',                      # 对称：DES 家族
    'BLOWFISH', 'CAST5', 'CAST', 'IDEA', 'SEED',  # Legacy cipher 家族
    'RC2', 'RC4', 'RC5',                          # RC 家族
    'TEA', 'XTEA',                                # TEA 家族
    'MD2', 'MD4', 'MD5',                          # 已破哈希
    'SHA1',                                       # 已不推荐哈希
))

_MAX_FILE_BYTES = 8 * 1024 * 1024   # 防单个巨型生成文件拖垮全文扫描


def _line_of(text, pos):
    return text.count('\n', 0, pos) + 1


def scan(target):
    """遍历目标树，返回本源的 ToolGroup 列表（字段契约见 merge.py docstring）。

    一个 ToolGroup = 一个 (file, 算法) 的字面量证据；行号 = 命中的
    字面量行 + 汇点行（两者都是「算法落地」链条上的证据）。
    """
    groups = []
    target = os.path.abspath(target)
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if not d.startswith('.')]
        for fn in filenames:
            if not fn.endswith('.java'):
                continue
            full = os.path.join(dirpath, fn)
            rel = to_relative_path(full, target)
            if not rel:
                continue
            try:
                if os.path.getsize(full) > _MAX_FILE_BYTES:
                    continue
                with open(full, encoding='utf-8', errors='replace') as fh:
                    src = fh.read()
            except OSError:
                continue          # 读不了的文件交给外部工具，不炸主流程

            sink_lines = [_line_of(src, m.start()) for m in _SINK_RE.finditer(src)]
            if not sink_lines:
                continue

            by_alg = {}           # norm -> (显示名, [行号])
            for m in _STRING_RE.finditer(src):
                # 转换串只取首段（"DES/CBC/PKCS5Padding" 的算法段是 DES）
                first_seg = m.group(1).split('/', 1)[0]
                tok = norm_algorithm(first_seg)
                if tok not in BROKEN_ALGORITHMS:
                    continue
                display, lines = by_alg.get(tok, (first_seg, []))
                lines.append(_line_of(src, m.start()))
                by_alg[tok] = (display, lines)

            for tok, (display, lines) in by_alg.items():
                groups.append({
                    'tool': TOOL_NAME,
                    'file': rel,
                    'alg_norm': canon_algorithm(display),
                    'algorithm': display,
                    'usage': 'unknown',
                    'lines': sorted(set(lines) | set(sink_lines)),
                    'severity': None,          # 本层没有 severity 概念
                    'confidence': None,
                    'risk': 'broken',          # 词表内全部是经典已淘汰算法
                    'risk_types': [],          # （cryptoscan 专用字段）
                    'quantum_as_seen': [],     # （cryptoscan 专用字段）
                    'raw': {'kind': 'same-file-literal', 'algorithm': display,
                            'sinks': len(sink_lines)},
                })
    return groups
