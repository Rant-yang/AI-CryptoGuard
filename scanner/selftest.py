"""scanner 自检 —— 对齐 core/rules/pqc_routing.py 的做法：

    python scanner/selftest.py        # 全部断言通过则退出码 0

C 合并分支前跑这一条 + core/schema/validate.py，scanner 侧就算验收了。

断言全部针对**外部行为**（真实密码学约定 / schema 契约 / 实测踩过的坑），
不复述实现逻辑 —— 改内部写法不应导致这里挂掉，挂了就是行为真变了。
覆盖: normalize 的映射与裁决、merge 的融合规则（含行号吸收与输入保护）、
coverage 的差异计数、cbom_report 的结构与确定性。
"""
import os
import hashlib
import re
import sys
import tempfile
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from scanner.adapters import (cbom_scan, credential_scan, cryptoscan, java_properties,
                              local_literal, python_ast, source_filter)  # noqa: E402
from scanner.cbom_report import render_cbom                  # noqa: E402
from scanner.coverage import coverage_diff                   # noqa: E402
from scanner.merge import merge                              # noqa: E402
from scanner.normalize import (                              # noqa: E402
    canon_algorithm,
    max_severity,
    most_severe_risk,
    norm_algorithm,
    split_combined_algorithm,
    to_relative_path,
    usage_contradicts_algorithm,
)


def _print_safe(text):
    """中文控制台（GBK）打印兜底：编码不了的字符替换掉，绝不让自检挂掉。"""
    try:
        print(text)
    except UnicodeEncodeError:
        sys.stdout.buffer.write(text.encode('gbk', errors='replace'))
        sys.stdout.buffer.write(b'\n')


def _group(tool, file, alg, usage, lines, risk=None, sev=None, conf=None,
           risk_types=(), quantum_as_seen=(), algorithm=None):
    """构造一个 ToolGroup（字段契约见 merge.py docstring）。"""
    return {
        'tool': tool, 'file': file, 'alg_norm': alg,
        'algorithm': algorithm or alg, 'usage': usage,
        'lines': list(lines), 'severity': sev, 'confidence': conf,
        'risk': risk, 'risk_types': list(risk_types),
        'quantum_as_seen': list(quantum_as_seen), 'raw': {'stub': True},
    }


def test_normalize(check):
    # --- 算法名归一化：三个工具的写法差异必须被抹平 ---
    check("norm('SHA-1') == 'SHA1'", norm_algorithm('SHA-1'), 'SHA1')
    check("norm('Ed25519 / X25519') == 'ED25519X25519'",
          norm_algorithm('Ed25519 / X25519'), 'ED25519X25519')
    # 别名：只收确定同义（粒度不同的刻意不并）
    check("canon('ECDSA / EC') 对齐 CryptoScan 的 'ECC'",
          canon_algorithm('ECDSA / EC'), canon_algorithm('ECC'))
    check('DES 与 3DES 归一后仍为不同算法',
          (canon_algorithm('DES'), canon_algorithm('3DES')),
          ('DES', '3DES'))
    check('cbom 的 DES / 3DES asset 按两个算法拆开',
          split_combined_algorithm('DES / 3DES'), ['DES', '3DES'])
    # --- usage 映射：分不出用途的如实 unknown，不许猜 ---
    from scanner.normalize import CBOM_PRIM_TO_USAGE, CRYPTOSCAN_PURPOSE_TO_USAGE
    check('cbom prim=pke -> unknown（公钥加密分不出签名还是加密）',
          CBOM_PRIM_TO_USAGE.get('pke'), 'unknown')
    check('cbom prim=kem -> unknown（NIST PQC 大类混含 KEM 与签名）',
          CBOM_PRIM_TO_USAGE.get('kem'), 'unknown')
    check('cbom prim=key-agree -> key_exchange', CBOM_PRIM_TO_USAGE.get('key-agree'),
          'key_exchange')
    check('cs purpose=general -> unknown', CRYPTOSCAN_PURPOSE_TO_USAGE.get('general'),
          'unknown')
    check('cs purpose=tls-configuration -> tls_configuration',
          CRYPTOSCAN_PURPOSE_TO_USAGE.get('tls-configuration'), 'tls_configuration')
    # --- severity / confidence 表示法统一 ---
    from scanner.normalize import CRYPTOSCAN_SEVERITY_TO_ENUM
    check('cs severity 4 -> critical', CRYPTOSCAN_SEVERITY_TO_ENUM.get(4), 'critical')
    check('cs severity 0 -> info', CRYPTOSCAN_SEVERITY_TO_ENUM.get(0), 'info')
    check('risk 平级时 shor 优先（量子迁移主线）',
          most_severe_risk(['broken', 'shor']), 'shor')
    check('risk 取最严重档', most_severe_risk(['grover', 'broken']), 'broken')
    check('risk 无来源 -> review（不猜）', most_severe_risk([]), 'review')
    check('severity 取最大', max_severity(['info', 'critical', 'high']), 'critical')
    # --- 确定性用途矛盾（实测上游误判的形态） ---
    contradictions = [
        ('RSA', 'hashing', True, '公钥算法不做哈希（实测: import 行被 cs 判成 RSA/hashing）'),
        ('MLKEM', 'hashing', True, '后量子公钥算法不做哈希'),
        ('MD5', 'encryption', True, '纯哈希不加密（实测上游误判形态）'),
        ('SHA256', 'signing', True, '纯哈希不做数字签名'),
        ('AES', 'signing', True, '数字签名需要非对称密钥'),
        ('CHACHA20POLY1305', 'signing', True, 'AEAD 不是签名'),
    ]
    for alg, usage, want, why in contradictions:
        check('矛盾 %s x %s == %s（%s）' % (alg, usage, want, why),
              usage_contradicts_algorithm(alg, usage), want)
    for alg, usage in [('RSA', 'signing'), ('RSA', 'encryption'), ('MD5', 'hashing'),
                       ('AES', 'encryption'), ('AESGCM', 'encryption'),
                       ('PBKDF2', 'authentication'), ('ECC', 'unknown')]:
        check('非矛盾 %s x %s 不打标' % (alg, usage),
              usage_contradicts_algorithm(alg, usage), False)
    # 78 type 值域冒烟暴露的新算法也要覆盖（FN-DSA / XChaCha20）
    check('矛盾 FNDSA x hashing（PQC 签名不做哈希）',
          usage_contradicts_algorithm('FNDSA', 'hashing'), True)
    check('矛盾 XCHACHA20 x signing（流密码不做签名）',
          usage_contradicts_algorithm('XCHACHA20', 'signing'), True)


def test_relative_path(check):
    import tempfile
    with tempfile.TemporaryDirectory() as root:
        inner = os.path.join(root, 'sub', 'a.go')
        os.makedirs(os.path.dirname(inner), exist_ok=True)
        open(inner, 'w', encoding='utf-8').close()
        # CryptoScan 给绝对路径（信息泄露，必须剥）
        check('绝对路径 -> 项目内相对 + 正斜杠',
              to_relative_path(inner, root), 'sub/a.go')
        # cbom-scan 给相对路径 —— 不能再做 relpath（会相对 cwd 算错）
        check('相对路径原样保留',
              to_relative_path('sub/a.go', root), 'sub/a.go')
        check('反斜杠相对路径规范成正斜杠',
              to_relative_path('sub\\a.go', root), 'sub/a.go')
        # 目标目录之外：'../' 形式照样泄露路径，必须丢弃（返回 ''）
        check('目标外路径 -> 空串（丢弃，不泄露）',
              to_relative_path(os.path.join(os.path.dirname(root), 'x.go'), root), '')
        # Windows 跨盘：relpath 会抛 ValueError —— 不许崩，返回空串
        other_root = 'C:\\' if root[:1].upper() != 'C' else 'D:\\'
        check('跨盘路径 -> 空串（不抛 ValueError）',
              to_relative_path(other_root + 'x\\a.go', root), '')
        # GitHub Linux runner must also handle an explicitly Windows-styled
        # pair from saved CryptoScan JSON; never turn it into a POSIX-relative
        # path or accept a different drive / a file outside the project.
        win_root = r'D:\acg-fixture'
        check('Windows 绝对路径对在 Linux 仍归位',
              to_relative_path(r'D:\acg-fixture\sub\a.go', win_root), 'sub/a.go')
        check('Windows 绝对路径跨盘拒绝',
              to_relative_path(r'C:\elsewhere\a.go', win_root), '')
        check('Windows 绝对路径目标外拒绝',
              to_relative_path(r'D:\elsewhere\a.go', win_root), '')
        if os.name != 'nt':
            check('Windows 源路径不能映射进 POSIX 目标',
                  to_relative_path(r'D:\acg-fixture\a.go', root), '')


def test_merge_absorb_and_fuse(check):
    """行号吸收 + 双源融合：schema 计数单位与合并规则的核心场景。"""
    g_cbom = _group('cbom-scan', 'a.go', 'RSA', 'unknown', [10, 20], risk='shor',
                    algorithm='RSA')
    g_cs_sig = _group('cryptoscan', 'a.go', 'RSA', 'signing', [10], sev='high',
                      conf=0.9, quantum_as_seen=['shor'], algorithm='RSA')
    g_cs_enc = _group('cryptoscan', 'a.go', 'RSA', 'encryption', [20], sev='medium',
                      conf=0.6, quantum_as_seen=['shor'], algorithm='RSA')
    original_lines = list(g_cbom['lines'])

    findings = merge([g_cbom, g_cs_sig, g_cs_enc])
    by_usage = {f['usage']: f for f in findings}

    check('同一 (file,alg) 按 usage 拆成两条', len(findings), 2)
    check('unknown 桶全部被行号吸收吸收走', 'unknown' in by_usage, False)
    check('signing 条挂双源证据',
          len(by_usage['signing']['evidence']), 2)
    check('吸收后 cbom 的行 10 归 signing、行 20 归 encryption',
          (by_usage['signing']['evidence'][0]['lines'],
           by_usage['encryption']['evidence'][0]['lines']), ([10], [20]))
    check('risk 由主源 cbom 裁决为 shor',
          (by_usage['signing']['risk'], by_usage['encryption']['risk']),
          ('shor', 'shor'))
    check('上游 severity 不被 risk 兜底抬高（cs 给 medium 就是 medium）',
          by_usage['encryption']['severity'], 'medium')
    check('confidence 取最大', by_usage['signing']['confidence'], 0.9)
    check('cs 的 quantumRisk 与裁决一致时不打纠正标',
          'upstream-risk-corrected' in by_usage['signing'].get('tags', []), False)
    check('merge 不污染调用方原始分组（coverage 依赖）',
          g_cbom['lines'], original_lines)
    for f in findings:
        check('finding_id 符合 schema 模式（%s）' % f['finding_id'],
              bool(re.fullmatch(r'[0-9a-f]{12}', f['finding_id'])), True)
    check('同输入重复 merge 结果一致（finding_id 可复现）',
          merge([dict(g_cbom), dict(g_cs_sig), dict(g_cs_enc)]), findings)


def test_merge_risk_overrides_and_tags(check):
    """risk 不透传上游：cs 独有发现按 type 表裁决，错标打纠正标记。"""
    g = _group('cryptoscan', 'b.py', 'MD5', 'hashing', [5], sev='critical',
               risk_types=['MD5 Hash Function'], quantum_as_seen=['shor'],
               algorithm='MD5')
    findings = merge([g])
    f = findings[0]
    check('MD5 裁决为 broken（经典攻破，与量子无关）', f['risk'], 'broken')
    check('cs 标 VULNERABLE(=shor) 被推翻 -> upstream-risk-corrected',
          'upstream-risk-corrected' in f.get('tags', []), True)
    check('矛盾用途打 needs-usage-review（此处 hashing 合法，不打）',
          'needs-usage-review' in f.get('tags', []), False)

    g2 = _group('cbom-scan', 'c.go', 'RSA', 'unknown', [1], risk='shor')
    f2 = merge([g2])[0]
    check('用途 unknown 打 needs-usage-review',
          'needs-usage-review' in f2.get('tags', []), True)
    check('无 cs severity 时按 risk 兜底（shor->high）', f2['severity'], 'high')
    g3 = _group('cbom-scan', 'd.go', 'MD5', 'hashing', [1], risk='broken')
    f3 = merge([g3])[0]
    check('broken 兜底为 high（critical 留给真实调用，兜底不越权）',
          f3['severity'], 'high')
    check('无 confidence 来源时不编造（字段缺省）', 'confidence' in f2, False)

    ecb = _group('cryptoscan', 'Demo.java', 'AESECB', 'encryption', [11],
                 risk_types=['AES-ECB Mode'], algorithm='AES-ECB')
    check('type 表外的 AES-ECB 使用共享算法规则判为经典不安全',
          merge([ecb])[0]['risk'], 'broken')
    unknown = _group('cryptoscan', 'Unknown.java', 'MYSTERYCIPHER',
                     'unknown', [3], risk_types=['New Crypto Type'],
                     algorithm='MysteryCipher')
    check('真正未知算法仍为 review，不猜测',
          merge([unknown])[0]['risk'], 'review')


def test_ed25519_match_refinement(check):
    """捆绑 asset 的行级细分：x25519 的行不再是 signing。"""
    data = {'assets': [{
        'id': 'curve25519', 'algo': 'Ed25519 / X25519', 'prim': 'signature',
        'risk': 'shor',
        'occurrences': [
            {'file': 'a.go', 'line': 1, 'match': 'Ed25519'},
            {'file': 'a.go', 'line': 2, 'match': 'x25519'},
            {'file': 'a.go', 'line': 3, 'match': 'ed25519'},
        ],
    }]}
    groups = cbom_scan.to_groups(data, 'unused-target')
    usages = {g['usage']: g['lines'] for g in groups}
    check('ed25519 命中行 -> signing', usages.get('signing'), [1, 3])
    check('x25519 命中行 -> key_exchange', usages.get('key_exchange'), [2])
    check('不再把 X25519 误标为 signing', 'signing' in usages and
          2 in usages['signing'], False)


def test_malformed_inputs(check):
    """畸形上游数据不许崩、不许流出脏组（对抗实测抓过 4 个真 bug，此处防回归）。"""
    # findings/assets 不是数组时（上游格式变化）安全归零，不迭代字符串炸掉
    check('cbom assets 是字符串 -> []',
          cbom_scan.to_groups({'assets': 'x'}, 'T'), [])
    check('cs findings 是字符串 -> []',
          cryptoscan.to_groups({'findings': 'x'}, 'T'), [])
    check('cs finding 字段全缺 -> []',
          cryptoscan.to_groups({'findings': [{}]}, 'T'), [])
    # file 合法但行号全非法的命中：一个真实命中都没有，不许流出空行组
    # （空行组会骗过 coverage 的算法级覆盖统计）
    r = cbom_scan.to_groups({'assets': [{'id': 'x', 'algo': 'RSA',
        'prim': 'pke', 'risk': 'shor', 'occurrences': [
            {'file': None, 'line': 5}, {'file': 'a.go', 'line': 0},
            {'file': 'a.go', 'line': '7'}, {'file': 'a.go'}]}]}, 'T')
    check('cbom 行号全非法 -> 不产出空行组', r, [])
    # 值域外的 severity/confidence/purpose/type：忽略未知值，不猜不崩
    r = cryptoscan.to_groups({'findings': [
        {'algorithm': 'RSA', 'file': r'D:\p\a.py', 'line': 3, 'severity': 7,
         'confidence': 'ULTRA', 'purpose': 'time-travel', 'type': None}]}, r'D:\p')
    check('cs 值域外字段 -> 保守归 unknown/None',
          (r[0]['usage'], r[0]['severity'], r[0]['confidence'], r[0]['risk_types']),
          ('unknown', None, None, []))
    # 目标外 / 驱动器相对路径：丢弃（不泄露路径、不可移植的不带进来）
    r = cryptoscan.to_groups({'findings': [
        {'algorithm': 'RSA', 'file': r'D:\elsewhere\a.py', 'line': 1},
        {'algorithm': 'RSA', 'file': r'D:crypto\b.py', 'line': 2}]}, r'D:\p')
    check('cs 目标外+驱动器相对路径 -> 全丢弃', r, [])
    # merge: 空行组剔除、重复行号去重
    f = merge([
        {'tool': 'cbom-scan', 'file': 'a.go', 'alg_norm': 'RSA',
         'algorithm': 'RSA', 'usage': 'unknown', 'lines': [1, 1, 2],
         'severity': None, 'confidence': None, 'risk': 'shor',
         'risk_types': [], 'quantum_as_seen': [], 'raw': {}},
        {'tool': 'cryptoscan', 'file': 'a.go', 'alg_norm': 'RSA',
         'algorithm': 'RSA', 'usage': 'signing', 'lines': [],
         'severity': 'high', 'confidence': None, 'risk': None,
         'risk_types': [], 'quantum_as_seen': [], 'raw': {}}])
    check('merge 空行组剔除 + 行号去重',
          (len(f), f[0]['evidence'][0]['lines']), (1, [1, 2]))


def test_split_combined_and_no_algorithm(check):
    """任务 1（合并名拆词）+ 任务 2（type 不许当算法）的硬性不变式。"""
    # ---- 任务 1: 拆词规则钉死全部真实形态（cbom-scan asset.algo 实测值域）----
    check('拆: Legacy cipher 合并名 -> 4 个并列算法',
          split_combined_algorithm('Legacy cipher (Blowfish/CAST5/IDEA/SEED)'),
          ['Blowfish', 'CAST5', 'IDEA', 'SEED'])
    check('拆: SSH 依赖的并列算法',
          split_combined_algorithm('SSH (RSA/ECDSA/Ed25519)'),
          ['RSA', 'ECDSA', 'Ed25519'])
    check('不拆: 无括号原样返回',
          split_combined_algorithm('AES-128'), ['AES-128'])
    check('不拆: AES/GCM/NoPadding 是「算法/模式/填充」参数写法，不是并列',
          split_combined_algorithm('AES/GCM/NoPadding'), ['AES/GCM/NoPadding'])
    check('不拆: PKCS#8 括号内是说明文字（alg unspecified）',
          split_combined_algorithm('PKCS#8 private key (alg unspecified)'),
          ['PKCS#8 private key (alg unspecified)'])
    check('不拆: JWT/multi 拆出的段含空格，不是算法 token',
          split_combined_algorithm('JWT/multi (often RS256/ES256)'),
          ['JWT/multi (often RS256/ES256)'])
    check('不拆: SHA-384/512 括号内是家族名单段',
          split_combined_algorithm('SHA-384/512 (SHA-2)'), ['SHA-384/512 (SHA-2)'])

    # ---- 任务 1 端到端: Legacy asset 在 to_groups 里就拆开 ----
    data = {'assets': [{
        'id': 'legacy-sym', 'algo': 'Legacy cipher (Blowfish/CAST5/IDEA/SEED)',
        'prim': 'block-cipher', 'risk': 'broken',
        'occurrences': [{'file': 'a.go', 'line': 7}],
    }]}
    groups = cbom_scan.to_groups(data, 'unused')
    check('Legacy asset 拆成 4 个独立组', len(groups), 4)
    check('拆出的组归一名都是单算法（硬性不变式: 不允许 LEGACY 拼接串）',
          sorted(g['alg_norm'] for g in groups),
          ['BLOWFISH', 'CAST5', 'IDEA', 'SEED'])
    check('拆出组的 algorithm 是具体算法名',
          sorted(g['algorithm'] for g in groups),
          ['Blowfish', 'CAST5', 'IDEA', 'SEED'])
    check('raw.algo 保留原始合并名供溯源',
          groups[0]['raw']['algo'], 'Legacy cipher (Blowfish/CAST5/IDEA/SEED)')

    # ---- 任务 1 补（2026-10-09 cryptoapi-bench 实测抓的坑）: 拆开后命中只归
    # match 点名的候选 —— 否则只用 Blowfish 的文件会把 CAST5/IDEA/SEED 全带上，
    # 每个文件 1 条误报变 3 条（TP 不动、FP +13 的回归就这样来的）----
    data = {'assets': [{
        'id': 'legacy2', 'algo': 'Legacy cipher (Blowfish/CAST5/IDEA/SEED)',
        'prim': 'block-cipher', 'risk': 'broken',
        'occurrences': [
            {'file': 'b.go', 'line': 1, 'match': 'Blowfish'},
            {'file': 'b.go', 'line': 2, 'match': 'CAST5'},
            {'file': 'c.go', 'line': 5, 'match': 'ssh'},   # 对不上任何候选
            {'file': 'c.go', 'line': 6},                   # 无 match
        ],
    }]}
    got = sorted((g['file'], g['algorithm'], tuple(g['lines']))
                 for g in cbom_scan.to_groups(data, 'unused'))
    check('match 点名的候选才继承命中；对不上/缺失时保守归全部',
          got, [
        ('b.go', 'Blowfish', (1,)), ('b.go', 'CAST5', (2,)),
        ('c.go', 'Blowfish', (5, 6)), ('c.go', 'CAST5', (5, 6)),
        ('c.go', 'IDEA', (5, 6)), ('c.go', 'SEED', (5, 6)),
    ])

    # ---- 任务 2: 无 algorithm 的 finding 不再拿 type 当算法 ----
    r = cryptoscan.to_groups({'findings': [
        {'type': 'Mutual TLS (mTLS)', 'file': r'D:\p\a.py', 'line': 5,
         'purpose': 'tls-configuration', 'severity': 0}]}, r'D:\p')
    check('无 algorithm 的 finding 分组键用 TYPE: 前缀',
          r[0]['alg_norm'], 'TYPE:MUTUALTLSMTLS')
    f = merge(r)[0]
    check('algorithm_normalized 如实留空（不打假算法）',
          f['algorithm_normalized'], '')
    check('algorithm 同样留空', f['algorithm'], '')
    check('打 no-algorithm 标记', 'no-algorithm' in f.get('tags', []), True)
    check('risk 兜底照常工作: 表外 type 落 review（不猜，扩表归 C）',
          f['risk'], 'review')
    f_hk = merge(cryptoscan.to_groups({'findings': [
        {'type': 'Hardcoded Key Size', 'file': r'D:\p\a.py', 'line': 9,
         'severity': 1}]}, r'D:\p'))[0]
    check('risk 兜底照常工作: 表内 type 按 RISK_BY_TYPE 裁决',
          f_hk['risk'], 'grover')

    # TLS 版本或协议名称只证明配置存在，不证明协商了 ECDHE/RSA 等公钥算法。
    # 这条真实公开样例曾被直接判成 shor，进而让 AI 把未确认的前提写成事实。
    tls = merge(cryptoscan.to_groups({'findings': [
        {'algorithm': 'TLS', 'type': 'TLS Configuration',
         'file': r'D:\p\tls.java', 'line': 8,
         'purpose': 'tls-configuration', 'severity': 0},
    ]}, r'D:\p'))[0]
    check('只有 TLS 配置线索时风险为 review', tls['risk'], 'review')
    from core.quantum_assessment import assess_one
    assessed = assess_one(tls)
    check('没有握手算法证据时不声称 Shor 已确认',
          (assessed['quantum_assessment']['status'],
           assessed['quantum_assessment']['migration_candidates']),
          ('insufficient_evidence', []))

    # ---- 任务 2: finding_id 不撞（同文件同用途、不同 type）----
    r2 = merge(cryptoscan.to_groups({'findings': [
        {'type': 'Hardcoded Key Size', 'file': r'D:\p\a.py', 'line': 1},
        {'type': 'Mutual TLS (mTLS)', 'file': r'D:\p\a.py', 'line': 2},
    ]}, r'D:\p'))
    check('同文件不同 type 是两条独立 finding', len(r2), 2)
    check('两条的 finding_id 不撞（分桶键入指纹）',
          r2[0]['finding_id'] != r2[1]['finding_id'], True)

    # ---- 任务 2: 有 algorithm 的 finding 走原路径不受影响 ----
    r3 = cryptoscan.to_groups({'findings': [
        {'algorithm': 'RSA', 'type': 'RSA Algorithm', 'file': r'D:\p\b.py',
         'line': 3, 'purpose': 'signing', 'severity': 3}]}, r'D:\p')
    check('有 algorithm 的 finding 照常归一', r3[0]['alg_norm'], 'RSA')


def test_cryptoscan_usage_fuse(check):
    """非公钥的启发式摆动消噪；公钥迁移用途必须分开。

    llmcmt 实测 124 条 FP 全来自 cryptoscan 逐行 purpose 把同一处使用拆成
    authentication/encryption 两桶 —— 计数单位 (file, algorithm) 之下它
    只能是一条。合到行数最多的具体用途桶, 行号全并。
    """
    data = {'findings': [
        # 同文件同算法 3 行: 2 行 encryption、1 行 authentication -> 一组
        {'algorithm': 'PBKDF2', 'file': r'D:\p\a.py', 'line': 4,
         'purpose': 'encryption', 'severity': 1, 'confidence': 'LOW'},
        {'algorithm': 'PBKDF2', 'file': r'D:\p\a.py', 'line': 14,
         'purpose': 'encryption', 'severity': 1, 'confidence': 'LOW'},
        {'algorithm': 'PBKDF2', 'file': r'D:\p\a.py', 'line': 27,
         'purpose': 'authentication', 'severity': 2, 'confidence': 'MEDIUM'},
        # 同文件另一算法不受影响
        {'algorithm': 'AES-GCM', 'file': r'D:\p\a.py', 'line': 30,
         'purpose': 'encryption', 'severity': 0},
    ]}
    groups = cryptoscan.to_groups(data, r'D:\p')
    check('同 (file,alg) 合流成一组（usage=行数最多的 encryption）',
          [(g['algorithm'], g['usage']) for g in groups],
          [('PBKDF2', 'encryption'), ('AES-GCM', 'encryption')])
    main = groups[0]
    check('行号全并 + 顺序稳定', main['lines'], [4, 14, 27])
    check('severity 取最严重（跨桶照比）', main['severity'], 'medium')
    check('confidence 取最大（跨桶照比, MEDIUM=0.6）', main['confidence'], 0.6)
    check('被并桶的记录不丢（raw.records 3 条）',
          len(main['raw']['records']), 3)
    # 全 unknown 的多桶不猜（由 merge 的行号吸收按精确行号细分）
    data2 = {'findings': [
        {'algorithm': 'RSA', 'file': r'D:\p\b.py', 'line': 1, 'purpose': None},
        {'algorithm': 'RSA', 'file': r'D:\p\b.py', 'line': 2},
    ]}
    g2 = cryptoscan.to_groups(data2, r'D:\p')
    check('全 unknown 时保持单桶 unknown（不猜用途）',
          [(g['usage'], g['lines']) for g in g2], [('unknown', [1, 2])])

    ecc = cryptoscan.to_groups({'findings': [
        {'algorithm': 'ECC', 'file': r'D:\p\hybrid.js', 'line': 13,
         'purpose': 'key-exchange'},
        {'algorithm': 'ECC', 'file': r'D:\p\hybrid.js', 'line': 104,
         'purpose': 'signing'},
    ]}, r'D:\p')
    check('ECC 签名与密钥交换行不合桶（迁移路线不同）',
          sorted((g['usage'], g['lines']) for g in ecc),
          [('key_exchange', [13]), ('signing', [104])])


def test_family_asset_evidence_isolation(check):
    """家族 asset 不能把曲线名冒充签名或把 3DES 冒充 DES。"""
    groups = cbom_scan.to_groups({'assets': [
        {'algo': 'ECDSA / EC', 'prim': 'signature', 'risk': 'shor',
         'occurrences': [
             {'file': 'hybrid.js', 'line': 13, 'match': 'prime256v1'},
             {'file': 'hybrid.js', 'line': 104, 'match': 'ECDSA'}]},
        {'algo': 'DES / 3DES', 'prim': 'block-cipher', 'risk': 'broken',
         'occurrences': [
             {'file': 'crypto.go', 'line': 151, 'match': 'DES'},
             {'file': 'crypto.go', 'line': 159, 'match': 'Triple-DES'},
             {'file': 'crypto.go', 'line': 162, 'match': 'TripleDES'}]},
    ]}, 'unused-target')
    check('曲线名只证明 ECC，ECDSA 命中才证明签名',
          sorted((g['usage'], g['lines']) for g in groups if g['file']=='hybrid.js'),
          [('signing', [104]), ('unknown', [13])])
    check('DES / 3DES 的匹配行各归各的算法',
          sorted((g['alg_norm'], g['lines']) for g in groups if g['file']=='crypto.go'),
          [('3DES', [159, 162]), ('DES', [151])])
    cs = cryptoscan.to_groups({'findings': [
        {'algorithm': 'ECC', 'file': r'D:\p\hybrid.js', 'line': 13,
         'purpose': 'key-exchange'},
        {'algorithm': 'ECC', 'file': r'D:\p\hybrid.js', 'line': 104,
         'purpose': 'signing'},
    ]}, r'D:\p')
    merged = merge(groups + cs)
    check('cbom unknown 同行吸收进 ECDH，签名证据不串入交换结论',
          sorted((f['usage'], f['evidence'][0]['lines']) for f in merged
                 if f['file']=='hybrid.js'),
          [('key_exchange', [13]), ('signing', [104])])
    check('交换用途不展示误导性的 ECDSA 家族名',
          [f['algorithm'] for f in merged if f['file']=='hybrid.js'
           and f['usage']=='key_exchange'], ['ECC'])


def test_local_literal(check):
    """本地字面量源：双条件判定、只补盲区、词表外不猜。"""
    import tempfile
    with tempfile.TemporaryDirectory() as root:
        def put(name, text):
            with open(os.path.join(root, name), 'w', encoding='utf-8') as fh:
                fh.write(text)
            return name

        # 1) 汇点 + 字面量（经变量间接传入的真实形态）
        put('a.java', 'class A {\n'
                      '  static final String D = "IDEA";\n'          # 行 2
                      '  void go(char[] c) throws Exception {\n'
                      '    Cipher.getInstance(String.valueOf(c));\n'  # 行 4
                      '  } }\n')
        # 2) 只有字面量、没有汇点（测试资源/文档 —— 不许触发）
        put('b.java', 'class B { static final String D = "RC2"; }\n')
        # 3) 转换串首段命中（调用点字面量、算法表缺词的形态）
        put('c.java', 'class C { void go() throws Exception {\n'
                      '  Cipher.getInstance("DES/CBC/PKCS5Padding");\n'  # 行 2
                      '} }\n')
        # 4) 健全算法不在词表（AES 不是已淘汰经典算法）
        put('d.java', 'class D { static final String D = "AES";\n'
                      '  void go() throws Exception { Cipher.getInstance(D); } }\n')
        # 5) 注释里出现算法名（无引号 —— 不算写死的算法选择）
        put('e.java', 'class E { // IDEA is broken\n'
                      '  void go() throws Exception { Cipher.getInstance(x); } }\n')
        # 6) 同文件多字面量去重成一个组
        put('f.java', 'class F {\n'
                      '  static final String D1 = "MD4";\n'          # 行 2
                      '  static final String D2 = "MD4";\n'          # 行 3
                      '  void go(char[] c) throws Exception {\n'
                      '    MessageDigest.getInstance(String.valueOf(c));\n'  # 行 5
                      '  } }\n')
        # 7) R2+R3 跨文件一跳: caller 常量实参 -> callee 的 JCE 汇点
        put('caller1.java', 'class Caller1 {\n'
                            '  void go() {\n'
                            '    Callee1 c = new Callee1();\n'
                            '    String a = "RC2";\n'
                            '    c.go(a); }\n'                       # 行 5
                            '}\n')
        put('callee1.java', 'class Callee1 {\n'
                            '  void go(String crypto) throws Exception {\n'
                            '    Cipher.getInstance(crypto); }\n'    # 行 3
                            '}\n')
        # 8) R4 两层嵌套括号（Integer.parseInt(String.valueOf(count))）
        put('pbe1.java', 'class Pbe1 {\n'
                         '  void go() throws Exception {\n'
                         '    int count = 20;\n'
                         '    byte[] salt = new byte[8];\n'
                         '    new PBEParameterSpec(salt, '
                         'Integer.parseInt(String.valueOf(count)));\n'  # 行 5
                         '  } }\n')
        # 9) R4 高迭代（>= 1000）不报 + 解析不到常量不报（不猜）
        put('pbe2.java', 'class Pbe2 {\n'
                         '  void go() throws Exception {\n'
                         '    int count = 100000;\n'
                         '    byte[] salt = new byte[8];\n'
                         '    new PBEParameterSpec(salt, count);\n'
                         '  } }\n')
        put('neg2.java', 'class Neg2 {\n'
                         '  void go(int count) throws Exception {\n'  # 形参, 无来源
                         '    byte[] salt = new byte[8];\n'
                         '    new PBEParameterSpec(salt, count);\n'
                         '  } }\n')
        # 10) R4x 跨文件反向: PBE 汇点在 callee, 迭代常量来自 caller
        put('pcaller.java', 'class Pcaller {\n'
                            '  void go() {\n'
                            '    Pcallee p = new Pcallee();\n'
                            '    int count = 20;\n'
                            '    p.go(count); }\n'                   # 行 5
                            '}\n')
        put('pcallee.java', 'class Pcallee {\n'
                            '  void go(int count) throws Exception {\n'
                            '    byte[] salt = new byte[8];\n'
                            '    new PBEParameterSpec(salt, count); }\n'  # 行 4
                            '}\n')
        # 11) R5 转换串 ECB 模式（首段 AES 不在词表, 不触发 R1/R3）
        put('ecb.java', 'class Ecb {\n'
                        '  void go() throws Exception {\n'
                        '    String t = "AES/ECB/PKCS5Padding";\n'
                        '    Cipher.getInstance(t); }\n'             # 行 4
                        '}\n')
        # 12) map put/get 同 key 传播（R1 兜底也覆盖, 此处防传播链崩坏）
        put('hm.java', 'class Hm {\n'
                       '  void go() throws Exception {\n'
                       '    HashMap h = new HashMap();\n'
                       '    h.put("aaa", "MD2");\n'
                       '    String c = h.get("aaa");\n'
                       '    MessageDigest.getInstance(c); }\n'
                       '}\n')
        # 13) R4 must 口径: 恒假分支的升值是死代码（llmcmt af10401 形态）
        put('dead1.java', 'class Dead1 {\n'
                          '  void go() {\n'
                          '    int choice = 0;\n'
                          '    int count = 5;\n'
                          '    if (choice > 1)\n'
                          '      count = 1050;\n'          # 恒假 -> 死代码
                          '    PBEParameterSpec s = new PBEParameterSpec(new byte[8], count); }\n'
                          '}\n')
        # 14) R4 must 口径: 可达分支存在合规路径 -> 不报（a1e0131 corrected 形态）
        put('dead2.java', 'class Dead2 {\n'
                          '  void go(boolean fix) {\n'
                          '    int count = 5;\n'
                          '    if (fix)\n'
                          '      count = 1050;\n'          # 参数条件可达
                          '    PBEParameterSpec s = new PBEParameterSpec(new byte[8], count); }\n'
                          '}\n')
        # 15) R4 阈值含边界: 恰 1000 也报（llmcmt af10416 形态, PBEKeySpec 第 3 参）
        put('pbe3.java', 'class Pbe3 {\n'
                         '  void go() {\n'
                         '    int iterations = 1000;\n'
                         '    PBEKeySpec spec = new PBEKeySpec(new char[8], new byte[8], iterations, 128); }\n'
                         '}\n')
        # 16) 多语言: py ECB / C 词表+ECB / Go 词表
        put('ecb.py', 'from Crypto.Cipher import AES\n'
                      'AES_128 = AES.new(K, AES.MODE_ECB)\n')
        put('des3.py', 'from Crypto.Cipher import DES3\n'
                       'cipher = DES3.new(key, DES3.MODE_CBC)\n')
        put('md4.c', '#include <openssl/md4.h>\n'
                     'void go() { MD4((const unsigned char*)t, len, out); }\n')
        put('ecb.c', '#include <openssl/evp.h>\n'
                     'void go() { EVP_aes_128_ecb(); }\n')
        put('bf.cpp', 'void go() { BF_ecb_encrypt(p, c, &k, 1); }\n')
        put('cast.go', 'import "golang.org/x/crypto/cast5"\n'
                       'func go2() { block, _ := cast5.NewCipher(key) }\n')
        put('xtea.go', 'import "golang.org/x/crypto/xtea"\n'
                       'func go3() { block, _ := xtea.NewCipher(key) }\n')
        put('gmd5.go', 'func go4() { s := gmd5.MustEncryptString(pw) }\n')
        # 17) R10 ucryptolib (MicroPython): mode = MODE_ECB 变量形态
        put('ucrypto.py', 'from ucryptolib import aes, MODE_ECB, MODE_CBC\n'
                          'def enc(key, data, mode):\n'
                          '    cipher = aes(key, mode)\n'
                          '    return cipher.encrypt(data)\n'
                          'def go(key, data):\n'
                          '    mode = MODE_ECB\n'
                          '    return enc(key, data, mode)\n')
        # 18) R12 C 宏迭代数: #define ITERATIONS 1000 (含边界)
        put('pbemac.c', '#include <openssl/evp.h>\n'
                        '#define ITERATIONS 1000\n'
                        'void go() { PKCS5_PBKDF2_HMAC(pw, l, salt, s, ITERATIONS, EVP_sha256(), klen, out); }\n')
        # 19) JCE PBE 组合名拆词: PBEWithMD5AndDES -> MD5 + DES
        put('pbec.java', 'class Pbec {\n'
                         '  void go() throws Exception {\n'
                         '    Cipher c = Cipher.getInstance("PBEWithMD5AndDES");\n'  # 行 3
                         '  } }\n')
        # 20) R2 放宽: 接收者是显式 new 构造、类文件不在树内 -> caller 仍报
        put('caller2.java', 'class Caller2 {\n'
                            '  void go() {\n'
                            '    X9999 bc = new X9999();\n'
                            '    String a = "IDEA";\n'
                            '    bc.go(a); }\n'                    # 行 5
                            '}\n')
        put('fixed.java', 'class Fixed {\n'
                          '  private final static String DES = "DES";\n'
                          '  void go() throws Exception { Cipher.getInstance(DES); }\n'
                          '}\n')
        put('commented.java', 'class Commented {\n'
                              '  /* static final String D = "DES"; */\n'
                              '  void go() throws Exception {\n'
                              '    String D = "DES"; Cipher.getInstance(D);\n'
                              '  } }\n')

        groups = {(g['file'], g['alg_norm']): g
                  for g in local_literal.scan(root)}
        check('汇点+字面量 -> IDEA 组', ('a.java', 'IDEA') in groups, True)
        g = groups[('a.java', 'IDEA')]
        check('行号 = 字面量行 + 汇点行', g['lines'], [2, 4])
        check('risk 统一 broken（词表内全是已淘汰经典算法）', g['risk'], 'broken')
        check('usage 如实 unknown（不猜用途）', g['usage'], 'unknown')
        check('不可变字段的调用点有独立 R3-final 行号',
              groups[('fixed.java', 'DES')]['raw']['rule_lines'].get('R3-final'),
              [3])
        check('跨文件形参推断不能冒充不可变字段调用点',
              groups[('callee1.java', 'RC2')]['raw']['rule_lines'].get('R3-final', []),
              [])
        check('注释中的 final 声明不能使可变局部变量成为确定字段',
              groups[('commented.java', 'DES')]['raw']['rule_lines'].get('R3-final', []),
              [])
        check('无汇点不触发（b.java 不产出）',
              [k for k in groups if k[0] == 'b.java'], [])
        check('转换串首段命中 -> DES 组', ('c.java', 'DES') in groups, True)
        check('词表外健全算法不触发（d.java 不产出）',
              [k for k in groups if k[0] == 'd.java'], [])
        check('无引号注释不触发（e.java 不产出）',
              [k for k in groups if k[0] == 'e.java'], [])
        if ('f.java', 'MD4') in groups:
            check('同文件多字面量去重成一个组', groups[('f.java', 'MD4')]['lines'],
                  [2, 3, 5])
        else:
            check('同文件多字面量去重成一个组', ('f.java', 'MD4') in groups, True)

        # ---- R2/R3: 跨文件一跳（caller 常量实参 -> callee 形参 -> JCE 汇点）----
        check('R2: 词表字面量传给树内类 -> caller 侧 RC2',
              ('caller1.java', 'RC2') in groups, True)
        check('R2 行号 = 调用行', groups[('caller1.java', 'RC2')]['lines'], [5])
        check('R3: callee 形参解析到跨文件常量 -> callee 侧 RC2',
              ('callee1.java', 'RC2') in groups, True)
        check('R3 行号 = 汇点行', groups[('callee1.java', 'RC2')]['lines'], [3])

        # ---- R4: PBE 低迭代（两层嵌套括号 + 风险档 + 防误报）----
        check('R4: 两层嵌套括号的低迭代 -> PBKDF2',
              ('pbe1.java', 'PBKDF2') in groups, True)
        check('R4 risk=review（健全 KDF 的实现误用, 不是 broken）',
              groups[('pbe1.java', 'PBKDF2')]['risk'], 'review')
        check('R4 规则留痕', groups[('pbe1.java', 'PBKDF2')]['raw']['rules'], ['R4'])
        check('R4 高迭代（100000）不报',
              [k for k in groups if k[0] == 'pbe2.java'], [])
        check('R4 解析不到常量就不报（不猜）',
              [k for k in groups if k[0] == 'neg2.java'], [])

        # ---- R4x: 迭代常量来自 caller -> caller 文件反向同报 ----
        check('R4x: callee 命中 + caller 反向各一条 PBKDF2',
              ('pcallee.java', 'PBKDF2') in groups and
              ('pcaller.java', 'PBKDF2') in groups, True)
        check('R4x caller 行号 = 真实调用行（不是 None/0）',
              groups[('pcaller.java', 'PBKDF2')]['lines'], [5])

        # ---- R5: 转换串 ECB 模式 ----
        ecb_key = ('ecb.java', canon_algorithm('AES/ECB'))
        check('R5: 转换串模式段 ECB -> AES/ECB 条目', ecb_key in groups, True)
        check('R5 risk=review（模式误用待复核）',
              groups[ecb_key]['risk'], 'review')

        # ---- map put/get 同 key 传播 ----
        check('HashMap put/get 同 key 传播 -> MD2', ('hm.java', 'MD2') in groups, True)

        # ---- R4 must 口径（恒假剔除 + 可达值上界 <= 1000）----
        check('R4 恒假分支的 1050 是死代码 -> 上界 5, 照报',
              ('dead1.java', 'PBKDF2') in groups, True)
        check('R4 可达分支存在 1050 的合规路径 -> 不报（corrected 形态）',
              [k for k in groups if k[0] == 'dead2.java'], [])
        check('R4 阈值含边界: PBEKeySpec 恰 1000 也报',
              ('pbe3.java', 'PBKDF2') in groups, True)

        # ---- 多语言扫描（R6 py / R7 C/Go / 词表映射）----
        check('R6 py: AES.new(K, AES.MODE_ECB) -> AES/ECB（review）',
              groups.get(('ecb.py', canon_algorithm('AES/ECB')), {}).get('risk'),
              'review')
        check('R6 py: DES3.new(key, MODE_CBC) -> 3DES（broken）',
              ('des3.py', canon_algorithm('3DES')) in groups, True)
        check('R7 C: MD4(...) 裸哈希调用',
              ('md4.c', 'MD4') in groups, True)
        check('R7 C: EVP_aes_128_ecb -> AES/ECB',
              ('ecb.c', canon_algorithm('AES/ECB')) in groups, True)
        check('R7 cpp: BF_ecb_encrypt -> Blowfish（词表算法报纯名, 不带 /ECB）',
              ('bf.cpp', canon_algorithm('Blowfish')) in groups, True)
        check('R8 Go: cast5.NewCipher -> CAST（标签口径短名）',
              ('cast.go', canon_algorithm('CAST')) in groups, True)
        check('R8 Go: xtea.NewCipher -> XTEA',
              ('xtea.go', canon_algorithm('XTEA')) in groups, True)
        check('R8 Go: gmd5.MustEncryptString -> MD5（Encrypt\\w* 覆盖后缀变体）',
              ('gmd5.go', 'MD5') in groups, True)
        check('R10: ucryptolib 变量 mode=MODE_ECB -> AES/ECB',
              ('ucrypto.py', canon_algorithm('AES/ECB')) in groups, True)
        check('R12: C 宏 #define ITERATIONS 1000 -> PBKDF2（含边界）',
              ('pbemac.c', 'PBKDF2') in groups, True)
        check('R1 拆词: PBEWithMD5AndDES -> MD5 与 DES 两条',
              (('pbec.java', 'MD5') in groups and
               ('pbec.java', canon_algorithm('DES')) in groups), True)
        check('R2 放宽: new 构造的接收者类不在树内 -> caller 侧照报',
              ('caller2.java', 'IDEA') in groups, True)

        # ---- 让位规则：外部工具已覆盖的 (file, alg)，本源不添 unknown 条 ----
        g_lit = _group('local-literal', 'a.java', 'BLOWFISH', 'unknown', [1],
                       risk='broken', algorithm='Blowfish')
        g_cbom = _group('cbom-scan', 'a.java', 'BLOWFISH', 'encryption', [2],
                        risk='broken', algorithm='Blowfish')
        f = merge([g_lit, g_cbom])
        check('工具已覆盖的 (file,alg) 本源让位（不拆成两条）',
              [(x['usage'], x['evidence'][0]['tool']) for x in f],
              [('encryption', 'cbom-scan')])
        # R1 的同文件所有汇点并无参数归属，绝不能用于补上游证据；
        # R3-final 的不可变字段实参才能把调用行补进同一个 Finding。
        g_lit_call = _group('local-literal', 'a.java', 'BLOWFISH',
                            'unknown', [1, 10, 20], risk='broken',
                            algorithm='Blowfish')
        g_lit_call['raw'] = {
            'kind': 'local-literal', 'algorithm': 'Blowfish',
            'rules': ['R1', 'R3-final'],
            'rule_lines': {'R1': [1, 10, 20], 'R3-final': [20]},
        }
        f_call = merge([g_lit_call, g_cbom])
        check('同文件已有算法时只补不可变字段的调用行，不添重复 Finding',
              [(x['usage'], [(e['tool'], e['lines']) for e in x['evidence']])
               for x in f_call],
              [('encryption', [('cbom-scan', [2]),
                               ('local-literal', [20])])])
        check('补充证据不冒认 R1 和上游工具来源',
              f_call[0]['evidence'][1]['raw']['rules'], ['R3-final'])
        other_usage = _group('cryptoscan', 'a.java', 'BLOWFISH',
                             'signing', [30], risk='broken',
                             algorithm='Blowfish')
        f_ambiguous = merge([g_lit_call, g_cbom, other_usage])
        check('同算法有多用途时 R3 不猜归属、不另造 unknown Finding',
              [(x['usage'], [e['tool'] for e in x['evidence']])
               for x in f_ambiguous],
              [('encryption', ['cbom-scan']),
               ('signing', ['cryptoscan'])])
        f2 = merge([g_lit])
        check('盲区里本源独立成条（unknown + needs-usage-review）',
              (len(f2), f2[0]['usage'], f2[0]['risk'],
               'needs-usage-review' in f2[0].get('tags', [])),
              (1, 'unknown', 'broken', True))


def test_source_filter(check):
    """命中来源过滤：import 声明不是算法使用，真实调用点才是。"""
    f = source_filter.is_string_or_comment_mention
    # Python `from X import Y` 声明是模块路径/符号，不是算法使用
    check('from ...rsa import RSAPublicKey 是 import 声明（过滤）',
          f('from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey',
            'rsa'), True)
    check('from Crypto.PublicKey import RSA 是 import 声明（过滤）',
          f('from Crypto.PublicKey import RSA', 'RSA'), True)
    check('from rsa import pkcs1 是 import 声明（过滤）',
          f('from rsa import pkcs1', 'rsa'), True)
    # 真实使用点（后续行的 rsa.encrypt）不受 import 过滤影响
    check('rsa.encrypt(...) 是代码符号使用（保留）',
          f('rsa.encrypt(data, key)', 'rsa'), False)
    # C 预处理器 include 仍是真实引入（不走 from-import 过滤）
    check('#include <openssl/blowfish.h> 是真实引入（保留）',
          f('#include <openssl/blowfish.h>', 'blowfish'), False)
    # Java 的 import 声明（无 from）走原逻辑，代码符号保留
    check('Java import java.security.MessageDigest 保留',
          f('import java.security.MessageDigest;', 'MessageDigest'), False)
    # 字符串经常就是密码 API / 配置的真实参数，不能为了降 FP 一刀切掉。
    check('createCipheriv 的变换参数保留',
          f("const c = crypto.createCipheriv('chacha20-poly1305', key, iv);",
            'chacha20-poly1305'), False)
    check('ECGenParameterSpec 的曲线参数保留',
          f('keyGen.initialize(new ECGenParameterSpec("secp256r1"));',
            'secp256r1'), False)
    check('TLS 配置值保留', f("minVersion: 'TLSv1.3',", 'TLSv1.3'), False)
    check('错误提示中的算法名过滤',
          f('throw new IllegalArgumentException("valid RSA key required");',
            'RSA'), True)
    check('Go import 路径过滤',
          f('"golang.org/x/crypto/bcrypt"', 'bcrypt'), True)


def test_split_output(check):
    """输出分层：safe 不是问题、no-algorithm 是线索 —— 都不进问题清单。"""
    from scanner.scan import split_output
    a = {'risk': 'safe', 'tags': []}
    b = {'risk': 'review', 'tags': ['no-algorithm']}
    c = {'risk': 'broken', 'tags': []}
    d = {'risk': 'broken', 'tags': ['needs-usage-review', 'no-algorithm']}
    findings, leads = split_output([a, b, c, d])
    check('safe 条目不进问题清单（CBOM 资产图侧仍保留）', findings, [c])
    check('no-algorithm 线索进 leads 层（无论风险档）', leads, [b, d])


def test_coverage(check):
    a = [_group('cbom-scan', 'a.go', 'RSA', 'unknown', [1, 2])]
    b = [_group('cryptoscan', 'a.go', 'RSA', 'signing', [2, 3])]
    rep = coverage_diff({'cbom-scan': a, 'cryptoscan': b})
    s = rep['summary']
    check('行级差异: both=1', s['both'], 1)
    check('行级差异: cbom-scan_only=1', s['cbom-scan_only'], 1)
    check('行级差异: cryptoscan_only=1', s['cryptoscan_only'], 1)


def test_cbom_report(check):
    f = merge([_group('cbom-scan', 'a.go', 'RSA', 'signing', [7], risk='shor')])
    bom1 = render_cbom(f, 'demo')
    bom2 = render_cbom(f, 'demo')
    check('CycloneDX 基本字段',
          (bom1['bomFormat'], bom1['specVersion']), ('CycloneDX', '1.6'))
    check('components 按算法去重', len(bom1['components']), 1)
    check('occurrences 带行号定位',
          bom1['components'][0]['evidence']['occurrences'],
          [{'location': 'a.go:7'}])
    check('serialNumber 确定性可复现', bom1['serialNumber'], bom2['serialNumber'])


def test_java_properties(check):
    """JCE 实际算法来自资源文件时，应定位到 Java 汇点，不发配置原文。"""
    with tempfile.TemporaryDirectory(prefix='acg-properties-') as root:
        folder = Path(root)
        (folder / 'choice.properties').write_text(
            'hashAlgorithm=MD5\nsafeAlgorithm=AES/GCM/NoPadding\n',
            encoding='ascii')
        (folder / 'Resolved.java').write_text(
            'Properties p = new Properties();\n'
            'p.load(getResourceAsStream("choice.properties"));\n'
            'String algorithm = p.getProperty("hashAlgorithm", "SHA512");\n'
            'MessageDigest.getInstance(algorithm);\n', encoding='utf-8')
        (folder / 'Safe.java').write_text(
            'Properties p = new Properties();\n'
            'p.load(getResourceAsStream("choice.properties"));\n'
            'String algorithm = p.getProperty("safeAlgorithm", "AES/ECB/PKCS5Padding");\n'
            'Cipher.getInstance(algorithm);\n', encoding='utf-8')
        (folder / 'Reassigned.java').write_text(
            'Properties p = new Properties();\n'
            'p.load(getResourceAsStream("choice.properties"));\n'
            'String algorithm = p.getProperty("hashAlgorithm", "SHA512");\n'
            'algorithm = "SHA256";\n'
            'MessageDigest.getInstance(algorithm);\n', encoding='utf-8')
        (folder / 'Commented.java').write_text(
            '/* Properties p = new Properties();\n'
            'p.load(getResourceAsStream("choice.properties"));\n'
            'String algorithm = p.getProperty("hashAlgorithm", "SHA512");\n'
            'MessageDigest.getInstance(algorithm); */\n', encoding='utf-8')
        (folder / 'LateLoad.java').write_text(
            'String algorithm = p.getProperty("hashAlgorithm", "SHA512");\n'
            'MessageDigest.getInstance(algorithm);\n'
            'p.load(getResourceAsStream("choice.properties"));\n', encoding='utf-8')
        groups = java_properties.scan(root)
        check('配置 MD5 被关联到调用 Java 文件与汇点行',
              [(g['file'], g['algorithm'], g['lines']) for g in groups],
              [('Resolved.java', 'MD5', [4])])
        check('配置证据只给算法与引用，不泄露配置全文',
              set(groups[0]['raw']),
              {'kind', 'resource_file', 'property_key', 'resource_line',
               'resolved_algorithm'})
        check('配置来源可以定位到资源文件行号',
              groups[0]['raw']['resource_line'], 1)


def test_credential_identity(check):
    """同一位置两份不同凭据保留为两条时，引用 ID 也必须不同。"""
    args = ('example.py', 7, 2, 'CRED-HARDCODED-PASSWORD')
    a = credential_scan._finding(*args, 'synthetic-alpha', b'test-pepper', 'pattern')
    b = credential_scan._finding(*args, 'synthetic-beta', b'test-pepper', 'pattern')
    # _finding builds a location-only provisional ID. The public scan path
    # passes its candidates through _dedup, which assigns stable ordinals for
    # distinct values at the same coordinate without hashing weak passwords
    # into an offline-guessable persistent ID.
    final = credential_scan._dedup([a, b])
    check('同位置不同凭据在最终输出中不复用 ID',
          len(final) == 2 and final[0]['finding_id'] != final[1]['finding_id'],
          True)
    check('凭据证据只存 HMAC 指纹，不含测试字面量',
          'synthetic-alpha' not in repr(a), True)


def test_conditional_default(check):
    from scanner.scan import annotate_conditional_defaults
    cond = [{'file': 'A.java', 'alg_norm': 'AESECB', 'lines': [10, 11],
             'resource_file': 'choice.properties', 'resource_line': 2,
             'property_key': 'cipher'}]
    only_fallback = merge([_group('cryptoscan', 'A.java', 'AESECB',
                                  'encryption', [10], risk='review',
                                  algorithm='AES-ECB')])
    check('只有覆盖默认值的证据时标作条件性风险',
          annotate_conditional_defaults(only_fallback, cond), 1)
    check('条件性风险仍保留在问题清单和独立证据中',
          ('conditional-default' in only_fallback[0]['tags'],
           len(only_fallback[0]['evidence'])), (True, 2))
    check('备用值不给确定整改结论',
          (only_fallback[0]['remediation']['decided'],
           only_fallback[0]['remediation']['reason']),
          (False, 'conditional-default'))
    independent = merge([_group('cryptoscan', 'A.java', 'AESECB',
                                'encryption', [10, 50], risk='review',
                                algorithm='AES-ECB')])
    check('同文件还有独立命中时不能把整条降为条件性',
          annotate_conditional_defaults(independent, cond), 0)


def test_python_ast_weak_random(check):
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, 'sample.py')
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write('import random as r\n'
                     'nonce = r.Random().randbytes(12)\n'
                     'simulation = r.Random().randbytes(12)\n'
                     'safe_iv = r.SystemRandom().randbytes(12)\n'
                     'from random import Random as R\n'
                     'session_key = R().randbytes(32)\n')
        rows = python_ast.scan(td)
        check('AST 只把安全用途的弱随机字节报告为问题', len(rows), 1)
        check('AST 排除模拟用途和 SystemRandom',
              rows[0]['evidence'][0]['lines'], [2, 6])
        check('AST 来源和风险类别真实标注',
              (rows[0]['evidence'][0]['tool'], rows[0]['evidence'][0]['kind'],
               rows[0]['risk']), ('python-ast', 'ast', 'not_applicable'))
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write('import random\nnonce = random.SystemRandom().randbytes(12)\n')
        check('修复后 AST 结果消失', python_ast.scan(td), [])
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write('import random as r\nr = fake_provider()\n'
                     'nonce = r.Random().randbytes(12)\n')
        check('导入别名被重新绑定时不猜标准库身份', python_ast.scan(td), [])
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write('import random\n'
                     'nonce = random.Random().randbytes(16) if hasattr(random.Random, "randbytes") '
                     'else bytes(random.randint(0, 255) for _ in range(16))\n'
                     'simulation = random.Random().randbytes(16) if enabled else b""\n')
        rows = python_ast.scan(td)
        check('条件表达式的弱随机 nonce 仍被检测', len(rows), 1)
        check('条件表达式来源行号，不误报模拟数据',
              rows[0]['evidence'][0]['lines'], [2])


def test_python_ast_hashlib_new(check):
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, 'hash_case.py')
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write('def weak():\n'
                     '    import hashlib as h\n'
                     '    return h.new("md5")\n'
                     'def weak_two():\n'
                     '    from hashlib import new as create\n'
                     '    return create("sha1")\n'
                     'def safe():\n'
                     '    import hashlib\n'
                     '    return hashlib.new("sha384")\n'
                     'def rebound():\n'
                     '    import hashlib as h\n'
                     '    h = fake_provider()\n'
                     '    return h.new("md5")\n'
                     'def dynamic(name):\n'
                     '    import hashlib\n'
                     '    return hashlib.new(name)\n')
        rows = python_ast.scan(td)
        check('AST 抓标准库 hashlib.new 的 MD5/SHA-1 常量，排除安全/重绑定/动态调用',
              [(r['algorithm_normalized'], r['line']) for r in rows],
              [('MD5', 3), ('SHA1', 6)])
        check('弱哈希 AST 输出不含源码原文并遵守稳定 Finding ID',
              all(r['evidence'][0]['kind'] == 'ast' and
                  'sourceStmt' not in r['evidence'][0]['raw'] and
                  r['finding_id'] == hashlib.sha1(
                      (r['file'] + '|' + r['algorithm_normalized'] + '|hashing')
                      .encode('utf-8')).hexdigest()[:12] for r in rows), True)
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write('def modern():\n'
                     '    import hashlib\n'
                     '    # hashlib.new("sha1") is only a comment\n'
                     '    note = "hashlib.new(\\\"sha1\\\")"\n'
                     '    digest = hashlib.new("md5")\n'
                     '    print(f"value {digest.hexdigest()}")\n'
                     "    print(f'bad {data['x']}')\n")
        diagnostics = {}
        recovered = python_ast.scan(td, diagnostics=diagnostics)
        check('新语法解析失败时仅恢复有导入证据的真实调用',
              [(r['algorithm_normalized'], r['line']) for r in recovered],
              [('MD5', 5)])
        check('词法回退显式标记 partial，绝不冒充完整 AST',
              (recovered[0]['evidence'][0]['raw']['parse_scope'],
               'partial-parse' in recovered[0]['tags']),
              ('token_fallback', True))
        check('解析覆盖率如实记录，不能把部分解析当成全部解析',
              (diagnostics['full_ast_files'], diagnostics['partial_parse_files'],
               diagnostics['token_recovery_findings']), (0, 1, 1))


def test_cryptoscan_os_binary(check):
    with tempfile.TemporaryDirectory() as td:
        folder = os.path.join(td, 'cryptoscan')
        os.mkdir(folder)
        linux = os.path.join(folder, 'cryptoscan')
        windows = os.path.join(folder, 'cryptoscan.exe')
        Path(linux).touch()
        Path(windows).touch()
        check('Linux 容器选择无扩展名的外部 CryptoScan',
              cryptoscan.find_tool(td, platform_name='posix'), linux)
        check('Windows 本机继续使用 exe',
              cryptoscan.find_tool(td, platform_name='nt'), windows)


def main():
    fails = []
    _checks = [0]

    def check(desc, got, want):
        _checks[0] += 1
        if got != want:
            fails.append('%s\n     期望 %r\n     得到 %r' % (desc, want, got))

    for fn in (test_normalize, test_relative_path, test_merge_absorb_and_fuse,
               test_merge_risk_overrides_and_tags, test_ed25519_match_refinement,
               test_split_combined_and_no_algorithm, test_cryptoscan_usage_fuse,
               test_family_asset_evidence_isolation,
               test_malformed_inputs,
               test_local_literal, test_source_filter, test_split_output,
               test_coverage,
               test_cbom_report, test_java_properties, test_credential_identity,
               test_conditional_default, test_python_ast_weak_random,
               test_python_ast_hashlib_new,
               test_cryptoscan_os_binary):
        fn(check)

    if fails:
        _print_safe('[FAIL] %d 项断言未通过:' % len(fails))
        for f in fails:
            _print_safe('  - %s' % f)
        return 1
    _print_safe('[PASS] 全部断言通过（%d 项）' % _checks[0])
    return 0


if __name__ == '__main__':
    sys.exit(main())
