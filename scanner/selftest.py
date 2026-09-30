"""scanner 自检 —— 对齐 core/rules/pqc_routing.py 的做法：

    python scanner/selftest.py        # 全部断言通过则退出码 0

C 合并分支前跑这一条 + core/schema/validate.py，scanner 侧就算验收了。

断言全部针对**外部行为**（真实密码学约定 / schema 契约 / 实测踩过的坑），
不复述实现逻辑 —— 改内部写法不应导致这里挂掉，挂了就是行为真变了。
覆盖: normalize 的映射与裁决、merge 的融合规则（含行号吸收与输入保护）、
coverage 的差异计数、cbom_report 的结构与确定性。
"""
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from scanner.adapters import cbom_scan, cryptoscan           # noqa: E402
from scanner.cbom_report import render_cbom                  # noqa: E402
from scanner.coverage import coverage_diff                   # noqa: E402
from scanner.merge import merge                              # noqa: E402
from scanner.normalize import (                              # noqa: E402
    canon_algorithm,
    max_severity,
    most_severe_risk,
    norm_algorithm,
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
    check("canon('DES / 3DES') / '3DES' / 'DES' 三写法同归一处",
          {canon_algorithm('DES / 3DES'), canon_algorithm('3DES'),
           canon_algorithm('DES')}, {'DES'})
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


def main():
    fails = []
    _checks = [0]

    def check(desc, got, want):
        _checks[0] += 1
        if got != want:
            fails.append('%s\n     期望 %r\n     得到 %r' % (desc, want, got))

    for fn in (test_normalize, test_relative_path, test_merge_absorb_and_fuse,
               test_merge_risk_overrides_and_tags, test_ed25519_match_refinement,
               test_malformed_inputs, test_coverage, test_cbom_report):
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
