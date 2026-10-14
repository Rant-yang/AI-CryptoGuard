# -*- coding: utf-8 -*-
"""ai/ 层的离线自检 —— 不装 anthropic、不调 API、不花一分钱。

用桩替换 LLM，把 enrich.py 的真实代码路径完整跑一遍。
断言的是**外部事实**（过 schema、不泄露源码、崩了不丢进度），
不是「代码就是这么写的」。

    python ai/selftest.py

退出码: 0 = 全过, 1 = 有断言失败。
"""
import json
import os
import sys
import tempfile
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import ai.enrich as enrich                      # noqa: E402
from ai import redact                           # noqa: E402

SAMPLE_FINDINGS = ROOT / 'core' / 'samples' / 'example_finding.json'
SCHEMA = ROOT / 'core' / 'schema' / 'finding.v0.1.json'

FAILS = []


def _fresh_findings():
    """从入库示例构造 scanner 阶段夹具，不依赖被 gitignore 的 out/。"""
    findings = json.loads(SAMPLE_FINDINGS.read_text(encoding='utf-8'))
    for f in findings:
        f.pop('explanation', None)
        f.pop('evidence_refs', None)
        f['remediation'] = {
            'decided': False,
            'reason': 'not-enriched',
            'action': '尚未增强。',
            'source': 'none',
        }
        # full 模式必须有一条真实代码上下文可供脱敏回归测试。
        target = next((e for e in f['evidence']
                       if e.get('tool') == 'cryptoscan'), f['evidence'][0])
        target['tool'] = 'cryptoscan'
        target['raw'] = {
            'records': [{
                'type': 'Selftest',
                'language': 'java',
                'context': 'Cipher.getInstance("%s")' % f['algorithm'],
                'match': 'Cipher.getInstance',
            }]
        }

    unknown = json.loads(json.dumps(findings[-1]))
    unknown['finding_id'] = 'selftest000001'
    unknown['algorithm'] = 'UnmappedAlgorithm'
    unknown['algorithm_normalized'] = 'UNMAPPEDALGORITHM'
    unknown['usage'] = 'unknown'
    unknown['risk'] = 'review'
    unknown['severity'] = 'low'
    unknown['tags'] = ['needs-usage-review']
    findings.append(unknown)
    return findings


def _write_fixture(path):
    findings = _fresh_findings()
    path.write_text(json.dumps(findings, ensure_ascii=False, indent=2),
                    encoding='utf-8')
    return findings


def check(desc, got, want):
    if got != want:
        FAILS.append('%s\n     期望 %r\n     得到 %r' % (desc, want, got))


def check_true(desc, got):
    check(desc, bool(got), True)


# ------------------------------------------------------------------ 桩 LLM

#: 算法 -> 假用途。**这是伪造的，不是模型真实回答**，只用于驱动代码路径。
FAKE_USAGE = {
    'MD5': 'hashing', 'SHA1': 'hashing', 'SHA256': 'hashing',
    'SHA384512SHA2': 'hashing', 'SHA3SHAKE': 'hashing', 'KMAC': 'hashing',
    'PBKDF2': 'hashing', 'HKDF': 'hashing', 'ARGON2': 'hashing',
    'RSA': 'signing', 'ECDSA': 'signing', 'ED25519X25519': 'signing',
    'MLDSA': 'signing', 'SLHDSA': 'signing', 'LMS': 'signing', 'XMSS': 'signing',
    'AES': 'encryption', 'AES128': 'encryption', 'AES256': 'encryption',
    'AESGCM': 'encryption', 'DES': 'encryption', 'CHACHA20': 'encryption',
    'CHACHA20POLY1305': 'encryption', 'POLY1305': 'authentication',
    'ECDH': 'key_exchange', 'MLKEM': 'key_exchange', 'HYBRIDKEM': 'key_exchange',
    'TLS': 'tls_configuration',
}


class _Block:
    type = 'text'

    def __init__(self, text):
        self.text = text


class _ThinkBlock:
    """思维链块。实测 DeepSeek 会返回它，且它没有 .text。"""
    type = 'thinking'

    def __init__(self):
        self.text = ''


class _Resp:
    def __init__(self, text, stop_reason='end_turn', blocks=None):
        self.content = blocks if blocks is not None else [_Block(text)]
        self.stop_reason = stop_reason


class _Messages:
    def __init__(self, plan):
        self.plan = plan
        self.calls = []

    def create(self, **kwargs):

        prompt = kwargs['messages'][0]['content']
        self.calls.append(prompt)
        n = len(self.calls)

        # 从发给模型的 JSON 中读取算法和证据
        try:
            payload = json.loads(prompt)
        except (TypeError, ValueError):
            payload = {}

        alg = payload.get('algorithm_normalized')
        evidence = payload.get('evidence') or []

        for line in prompt.splitlines():
            if '"algorithm_normalized"' in line:
                alg = line.split('"')[3]
                break
        mode = self.plan(n, alg)
        if mode == 'raise':
            raise RuntimeError('桩：模拟网络错误')
        if mode == 'truncate':
            # 实测形态：预算全花在思维链上，stop_reason='max_tokens'，
            # 只有一个空的 thinking 块。
            return _Resp('', stop_reason='max_tokens', blocks=[_ThinkBlock()])
        if mode == 'garbage':
            return _Resp('抱歉，我无法回答这个问题。')

        # 模拟模型引用真实存在的证据：
        # 至少有两条证据时引用 E2，否则引用 E1。
        refs = ['E2'] if len(evidence) >= 2 else (
            ['E1'] if len(evidence) >= 1 else []
        )

        body = json.dumps({
            'usage': FAKE_USAGE.get(alg, 'unknown'),
            'explanation': '（假数据）%s 用于 %s。'
                           % (alg, FAKE_USAGE.get(alg, 'unknown')),
            'evidence_refs': refs,
        }, ensure_ascii=False)

        if mode == 'fence':
            body = '```json\n' + body + '\n```'
        elif mode == 'chatty':
            body = '好的，分析结果如下：\n' + body + '\n希望有帮助！'
        return _Resp(body)


class _FakeClient:
    def __init__(self, plan):
        self.messages = _Messages(plan)



def install_stub(plan=lambda n, alg: 'clean'):
    """把 enrich 的 client 换成桩。返回桩本身，便于事后检查 payload。"""
    # 离线自检需要模型名，但不需要真实 API
    os.environ.setdefault("ANTHROPIC_MODEL", "selftest-stub")

    client = _FakeClient(plan)
    enrich._CLIENT = client
    return client


# ------------------------------------------------------------------ 各场景

def t_evidence_refs_validation():
    """独立检查 evidence_refs 的格式、范围和去重行为。"""
    evidence = [{"note": "evidence 1"}, {"note": "evidence 2"}]

    cases = [
        ("正常引用", ["E1", "E2"], ["E1", "E2"]),
        ("拒绝 E0", ["E0"], []),
        ("拒绝 E01", ["E01"], []),
        ("拒绝越界引用", ["E99"], []),
        ("重复引用去重", ["E1", "E1", "E2"], ["E1", "E2"]),
        ("忽略非字符串", ["E1", 2], ["E1"]),
        ("空列表", [], []),
        ("非列表输入", "E1", []),
        ("证据非列表", ["E1"], []),
    ]

    for name, refs, expected in cases:
        actual = enrich._validate_evidence_refs(
            refs,
            "not a list" if name == "证据非列表" else evidence,
        )
        check("evidence_refs：" + name, actual, expected)

    legacy = {
        'evidence': evidence,
        'remediation': {'source': 'rule-base'},
    }
    check('resume 不复用缺少 evidence_refs 的旧增强结果',
          enrich._is_enriched(legacy), False)
    legacy['evidence_refs'] = ['E1']
    check('resume 复用带有效 evidence_refs 的增强结果',
          enrich._is_enriched(legacy), True)

    credential = {
        'finding_kind': 'credential',
        'evidence': evidence,
        'evidence_refs': ['E1'],
        'remediation': {'source': 'rule-base'},
    }
    check('凭据本地终态永不送 LLM', enrich._is_local_final(credential), True)
    credential['remediation']['source'] = 'none'
    check('未完成的凭据不能伪装成本地终态',
          enrich._is_local_final(credential), False)


def t_parse_robustness():
    """解析器要能吃下模型的真实输出习惯，且坏输入要抛出可读异常。"""
    good = '{"usage": "signing", "explanation": "x"}'
    check('裸 JSON', enrich.parse_llm_json(good)['usage'], 'signing')
    check('```json 围栏', enrich.parse_llm_json('```json\n' + good + '\n```')['usage'], 'signing')
    check('``` 无语言标记', enrich.parse_llm_json('```\n' + good + '\n```')['usage'], 'signing')
    check('前后有闲聊', enrich.parse_llm_json('好的：\n' + good + '\n完毕')['usage'], 'signing')
    # 字符串里含花括号 —— 朴素 find/rfind 会在这里取错范围
    check('字符串内含花括号',
          enrich.parse_llm_json('{"usage": "signing", "explanation": "用 {x} 表示"}')['explanation'],
          '用 {x} 表示')

    for bad in ('完全不是 JSON', '{"usage": ', ''):
        try:
            enrich.parse_llm_json(bad)
            FAILS.append('坏输入 %r 应该抛异常，却返回了' % bad[:20])
        except ValueError:
            pass


def t_full_run_clean():
    """干净跑：入库夹具全过，且仍然合规。"""
    stub = install_stub()
    with tempfile.TemporaryDirectory() as td:
        inp = Path(td) / 'findings.json'
        findings = _write_fixture(inp)
        out = Path(td) / 'ai.json'
        sys.argv = ['enrich.py', str(inp), '-o', str(out)]
        enrich.main()
        result = json.loads(out.read_text(encoding='utf-8'))

    check('条数不变', len(result), len(findings))
    check('每条都有 explanation', sum('explanation' in f for f in result), len(findings))
    check('全部换成 rule-base',
          sum(f['remediation']['source'] == 'rule-base' for f in result), len(findings))
    check('调用次数', len(stub.messages.calls), len(findings))

    # 检查每条 Finding 的 evidence_refs 是否合法
    valid_refs_count = 0

    for f in result:
        refs = f.get('evidence_refs')
        evidence = f.get('evidence') or []

        if not isinstance(refs, list) or not refs:
            continue

        valid = True
        seen = set()

        for ref in refs:
            if not isinstance(ref, str):
                valid = False
                break

            if not ref.startswith('E') or not ref[1:].isdigit():
                valid = False
                break

            number = int(ref[1:])

            # 禁止 E0、E01 等非规范编号，也不能引用不存在的证据
            if number < 1 or str(number) != ref[1:] or number > len(evidence):
                valid = False
                break

            if ref in seen:
                valid = False
                break

            seen.add(ref)

        if valid:
            valid_refs_count += 1

    check('每条都有合法 evidence_refs', valid_refs_count, len(result))

    # 检查多证据 Finding 是否引用了 E2 或更高编号
    multi_evidence = [
        f for f in result
        if len(f.get('evidence') or []) >= 2
    ]

    higher_ref_count = sum(
        1 for f in multi_evidence
        if any(
            isinstance(ref, str)
            and ref.startswith('E')
            and ref[1:].isdigit()
            and int(ref[1:]) >= 2
            for ref in (f.get('evidence_refs') or [])
        )
    )

    # 暂按至少 20% 作为自检门槛；若团队有明确比例要求，以团队要求为准
    if multi_evidence:
        check_true(
            '多证据 Finding 引用 E2 或更高编号的比例至少为 20%',
            higher_ref_count / len(multi_evidence) >= 0.20
        )
    else:
        check_true(
            '存在至少一条含多条证据的 Finding',
            False
        )

    return result



def t_schema_compliance(result):
    """产出必须仍然过收紧后的 schema —— 这是 README 的第一条验收标准。"""
    try:
        import jsonschema
    except ImportError:
        print('  (跳过 schema 校验：未安装 jsonschema)')
        return
    schema = json.loads(SCHEMA.read_text(encoding='utf-8'))
    validator = jsonschema.Draft7Validator(schema)
    bad = [(f.get('finding_id'), sorted(e.message for e in validator.iter_errors(f)))
           for f in result if list(validator.iter_errors(f))]
    check('全部条目过 schema', bad, [])


def t_fence_does_not_crash():
    """模型在第 N 条包围栏 —— 修之前这里会崩，且丢掉全部进度。"""
    install_stub(lambda n, alg: 'fence' if n == 2 else 'clean')
    with tempfile.TemporaryDirectory() as td:
        inp = Path(td) / 'findings.json'
        _write_fixture(inp)
        out = Path(td) / 'ai.json'
        sys.argv = ['enrich.py', str(inp), '-o', str(out)]
        enrich.main()
        check_true('围栏不再导致崩溃，输出文件存在', out.exists())
        result = json.loads(out.read_text(encoding='utf-8'))
    check('围栏场景下仍是全覆盖',
          sum(f['remediation']['source'] == 'rule-base' for f in result), len(result))


def t_partial_failure_is_survivable():
    """第 30 条一直失败 —— 其余必须照常完成，失败的保持占位符。"""
    install_stub(lambda n, alg: 'raise' if n == 2 else 'clean')
    with tempfile.TemporaryDirectory() as td:
        inp = Path(td) / 'findings.json'
        _write_fixture(inp)
        out = Path(td) / 'ai.json'
        sys.argv = ['enrich.py', str(inp), '-o', str(out)]
        enrich.main()
        result = json.loads(out.read_text(encoding='utf-8'))

    none_ct = sum(f['remediation']['source'] == 'none' for f in result)
    check('恰好 1 条保持占位符', none_ct, 1)
    check('其余全部增强',
          sum(f['remediation']['source'] == 'rule-base' for f in result),
          len(result) - 1)
    check('失败条目没有 explanation（半成品不该出现）',
          sum('explanation' in f for f in result), len(result) - 1)

    # --resume 必须自动重试那一条
    install_stub()
    with tempfile.TemporaryDirectory() as td:
        inp = Path(td) / 'findings.json'
        _write_fixture(inp)
        out = Path(td) / 'ai.json'
        out.write_text(json.dumps(result, ensure_ascii=False), encoding='utf-8')
        sys.argv = ['enrich.py', str(inp), '-o', str(out), '--resume']
        enrich.main()
        resumed = json.loads(out.read_text(encoding='utf-8'))
    check('resume 之后全部补上',
          sum(f['remediation']['source'] == 'rule-base' for f in resumed), len(resumed))


def t_truncation_is_reported_clearly():
    """截断必须被**明确报出来**，不能伪装成「模型不听话」。

    实测 max_tokens=500 时 16/91 条失败，两种表现（无文本块 / 花括号配不平）
    根因是同一个：思维链把预算吃光了。不报 stop_reason 的话只会看到
    「找不到 JSON 对象」，查错方向会完全跑偏。
    """
    install_stub(lambda n, alg: 'truncate')
    finding = _fresh_findings()[0]
    try:
        enrich.enrich_finding(dict(finding), 'full')
        FAILS.append('被截断的响应应该抛异常，却成功返回了')
    except RuntimeError as exc:
        check_true('截断错误信息点明 max_tokens', 'max_tokens' in str(exc))
        check_true('截断错误信息带内容块类型', 'thinking' in str(exc))

    # 截断的条目保持占位符，且不拖垮其余条目
    install_stub(lambda n, alg: 'truncate' if n == 2 else 'clean')
    with tempfile.TemporaryDirectory() as td:
        inp = Path(td) / 'findings.json'
        _write_fixture(inp)
        out = Path(td) / 'ai.json'
        sys.argv = ['enrich.py', str(inp), '-o', str(out)]
        enrich.main()
        result = json.loads(out.read_text(encoding='utf-8'))
    check('截断条目保持占位符',
          sum(f['remediation']['source'] == 'none' for f in result), 1)
    check('截断条目没有留下半成品 explanation',
          sum('explanation' in f for f in result), len(result) - 1)


def t_no_leak_in_payload():
    """两种模式下，发出去的 payload 都不许含源码路径或密钥。"""
    findings = _fresh_findings()
    for mode in ('shape', 'full'):
        blobs = [json.dumps(redact.redact_finding(f, mode), ensure_ascii=False)
                 for f in findings]
        blob = '\n'.join(blobs)
        for marker in ('C:' + chr(92), 'D:' + chr(92), '/home/', '/Users/',
                       '_smoke', 'crypto-samples', 'sk-live'):
            check('%s 模式不含 %s' % (mode, marker), marker in blob, False)
        check('%s 模式不含上游 raw' % mode, '"raw"' in blob, False)
        if mode == 'shape':
            check('shape 模式不含 call_context', 'call_context' in blob, False)
        else:
            check_true('full 模式确实发出了代码行', 'call_context' in blob)
        # 两种模式都必须保留判用途的线索
        check_true('%s 模式保留算法名' % mode, '"algorithm"' in blob)


def t_redaction_did_not_eat_signal():
    """脱敏不能把算法名/方法名误伤 —— 回归断言。"""
    for keep in ('POSTQUANTUMCRYPTOLIBRARY', 'bcrypt.GenerateFromPassword',
                 'SHA384512SHA2', 'CHACHA20POLY1305'):
        check('不过度脱敏: %s' % keep, redact.scrub(keep), keep)


def t_two_stage_redline():
    """§9.1：用途判不出时，绝不给具体算法。"""
    import importlib
    routing = importlib.import_module('core.rules.pqc_routing')
    r = routing.route('RSA', 'unknown')
    check('RSA/unknown -> decided=False', r['decided'], False)
    check_true('明说暂不给算法', '暂不给出具体算法' in r['action'])
    # 签名路线绝不能出现 ML-KEM
    check('RSA/signing 不给 ML-KEM', 'ML-KEM' in routing.route('RSA', 'signing')['action'], False)


def t_usage_rewrite_actually_happens():
    """AI 判出的用途必须真的写回 finding，并驱动 remediation。"""
    stub = install_stub(lambda n, alg: 'clean')
    with tempfile.TemporaryDirectory() as td:
        inp = Path(td) / 'findings.json'
        findings = _write_fixture(inp)
        out = Path(td) / 'ai.json'
        sys.argv = ['enrich.py', str(inp), '-o', str(out)]
        enrich.main()
        result = json.loads(out.read_text(encoding='utf-8'))

    before = {f['finding_id']: f for f in findings}
    rewritten = [f for f in result if before[f['finding_id']]['usage'] != f['usage']]
    check_true('确实有 usage 被改写（否则 AI 层没起作用）', rewritten)

    # 被改写成 signing 的 RSA，remediation 必须指向 ML-DSA，不许是 ML-KEM
    for f in result:
        if f['algorithm_normalized'].startswith('RSA') and f['usage'] == 'signing':
            check_true('RSA 判为签名 -> 给 ML-DSA', 'ML-DSA' in f['remediation']['action'])
            check('RSA 判为签名 -> 不给 ML-KEM',
                  'ML-KEM' in f['remediation']['action'], False)
            break

    # needs-usage-review 标记：判出来的该摘掉，仍 unknown 的该留着
    stale = [f['finding_id'] for f in result
             if f['usage'] != 'unknown'
             and 'needs-usage-review' in (f.get('tags') or [])]
    check('判出用途的条目不该还挂着 needs-usage-review', stale, [])
    kept = [f for f in result
            if f['usage'] == 'unknown'
            and 'needs-usage-review' in (f.get('tags') or [])]
    check_true('仍判不出用途的条目应保留该标记', kept)


# ------------------------------------------------------------------ 主流程

def main():
    print('ai/ 离线自检（桩 LLM，不花钱）')
    print('=' * 68)

    t_evidence_refs_validation()
    t_parse_robustness()
    print('  [1/8] 解析鲁棒性')
    result = t_full_run_clean()
    print('  [2/8] 干净跑通')
    t_schema_compliance(result)
    print('  [3/8] schema 合规')
    t_fence_does_not_crash()
    print('  [4/8] 代码围栏不再崩')
    t_partial_failure_is_survivable()
    print('  [5/8] 单条失败可存活 + resume')
    t_truncation_is_reported_clearly()
    print('  [6/8] 截断被明确报出')
    t_no_leak_in_payload()
    t_redaction_did_not_eat_signal()
    print('  [7/8] 脱敏：不泄露、也不误伤')
    t_two_stage_redline()
    t_usage_rewrite_actually_happens()
    print('  [8/8] §9.1 红线 + usage 改写')

    print('=' * 68)
    if FAILS:
        print('[FAIL] %d 项断言未通过:' % len(FAILS))
        for f in FAILS:
            print('  - %s' % f)
        return 1
    print('[PASS] 全部断言通过')
    return 0


if __name__ == '__main__':
    sys.exit(main())
