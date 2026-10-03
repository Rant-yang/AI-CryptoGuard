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

FINDINGS = ROOT / 'out' / 'findings.json'
SCHEMA = ROOT / 'core' / 'schema' / 'finding.v0.1.json'

FAILS = []


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


class _Resp:
    def __init__(self, text):
        self.content = [_Block(text)]


class _Messages:
    def __init__(self, plan):
        self.plan = plan
        self.calls = []

    def create(self, **kwargs):
        prompt = kwargs['messages'][0]['content']
        self.calls.append(prompt)
        n = len(self.calls)
        alg = None
        for line in prompt.splitlines():
            if '"algorithm_normalized"' in line:
                alg = line.split('"')[3]
                break
        mode = self.plan(n, alg)
        if mode == 'raise':
            raise RuntimeError('桩：模拟网络错误')
        if mode == 'garbage':
            return _Resp('抱歉，我无法回答这个问题。')
        body = json.dumps({'usage': FAKE_USAGE.get(alg, 'unknown'),
                           'explanation': '（假数据）%s 用于 %s。'
                                          % (alg, FAKE_USAGE.get(alg, 'unknown'))},
                          ensure_ascii=False)
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
    client = _FakeClient(plan)
    enrich._CLIENT = client
    return client


# ------------------------------------------------------------------ 各场景

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
    """干净跑：91 条全过，且仍然合规。"""
    stub = install_stub()
    findings = json.loads(FINDINGS.read_text(encoding='utf-8'))
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / 'ai.json'
        sys.argv = ['enrich.py', str(FINDINGS), '-o', str(out)]
        enrich.main()
        result = json.loads(out.read_text(encoding='utf-8'))

    check('条数不变', len(result), len(findings))
    check('每条都有 explanation', sum('explanation' in f for f in result), len(findings))
    check('全部换成 rule-base',
          sum(f['remediation']['source'] == 'rule-base' for f in result), len(findings))
    check('调用次数', len(stub.messages.calls), len(findings))
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
    install_stub(lambda n, alg: 'fence' if n == 50 else 'clean')
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / 'ai.json'
        sys.argv = ['enrich.py', str(FINDINGS), '-o', str(out)]
        enrich.main()
        check_true('围栏不再导致崩溃，输出文件存在', out.exists())
        result = json.loads(out.read_text(encoding='utf-8'))
    check('围栏场景下仍是全覆盖',
          sum(f['remediation']['source'] == 'rule-base' for f in result), len(result))


def t_partial_failure_is_survivable():
    """第 30 条一直失败 —— 其余必须照常完成，失败的保持占位符。"""
    install_stub(lambda n, alg: 'raise' if n == 30 else 'clean')
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / 'ai.json'
        sys.argv = ['enrich.py', str(FINDINGS), '-o', str(out)]
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
        out = Path(td) / 'ai.json'
        out.write_text(json.dumps(result, ensure_ascii=False), encoding='utf-8')
        sys.argv = ['enrich.py', str(FINDINGS), '-o', str(out), '--resume']
        enrich.main()
        resumed = json.loads(out.read_text(encoding='utf-8'))
    check('resume 之后全部补上',
          sum(f['remediation']['source'] == 'rule-base' for f in resumed), len(resumed))


def t_no_leak_in_payload():
    """两种模式下，真实 91 条发出去的 payload 都不许含源码/绝对路径。"""
    findings = json.loads(FINDINGS.read_text(encoding='utf-8'))
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
    findings = json.loads(FINDINGS.read_text(encoding='utf-8'))
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / 'ai.json'
        sys.argv = ['enrich.py', str(FINDINGS), '-o', str(out)]
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

    t_parse_robustness()
    print('  [1/7] 解析鲁棒性')
    result = t_full_run_clean()
    print('  [2/7] 干净跑通')
    t_schema_compliance(result)
    print('  [3/7] schema 合规')
    t_fence_does_not_crash()
    print('  [4/7] 代码围栏不再崩')
    t_partial_failure_is_survivable()
    print('  [5/7] 单条失败可存活 + resume')
    t_no_leak_in_payload()
    t_redaction_did_not_eat_signal()
    print('  [6/7] 脱敏：不泄露、也不误伤')
    t_two_stage_redline()
    t_usage_rewrite_actually_happens()
    print('  [7/7] §9.1 红线 + usage 改写')

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
