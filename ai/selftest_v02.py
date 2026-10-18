"""Offline v0.2 AI contract, grounding, redaction and resume checks."""
import copy
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai.enrich_v02 import (_has_direct_usage_evidence, _model_payload,
                           enrich_file, enrich_one)
from core.quantum_assessment import assess_one
from core.schema.validate_v02 import errors


def sample(name):
    rows = json.loads((ROOT / "core" / "samples" / "v0.2" /
                       (name + ".json")).read_text(encoding="utf-8"))
    return copy.deepcopy(rows[1])


def check(label, condition):
    if not condition:
        raise AssertionError(label)
    print("[PASS] " + label)


def model(usage="signing", refs=None):
    return {"usage": usage, "reason": "调用点用于数字签名" if usage != "unknown" else
            "证据尚不足以确定用途", "evidence_refs": refs or ["E1"],
            "unknowns": [] if usage != "unknown" else ["业务调用方式待确认"],
            "explanation": "当前调用存在公钥量子风险，实际用途需结合调用点确认。",
            "steps": [{"action": "核对该调用点的输入输出与业务用途",
                       "evidence_refs": refs or ["E1"], "prerequisites": [],
                       "verification": ["运行对应的集成测试并核对调用路径"]}]}


def main():
    bare = assess_one(sample("java_complete"))
    unsupported = enrich_one(bare, lambda *_: model(), model_id="offline-test")
    check("仅凭算法名和无关污点汇点不能认定 RSA 签名用途",
          unsupported["usage"] == "unknown" and
          unsupported["remediation"]["reason"] == "usage-undetermined")
    kdf = copy.deepcopy(bare)
    kdf["algorithm"] = kdf["algorithm_normalized"] = "HKDF"
    check("单独的 KDF 调用不能证明认证或密钥交换用途",
          not _has_direct_usage_evidence(kdf, "authentication"))

    rsa = copy.deepcopy(bare)
    rsa["evidence"][0]["flow"]["sink"]["method"] = "java.security.Signature.sign"
    rsa = assess_one(rsa)
    got = enrich_one(rsa, lambda *_: model(), model_id="offline-test")
    check("用途变更后重新路由到签名，结果符合 v0.2", not errors(got) and
          got["usage"] == "signing" and got["quantum_assessment"]
          ["migration_candidates"][0]["usage"] == "signing" and
          "ML-DSA" in got["remediation"]["action"] and
          "ML-KEM" not in got["remediation"]["action"])
    check("步骤目标来自真实证据且未声称已执行",
          all(step["target"] is None or step["target"]["line"] > 0
              for step in got["remediation_steps"]) and
          all(step["execution_status"] == "not_run" for step in got["remediation_steps"]))

    two_sources = copy.deepcopy(rsa)
    call_evidence = two_sources["evidence"][0]
    two_sources["evidence"] = [
        {"tool": "cbom-scan", "kind": "pattern", "lines": [21],
         "raw": {"algo": "RSA", "prim": "asymmetric"}},
        call_evidence,
    ]
    two_sources = assess_one(two_sources)
    try:
        enrich_one(two_sources, lambda *_: model(refs=["E1"]),
                   model_id="offline-test")
    except ValueError as exc:
        check("资产 E1 不能冒充 E2 的签名调用证据",
              str(exc) == "模型用途引用缺少实际调用证据")
    else:
        raise AssertionError("uncited call evidence accepted")
    cited = enrich_one(two_sources, lambda *_: model(refs=["E2"]),
                       model_id="offline-test")
    check("引用真正调用证据 E2 后可形成签名结论",
          cited["usage"] == "signing" and cited["evidence_refs"] == ["E2"])
    unrelated_call = copy.deepcopy(two_sources)
    unrelated_call["evidence"][0]["tool"] = "cryptoscan"
    unrelated_call["evidence"][0]["raw"] = {
        "records": [{"context": "cipher.encrypt(data)"}]}
    unrelated_call = assess_one(unrelated_call)
    wrong_primitive = enrich_one(
        unrelated_call, lambda *_: model(refs=["E1"]),
        model_id="offline-test")
    check("引用了调用点但调用属于另一原语时不得认定 RSA 签名",
          wrong_primitive["usage"] == "unknown" and
          wrong_primitive["remediation"]["reason"] == "usage-undetermined")

    primitive = copy.deepcopy(bare)
    primitive["evidence"] = [{
        "tool": "cryptoscan", "kind": "pattern", "lines": [9],
        "raw": {"records": [{"context": 'MessageDigest.getInstance("MD5")'}]},
    }]
    primitive["algorithm"] = primitive["algorithm_normalized"] = "MD5"
    check("只创建 MessageDigest 对象不能判为已执行 hashing",
          not _has_direct_usage_evidence(primitive, "hashing", ["E1"]))
    primitive["evidence"][0]["raw"]["records"][0]["context"] = \
        "return hashlib.md5(data).digest()"
    check("真实 digest 调用仍可判为 hashing",
          _has_direct_usage_evidence(primitive, "hashing", ["E1"]))
    primitive["algorithm"] = primitive["algorithm_normalized"] = "3DES"
    primitive["evidence"][0]["raw"]["records"][0]["context"] = \
        "cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))"
    check("只创建对称 Cipher 对象不能判为已执行 encryption",
          not _has_direct_usage_evidence(primitive, "encryption", ["E1"]))
    primitive["evidence"][0]["raw"]["records"][0]["context"] = \
        "cipher.encrypt(data)"
    check("明确的加密调用仍可判为 encryption",
          _has_direct_usage_evidence(primitive, "encryption", ["E1"]))

    undecided = enrich_one(rsa, lambda *_: model("unknown"), model_id="offline-test")
    check("用途未知时不选定 PQC 路线", not errors(undecided) and
          not undecided["remediation"]["decided"] and
          not any("ML-DSA" in s["action"] for s in undecided["remediation_steps"]))

    for bad in (model(refs=["E2"]),
                {**model(), "steps": [{**model()["steps"][0],
                                       "action": "将 RSA 换成 ML-KEM"}]},
                {**model(), "steps": [{**model()["steps"][0],
                                       "action": "立即改用 AES-256-GCM"}]}):
        try:
            enrich_one(rsa, lambda *_: bad, model_id="offline-test")
        except ValueError:
            pass
        else:
            raise AssertionError("invalid model output accepted")
    check("越界引用与模型擅选 PQC 均被拒绝", True)

    credential = sample("credential")
    local = enrich_one(credential, lambda *_: (_ for _ in ()).throw(
        AssertionError("credential sent to model")))
    check("凭据本地处理，无模型调用或量子迁移", not errors(local) and
          local["analysis_provenance"]["model_id"] == "local-rule-base" and
          not local["quantum_assessment"]["migration_candidates"])

    fallback = copy.deepcopy(bare)
    fallback["tags"] = ["conditional-default"]
    fallback = assess_one(fallback)
    fallback_local = enrich_one(fallback, lambda *_: (_ for _ in ()).throw(
        AssertionError("conditional fallback sent to model")))
    check("条件性默认值本地解释，不把备用算法说成当前已生效", not errors(fallback_local) and
          fallback_local["analysis_provenance"]["model_id"] == "local-config-rule" and
          fallback_local["remediation"]["reason"] == "conditional-default" and
          "不能断言" in fallback_local["usage_assessment"]["reason"])

    from scanner.adapters import python_ast
    with tempfile.TemporaryDirectory() as td:
        Path(td, 'case.py').write_text(
            'import random\nnonce = random.Random().randbytes(12)\n',
            encoding='utf-8')
        weak = assess_one(python_ast.scan(td)[0])
    weak_local = enrich_one(weak, lambda *_: (_ for _ in ()).throw(
        AssertionError("weak random AST fact sent to model")))
    check("弱随机 AST 事实本地解释并保留扫描器整改结论",
          not errors(weak_local) and
          weak_local["analysis_provenance"]["model_id"] == "local-ast-rule" and
          weak_local["remediation"]["decided"] and
          weak_local["evidence_refs"] == ["E1"])

    sensitive = copy.deepcopy(rsa)
    sensitive["file"] = "src/Actual.java"
    sensitive["evidence"][0]["raw"] = {"context":
        "private_key = 'sk-live-Aaa1Bbb2Ccc3Ddd4Eee5Fff6Ggg7Hhh8'"}
    safe = json.dumps(_model_payload(sensitive, "shape"), ensure_ascii=False)
    check("默认载荷不发送源码、凭据和绝对路径",
          "Aaa1Bbb2" not in safe and "private_key =" not in safe and
          "D:\\" not in safe)
    check("模型载荷逐条显式标出 E 编号，减少资产与调用证据错位",
          [e["ref"] for e in _model_payload(two_sources, "shape")["evidence"]]
          == ["E1", "E2"])

    with tempfile.TemporaryDirectory() as tmp:
        src, dst = Path(tmp) / "assessed.json", Path(tmp) / "explained.json"
        src.write_text(json.dumps([rsa, credential]), encoding="utf-8")
        calls = []
        def stub(*args):
            calls.append(1)
            return model()
        rows, failed, reused = enrich_file(src, dst, model_call=stub,
                                          model_id="offline-test", checkpoint=1)
        check("文件处理可混合云端与本地凭据", len(rows) == 2 and
              not failed and len(calls) == 1 and dst.is_file())
        rows, failed, reused = enrich_file(src, dst, model_call=stub,
                                          model_id="offline-test", resume=True)
        check("相同输入复用已校验结果", reused == 2 and len(calls) == 1)
        altered = copy.deepcopy(rsa)
        altered["evidence"][0]["lines"].append(987)
        src.write_text(json.dumps([altered, credential]), encoding="utf-8")
        rows, failed, reused = enrich_file(src, dst, model_call=stub,
                                          model_id="offline-test", resume=True)
        check("证据变化使缓存失效", reused == 1 and len(calls) == 2 and not failed)

        tries = []
        def flaky(*args):
            tries.append(1)
            return model(refs=['E2']) if len(tries) == 1 else model()
        rows, failed, reused = enrich_file(src, dst, model_call=flaky,
                                            model_id='offline-flaky', checkpoint=1)
        attempt_log = json.loads(Path(str(dst) + '.attempts.json').read_text(encoding='utf-8'))
        check('单条证据校验失败后只重试一次，且只记录安全错误类别',
              len(tries) == 2 and not failed and
              attempt_log == [{'finding_id': altered['finding_id'],
                               'recovered_after': 'invalid_refs'}])

        budgets = []
        def truncated_then_ok(_finding, _context, tokens):
            budgets.append(tokens)
            if len(budgets) == 1:
                raise RuntimeError('模型响应达到 token 上限；提高 --max-tokens')
            return model()
        rows, failed, reused = enrich_file(
            src, dst, model_call=truncated_then_ok, model_id='offline-budget',
            max_tokens=4000, checkpoint=1)
        check('模型截断仅在第二次将 token 预算加倍',
              not failed and budgets == [4000, 8000] and
              'tokens=8000' in rows[0]['analysis_provenance']['model_id'])
        rows, failed, reused = enrich_file(
            src, dst, model_call=truncated_then_ok, model_id='offline-budget',
            max_tokens=4000, checkpoint=1, resume=True)
        check('加倍预算成功的结果可安全断点复用',
              not failed and reused == 2 and budgets == [4000, 8000])

        config_calls = []
        def bad_config(*_args):
            config_calls.append(1)
            raise PermissionError('no credentials')
        rows, failed, _ = enrich_file(src, dst, model_call=bad_config,
                                       model_id='offline-config', checkpoint=1)
        check('不可重试的配置错误只请求一次且不记录异常原文',
              len(config_calls) == 1 and rows[0]['stage'] == 'assessed' and
              failed == [{'finding_id': altered['finding_id'],
                          'error': 'PermissionError', 'category': 'PermissionError'}])

    print("AI v0.2 离线自检完成。")


if __name__ == "__main__":
    main()
