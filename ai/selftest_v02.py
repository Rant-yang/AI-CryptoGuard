"""Offline v0.2 AI contract, grounding, redaction and resume checks."""
import copy
import json
import tempfile
from pathlib import Path

from ai.enrich_v02 import _model_payload, enrich_file, enrich_one
from core.quantum_assessment import assess_one
from core.schema.validate_v02 import errors

ROOT = Path(__file__).resolve().parent.parent


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
    rsa = assess_one(sample("java_complete"))
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

    undecided = enrich_one(rsa, lambda *_: model("unknown"), model_id="offline-test")
    check("用途未知时不选定 PQC 路线", not errors(undecided) and
          not undecided["remediation"]["decided"] and
          not any("ML-DSA" in s["action"] for s in undecided["remediation_steps"]))

    for bad in (model(refs=["E2"]),
                {**model(), "steps": [{**model()["steps"][0],
                                       "action": "将 RSA 换成 ML-KEM"}]}):
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

    sensitive = copy.deepcopy(rsa)
    sensitive["file"] = "src/Actual.java"
    sensitive["evidence"][0]["raw"] = {"context":
        "private_key = 'sk-live-Aaa1Bbb2Ccc3Ddd4Eee5Fff6Ggg7Hhh8'"}
    safe = json.dumps(_model_payload(sensitive, "shape"), ensure_ascii=False)
    check("默认载荷不发送源码、凭据和绝对路径",
          "Aaa1Bbb2" not in safe and "private_key =" not in safe and
          "D:\\" not in safe)

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

    print("AI v0.2 离线自检完成。")


if __name__ == "__main__":
    main()
