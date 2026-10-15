"""C 线离线自检：不运行第三方工具，不调用云模型。"""
import copy
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.pipeline import main as pipeline_main
from core.quantum_assessment import assess_one
from core.quantum_timeline import make_profile
from core.schema.validate_v02 import errors

SAMPLES = json.loads((ROOT / "core/samples/example_finding.json").read_text(encoding="utf-8"))


def main():
    timeline = make_profile(10, 3, 8, "yes")
    rsa = assess_one(SAMPLES[0], timeline)
    assert rsa["stage"] == "assessed"
    assert rsa["quantum_assessment"]["quantum_effect"] == "shor"
    assert {x["usage"] for x in rsa["quantum_assessment"]["migration_candidates"]} == {
        "signing", "encryption", "key_exchange"
    }
    assert rsa["quantum_assessment"]["quantum_timeline"]["urgency"] == "immediate"
    assert rsa["quantum_assessment"]["quantum_timeline"]["hndl_status"] == "unknown"
    assert not errors(rsa)
    stale_timeline = copy.deepcopy(rsa)
    stale_timeline["quantum_assessment"]["quantum_timeline"]["years_until_action"] = 99
    assert "timeline action year mismatch" in errors(stale_timeline)

    md5 = assess_one(SAMPLES[1])
    assert md5["quantum_assessment"]["quantum_effect"] == "no_known_quantum_break"
    assert md5["quantum_assessment"]["classical_issues"]
    assert not errors(md5)

    credential = json.loads((ROOT / "core/samples/v0.2/credential.json").read_text(
        encoding="utf-8"))[0]
    credential = assess_one(credential)
    assert credential["quantum_assessment"]["status"] == "not_applicable"
    assert not credential["quantum_assessment"]["migration_candidates"]
    assert not errors(credential)

    configuration = dict(SAMPLES[0])
    configuration["finding_kind"] = "configuration"
    configuration["risk"] = "review"
    configuration = assess_one(configuration)
    assert configuration["quantum_assessment"]["status"] == "insufficient_evidence"

    with tempfile.TemporaryDirectory(prefix="acg-core-") as temp:
        code = pipeline_main(["--findings", str(ROOT / "core/samples/example_finding.json"),
                              "-o", temp, "--data-lifetime-years", "10",
                              "--migration-lead-years", "3",
                              "--threat-horizon-years", "8",
                              "--hndl-exposure", "yes"])
        assert code == 0
        task = json.loads((Path(temp) / "task.json").read_text(encoding="utf-8"))
        assessed = json.loads((Path(temp) / "findings_assessed.json").read_text(
            encoding="utf-8"))
        assert [s["status"] for s in task["stages"]] == [
            "skipped", "skipped", "completed", "skipped"
        ]
        assert len(assessed) == 2
        assert task["quantum_timeline_profile"]["source"] == "user-input"
        assert assessed[0]["quantum_assessment"]["quantum_timeline"]["urgency"] == "immediate"

        bad_input = Path(temp) / "bad.json"
        bad_input.write_text('[{"schema_version":"0.1"}]\n', encoding="utf-8")
        bad_out = Path(temp) / "bad-run"
        assert pipeline_main(["--findings", str(bad_input), "-o", str(bad_out)]) == 2
        failed_task = json.loads((bad_out / "task.json").read_text(encoding="utf-8"))
        assert failed_task["stages"][2]["status"] == "failed"
        assert failed_task["stages"][2]["reason"]
    print("PASS: C quantum assessment + unified entry offline selftest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
