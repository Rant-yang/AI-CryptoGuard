"""C 线离线自检：不运行第三方工具，不调用云模型。"""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.pipeline import main as pipeline_main
from core.quantum_assessment import assess_one
from core.schema.validate_v02 import errors

SAMPLES = json.loads((ROOT / "core/samples/example_finding.json").read_text(encoding="utf-8"))


def main():
    rsa = assess_one(SAMPLES[0])
    assert rsa["stage"] == "assessed"
    assert rsa["quantum_assessment"]["quantum_effect"] == "shor"
    assert {x["usage"] for x in rsa["quantum_assessment"]["migration_candidates"]} == {
        "signing", "encryption", "key_exchange"
    }
    assert not errors(rsa)

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
                              "-o", temp])
        assert code == 0
        task = json.loads((Path(temp) / "task.json").read_text(encoding="utf-8"))
        assessed = json.loads((Path(temp) / "findings_assessed.json").read_text(
            encoding="utf-8"))
        assert [s["status"] for s in task["stages"]] == [
            "skipped", "skipped", "completed", "skipped"
        ]
        assert len(assessed) == 2

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
