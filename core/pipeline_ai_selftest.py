"""Offline end-to-end check for optional AI stage. No cloud requests."""
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai.enrich_v02 import enrich_file
from core import pipeline
from core.schema.validate_v02 import errors


def stub(finding, _context, _max_tokens):
    return {
        "usage": "unknown", "reason": "只有算法命中，不能据此确定业务用途。",
        "evidence_refs": ["E1"], "unknowns": ["需要核对调用者及输入输出"],
        "explanation": "证据表明项目使用该算法；具体用途仍需人工核对。",
        "steps": [{"action": "定位调用者并核对用途", "evidence_refs": ["E1"],
                   "prerequisites": [], "verification": ["复核调用点和业务调用链"]}],
    }


def offline_enrich(input_path, output_path, **kwargs):
    return enrich_file(input_path, output_path, model_call=stub,
                       model_id="offline-pipeline-test", **kwargs)


def main():
    source = ROOT / "core" / "samples" / "example_finding.json"
    with tempfile.TemporaryDirectory(prefix="acg-pipeline-ai-") as tmp:
        with patch.object(pipeline, "enrich_ai_file", offline_enrich), patch.dict(
                "os.environ", {"ANTHROPIC_AUTH_TOKEN": "fixture-only",
                               "ANTHROPIC_MODEL": "offline-pipeline-test"}):
            rows, task, path, _ = pipeline.run(
                findings_path=source, output_dir=Path(tmp) / "with-ai", ai=True)
        stages = {s["name"]: s for s in task["stages"]}
        assert stages["ai"]["status"] == "completed", stages["ai"]
        assert path.name == "findings_explained.json"
        assert len(rows) == 2 and all(r["stage"] == "explained" and not errors(r)
                                      for r in rows)
        assert not errors(task), errors(task)

        with patch.dict("os.environ", {"ANTHROPIC_AUTH_TOKEN": "",
                                       "ANTHROPIC_MODEL": ""}):
            rows, task, path, _ = pipeline.run(
                findings_path=source, output_dir=Path(tmp) / "without-key", ai=True)
        assert task["stages"][3]["status"] == "failed"
        assert path.name == "findings_assessed.json"
        assert all(r["stage"] == "assessed" for r in rows)
        assert not errors(task), errors(task)
    print("PASS: optional AI pipeline, v0.2 schema, missing-key fallback")


if __name__ == "__main__":
    main()
