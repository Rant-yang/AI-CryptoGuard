import argparse
import json
import os
import sys
from pathlib import Path

import anthropic

# 把项目根目录加入 Python 模块搜索路径
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.rules.pqc_routing import route


# AI 允许返回的 usage
VALID_USAGES = {
    "signing",
    "encryption",
    "key_exchange",
    "hashing",
    "authentication",
    "tls_configuration",
    "unknown",
}


SYSTEM_PROMPT = """
你是 AI-CryptoGuard 的密码学代码分析助手。

你的任务是分析 scanner 产生的 Finding。

你需要重点判断：
1. 当前发现的密码学算法实际上用于什么用途；
2. 给出简洁、基于证据的风险解释。

usage 只能从以下值中选择：
- signing
- encryption
- key_exchange
- hashing
- authentication
- tls_configuration
- unknown

重要规则：
- 不要根据算法名称直接猜用途。
- 如果证据不足，使用 unknown。
- RSA、ECC、ECDSA、ECDH 等算法必须结合代码证据判断用途。
- 仅仅出现 import、类名或变量名，不能证明具体用途。
- 例如 RSA 出现在 import 中，并不代表 RSA 用于 hashing。
- 不要决定 PQC 替换算法。
- 不要生成 remediation。
- 只返回 JSON，不要返回 Markdown。

JSON 格式：
{
  "usage": "...",
  "explanation": "..."
}
"""


def call_llm(finding):
    """调用 DeepSeek，返回 usage 和 explanation。"""
    client = anthropic.Anthropic(
        api_key=os.environ["ANTHROPIC_AUTH_TOKEN"]
    )

    user_prompt = json.dumps(
        {
            "algorithm": finding.get("algorithm"),
            "algorithm_normalized": finding.get("algorithm_normalized"),
            "current_usage": finding.get("usage"),
            "risk": finding.get("risk"),
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
            "tags": finding.get("tags", []),
            "evidence": finding.get("evidence", []),
        },
        ensure_ascii=False,
        indent=2,
    )

    response = client.messages.create(
        model=os.environ["ANTHROPIC_MODEL"],
        max_tokens=500,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": user_prompt,
            }
        ],
    )

    # DeepSeek 可能返回 ThinkingBlock + TextBlock。
    # 我们只取真正的文本块。
    text_parts = [
        block.text
        for block in response.content
        if getattr(block, "type", None) == "text"
    ]

    if not text_parts:
        raise RuntimeError("LLM 没有返回文本结果。")

    raw_text = "\n".join(text_parts).strip()

    return json.loads(raw_text)


def enrich_finding(finding):
    """增强单个 finding。"""
    ai_result = call_llm(finding)

    usage = ai_result.get("usage", "unknown")

    if usage not in VALID_USAGES:
        usage = "unknown"

    finding["usage"] = usage
    finding["explanation"] = ai_result.get(
        "explanation",
        "AI 未能生成解释。"
    )

    # PQC 路由由规则库决定，不交给 LLM 自由生成。
    finding["remediation"] = route(
        finding["algorithm"],
        finding["usage"],
        finding.get("algorithm_normalized"),
    )

    return finding


def main():
    parser = argparse.ArgumentParser(
        description="AI-CryptoGuard AI finding enrichment"
    )
    parser.add_argument("input", help="输入 findings.json")
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="输出 findings_ai.json",
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    with input_path.open("r", encoding="utf-8-sig") as f:
        findings = json.load(f)

    if not isinstance(findings, list):
        raise ValueError("输入 JSON 必须是 Finding 数组。")

    enriched = []

    for index, finding in enumerate(findings, start=1):
        print(
            f"[AI] 正在处理 {index}/{len(findings)}: "
            f"{finding.get('finding_id', 'unknown')}"
        )

        enriched.append(enrich_finding(finding))

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(
            enriched,
            f,
            ensure_ascii=False,
            indent=2,
        )

    print(f"[OK] 输出完成: {output_path}")


if __name__ == "__main__":
    main()