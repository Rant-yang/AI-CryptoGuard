"""AI 增强层主入口 —— 把 scanner 的 finding 补上 usage / explanation / remediation。

    findings.json  ->  调 LLM 判用途  ->  findings_ai.json

设计要点（详见 ai/README.md）：

1. **两段式，红线在 §9.1**：LLM 只判「用途」，算法由 core/rules/pqc_routing.py
   查表给出。LLM 永远不生成算法 —— 见 SYSTEM_PROMPT 与 enrich_finding()。

2. **发出去的东西先脱敏**：见 ai/redact.py。默认 context='full'（发代码行，
   但剥掉绝对路径和疑似凭据）。要回到 §19 的严格口径用 --context shape。

3. **能反复跑**：单条失败不中断、每 N 条落盘、--resume 断点续跑。

变更记录：
    2026-10-03  C（兜底修订，B 复核）
                - 新增脱敏（原样发送证据违反方案 §19）
                - 新增错误处理 / 检查点 / --resume（原来任何一次失败丢全部进度）
                - JSON 解析剥离 ``` 围栏（原来模型一包围栏就崩）
                - 判完用途后清掉过期的 needs-usage-review 标记
                - 新增 --dry-run / --limit / --context
"""
import argparse
import json
import os
import sys
from pathlib import Path

# 把项目根目录加入 Python 模块搜索路径
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.rules.pqc_routing import route

try:
    from ai.redact import redact_finding
except ImportError:                      # 直接 `python redact.py` 式运行时的退路
    from redact import redact_finding


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

#: scanner 打的「用途待复核」标记。AI 复核完就该摘掉（见 _refresh_tags）。
TAG_NEEDS_USAGE_REVIEW = "needs-usage-review"

#: 默认每处理多少条落一次盘。等于总条数时就是「只在最后写一次」。
DEFAULT_CHECKPOINT = 10

#: 单次请求超时（秒）与 SDK 层重试次数。
REQUEST_TIMEOUT = 60.0
MAX_RETRIES = 3

#: 单次响应的 token 上限。
#:
#: 原来写的是 500。实测（2026-10-03 全量真跑）这个数会导致 **16/91 条失败**：
#: 模型是带思维链的，`stop_reason='max_tokens'`、`output_tokens=500`、
#: 内容块只有一个 `thinking`，**预算被推理阶段整个吃光，一个字都没留给答案**。
#: 失败的两种表现都源于此 —— 「没有返回文本结果」（全花在思考上）
#: 和「找不到 JSON 对象」（思考完刚动笔就被截断，花括号配不平）。
MAX_TOKENS = 4000


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

输入字段说明（这些字段是脱敏后的结果，不含用户源码全文）：
- evidence[].call_shape   —— 抽出的方法调用链，如 "Cipher.getInstance"。
                              这是判断用途最可靠的线索：
                              Signature.getInstance / Cipher.getInstance /
                              KeyAgreement.getInstance / MessageDigest.getInstance /
                              Mac.getInstance 分别对应签名 / 加密 / 密钥交换 / 哈希 / 认证。
- evidence[].call_context —— 命中的代码行（已剥掉绝对路径与密钥）。
- evidence[].upstream.prim —— 上游工具给的算法大类，如 pke / hash / block-cipher /
                              signature / kem / key-agree。可直接用作旁证。
- scanner_usage          —— scanner 层的初步判断，可能有误，需要你复核。

JSON 格式：
{
  "usage": "...",
  "explanation": "..."
}
"""


_CLIENT = None


def _client():
    """懒加载单例。原来每条 finding 都新建一个 client，91 条就建 91 次。

    anthropic 也在这里 import —— 于是 `--dry-run` 不装 SDK 也能跑，
    而 dry-run 恰恰是最该能独立跑的那个（§19 合规自查不该有前置依赖）。
    """
    global _CLIENT
    if _CLIENT is None:
        try:
            import anthropic
        except ImportError:
            raise SystemExit(
                "[ERROR] 缺少依赖 anthropic。安装:  pip install -r ai/requirements.txt"
            )
        kwargs = {
            "api_key": os.environ["ANTHROPIC_AUTH_TOKEN"],
            "timeout": REQUEST_TIMEOUT,
            "max_retries": MAX_RETRIES,
        }
        # 指向 DeepSeek 等兼容端点；不设就走 SDK 默认
        base_url = os.environ.get("ANTHROPIC_BASE_URL")
        if base_url:
            kwargs["base_url"] = base_url
        _CLIENT = anthropic.Anthropic(**kwargs)
    return _CLIENT


def _strip_code_fence(text):
    """剥掉 ```json ... ``` 围栏。

    prompt 里写了「不要返回 Markdown」，但模型包围栏是常态 ——
    实测这是原来最常见的崩溃点（json.loads 直接 JSONDecodeError，
    叠加「只在最后写盘」= 前面全部进度蒸发）。
    """
    t = text.strip()
    if not t.startswith("```"):
        return t
    newline = t.find("\n")
    if newline == -1:              # 只有一行 ```json，没有内容
        return t.strip("`").strip()
    t = t[newline + 1:]
    if t.rstrip().endswith("```"):
        t = t.rstrip()[:-3]
    return t.strip()


def _extract_json_object(text):
    """从一段文本里取出第一个配对完整的 {...}。

    比 `text[text.find('{'):text.rfind('}')+1]` 稳：后者遇到模型在
    JSON 前后多写一句话、或字符串里含花括号时会取错范围。
    这里按花括号配对扫，且正确跳过字符串内部的括号与转义。
    """
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def parse_llm_json(raw_text):
    """把模型返回的文本解析成 dict。解析不出来时抛出带原文的异常。"""
    body = _extract_json_object(_strip_code_fence(raw_text))
    if body is None:
        raise ValueError("模型输出里找不到 JSON 对象。原文前 200 字: %r"
                         % raw_text[:200])
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise ValueError("模型输出的 JSON 解析失败: %s。原文前 200 字: %r"
                         % (exc, raw_text[:200]))


def call_llm(finding, context="full", max_tokens=None):
    """调用 DeepSeek，返回 usage 和 explanation。

    发出去的 payload 由 ai/redact.py 构造 —— **这里不做脱敏，
    但也不绕过它**：想改发什么，改 redact.py，别在这里加字段。
    """
    user_prompt = json.dumps(
        redact_finding(finding, context),
        ensure_ascii=False,
        indent=2,
    )

    response = _client().messages.create(
        model=os.environ["ANTHROPIC_MODEL"],
        max_tokens=max_tokens or MAX_TOKENS,
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

    # 截断要**明确报出来**，不要让它伪装成「模型不听话」。
    # 实测 max_tokens=500 时 16/91 条失败，且两种表现（无文本块 /
    # 花括号配不平）根因是同一个 —— 思维链把预算吃光了。
    # 不报 stop_reason 的话，只会看到「找不到 JSON 对象」，查错方向全错。
    if getattr(response, "stop_reason", None) == "max_tokens":
        kinds = [getattr(b, "type", "?") for b in response.content]
        raise RuntimeError(
            "响应被 max_tokens 截断（%d）。内容块=%s。"
            "带思维链的模型会把预算花在思考上，调大 --max-tokens。"
            % (max_tokens or MAX_TOKENS, kinds)
        )

    if not text_parts:
        kinds = [getattr(b, "type", "?") for b in response.content]
        raise RuntimeError("LLM 没有返回文本结果。内容块=%s" % kinds)

    return parse_llm_json("\n".join(text_parts))


def _refresh_tags(finding, usage):
    """AI 复核完用途后，刷新 scanner 打的那个「待复核」标记。

    `needs-usage-review` 的语义是「scanner 判的用途有待复核」。
    AI 复核过了，这个语义就结束了 —— 但若 AI 仍然给 unknown，
    说明用途还是没判出来，标记继续挂着才如实。
    """
    tags = list(finding.get("tags") or [])
    if usage == "unknown":
        if TAG_NEEDS_USAGE_REVIEW not in tags:
            tags.append(TAG_NEEDS_USAGE_REVIEW)
    else:
        tags = [t for t in tags if t != TAG_NEEDS_USAGE_REVIEW]
    if tags:
        finding["tags"] = sorted(tags)
    else:
        finding.pop("tags", None)


def enrich_finding(finding, context="full", max_tokens=None):
    """增强单个 finding。

    先全部算完再落地 —— 保证「要么全改，要么不改」。
    否则 route() 抛异常时会留下「usage 改了但 remediation 还是占位符」
    的半成品，那种条目最难看懂。
    """
    ai_result = call_llm(finding, context, max_tokens)

    usage = ai_result.get("usage", "unknown")
    if usage not in VALID_USAGES:
        usage = "unknown"

    explanation = ai_result.get("explanation", "AI 未能生成解释。")

    # PQC 路由由规则库决定，不交给 LLM 自由生成。
    remediation = route(
        finding["algorithm"],
        usage,
        finding.get("algorithm_normalized"),
    )

    finding["usage"] = usage
    finding["explanation"] = explanation
    finding["remediation"] = remediation
    _refresh_tags(finding, usage)
    return finding


def _is_enriched(finding):
    """这条是否已经增强过。用于 --resume 跳过。

    判据是 remediation.source != 'none' —— 失败的条目会保持 'none'，
    所以 --resume 会自动重试它们，不需要额外的失败清单。
    """
    return (finding.get("remediation") or {}).get("source") != "none" \
        and finding.get("remediation") is not None


def _write(output_path, findings):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(findings, fh, ensure_ascii=False, indent=2)


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
    parser.add_argument(
        "--context",
        choices=("shape", "full"),
        default="full",
        help="发给云端的内容：full=代码行（剥路径与密钥，默认）；"
             "shape=只发方法链，零源码出网（方案 §19 原样口径）",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=MAX_TOKENS,
        help="单次响应 token 上限（默认 %d）。带思维链的模型调小了会被截断"
             % MAX_TOKENS,
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="只处理前 N 条（调试用；0=全部）",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="不调 LLM，只打印会发出去的 payload —— 用于 §19 合规自查",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="输出文件已存在时，跳过其中已增强的条目继续跑",
    )
    parser.add_argument(
        "--checkpoint",
        type=int,
        default=DEFAULT_CHECKPOINT,
        help="每处理 N 条落一次盘（默认 %d）" % DEFAULT_CHECKPOINT,
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.0,
        help="每次调用之间的间隔秒数，用于限流",
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    with input_path.open("r", encoding="utf-8-sig") as fh:
        findings = json.load(fh)

    if not isinstance(findings, list):
        raise ValueError("输入 JSON 必须是 Finding 数组。")

    if args.limit:
        findings = findings[:args.limit]

    # ---------------------------------------------------------- dry-run
    if args.dry_run:
        import redact
        print("[DRY-RUN] 不调用 LLM，也不会写任何文件。")
        print("[DRY-RUN] 输入: %s（%d 条）" % (input_path, len(findings)))
        print()
        print("发往云端的 payload 总量: %d 字符"
              % sum(len(json.dumps(redact_finding(f, args.context),
                                   ensure_ascii=False)) for f in findings))
        print()
        for finding in findings[:3]:
            print("-" * 68)
            print(json.dumps(redact_finding(finding, args.context),
                             ensure_ascii=False, indent=2))
        if len(findings) > 3:
            print("-" * 68)
            print("（只打印前 3 条，共 %d 条）" % len(findings))
        return 0

    # ---------------------------------------------------------- resume
    done = {}
    if args.resume and output_path.exists():
        with output_path.open("r", encoding="utf-8-sig") as fh:
            for prev in json.load(fh):
                if _is_enriched(prev):
                    done[prev.get("finding_id")] = prev
        print("[RESUME] 复用已增强的 %d 条" % len(done))

    enriched = []
    failed = []
    skipped = 0

    for index, finding in enumerate(findings, start=1):
        fid = finding.get("finding_id", "unknown")

        if fid in done:
            skipped += 1
            enriched.append(done[fid])
            continue

        print("[AI] 正在处理 %d/%d: %s" % (index, len(findings), fid))

        try:
            enriched.append(enrich_finding(finding, args.context, args.max_tokens))
        except Exception as exc:                      # noqa: BLE001
            # 单条失败不中断：保持 remediation 占位符（source='none'），
            # 于是进度条天然能数出「还剩几条没增强」，--resume 也会重试它。
            failed.append((fid, "%s: %s" % (type(exc).__name__, exc)))
            enriched.append(finding)

        if args.sleep:
            import time
            time.sleep(args.sleep)

        if args.checkpoint and index % args.checkpoint == 0:
            _write(output_path, enriched)
            print("[CKPT] 已落盘 %d/%d" % (index, len(findings)))

    _write(output_path, enriched)
    print("[OK] 输出完成: %s" % output_path)

    ok = len(enriched) - skipped - len(failed)
    print("[SUM] 增强 %d 条，复用 %d 条，失败 %d 条" % (ok, skipped, len(failed)))
    if failed:
        print("[SUM] 失败的条目仍是占位符（source='none'），"
              "加了 --resume 重跑即可自动重试：")
        for fid, why in failed[:10]:
            print("      %s  %s" % (fid, why[:110]))
        if len(failed) > 10:
            print("      ...另 %d 条" % (len(failed) - 10))
    return 0


if __name__ == "__main__":
    sys.exit(main())
