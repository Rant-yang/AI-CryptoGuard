"""cbom-scan adapter —— 调用工具并把输出转成 scanner 内部分组。

cbom-scan 是我们的**模式证据主源**（scanner/README.md 的定位）：
    - risk 五档分类正确（shor / broken / grover / review / safe）
    - occurrences[] 按 (asset, file, line) 组织，天然接近计数单位
    - 它没有 severity / confidence，也不区分用途粒度（prim 粗）

调用形态（setup/README.md）:
    node cbom.js <目标目录> --json     # stdout 是纯 JSON
    退出码恒为 0。

内部分组单位 = (file, algorithm_canon, usage)，
同一 asset 在同一文件的多次命中合并为一个 ToolGroup，行号收进 lines。
"""
import json
import os
import subprocess

from scanner.normalize import (
    CBOM_PRIM_TO_USAGE,
    canon_algorithm,
    norm_algorithm,
    split_combined_algorithm,
    to_relative_path,
)
from scanner.adapters.source_filter import is_string_or_comment_mention

TOOL_NAME = 'cbom-scan'

#: 源文件行读取缓存：cbom-scan 的 occurrence 只带 (file, match, line)，
#: 没有整行上下文，判断 match 是否落在字符串/注释里需要读源文件。
_file_lines_cache = {}


def _read_line(target, rel, lineno):
    """读 target/rel 的第 lineno 行（1 基）。失败返回 None。"""
    # 同一 Web 进程会连续扫描多个项目；只用 rel 做键会把前一项目的
    # src/main.py 错套到后一项目的同名文件上。
    cache_key = (os.path.abspath(target), rel)
    lines = _file_lines_cache.get(cache_key)
    if lines is None:
        try:
            with open(os.path.join(target, rel), encoding='utf-8-sig',
                      errors='replace') as fh:
                lines = fh.read().splitlines()
        except OSError:
            lines = []
        _file_lines_cache[cache_key] = lines
    if not lines or lineno < 1 or lineno > len(lines):
        return None
    return lines[lineno - 1]


def _match_mention(linetext, match):
    """cbom 的 match 可能把引号一起匹配进来（'"DES"'），剥外层引号再判。"""
    m = str(match or '')
    if len(m) >= 2 and m[0] in ('"', "'") and m[-1] == m[0]:
        m = m[1:-1]
    return is_string_or_comment_mention(linetext, m)

#: cbom-scan 把 Ed25519 / X25519 捆成一个 asset 且 prim=signature ——
#: 对 Ed25519（签名）那半是对的，对 X25519（密钥交换）那半是错的。
#: occurrence 的 match 是命中的具体词，**行级可确定细分**，不需要猜：
#:     ed25519 -> signing     x25519 -> key_exchange     其他 -> 保持组级映射
#: 这是唯一做行级细分的捆绑 asset；判不出的 match 一律回落，不硬判。
_ED25519_ASSET_NORM = 'ED25519X25519'
_MATCH_REFINED_USAGE = {'ED25519': 'signing', 'X25519': 'key_exchange'}


def _refine_usage_by_match(alg_norm, usage, match):
    # ECDSA / EC 是 cbom 的家族级 asset，prim=signature 不能覆盖曲线名命中。
    # prime256v1 / secp256r1 只说明曲线；与 CryptoScan 的 createECDH
    # 同行时留 unknown 给 merge 的精确行号吸收，不伪称签名证据。
    if alg_norm == 'ECC' and usage == 'signing':
        token = norm_algorithm(match)
        if token == 'ECDSA':
            return 'signing'
        if token == 'ECDH':
            return 'key_exchange'
        return 'unknown'
    if alg_norm != _ED25519_ASSET_NORM:
        return usage
    token = ''.join(ch for ch in str(match or '').upper() if ch.isalnum())
    return _MATCH_REFINED_USAGE.get(token, usage)


class ToolError(RuntimeError):
    """工具没找到 / 没跑起来 / 输出无法解析。"""


def find_tool(tools_dir):
    """定位 cbom.js。约定布局: <tools_dir>/cbom-scan/cbom.js（tools/ 不入库）。"""
    cand = os.path.join(tools_dir, 'cbom-scan', 'cbom.js')
    if os.path.isfile(cand):
        return cand
    raise ToolError(
        '找不到 cbom-scan。期望位置: %s\n'
        '安装方式见 setup/README.md（工具本体不入库，需自行下载到 tools/）。' % cand)


def run(target, tools_dir, raw_out=None, timeout=300):
    """跑一次扫描，返回解析后的 JSON dict。

    stdout 直接就是机器可读 JSON（--json）。为稳妥起见，
    解析失败时尝试截取首尾大括号之间的内容再试一次（防上游混入提示文本）。
    """
    cbom_js = find_tool(tools_dir)
    cmd = ['node', cbom_js, os.path.abspath(target), '--json']
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            cwd=os.path.dirname(cbom_js))
    except FileNotFoundError:
        raise ToolError('找不到 node 可执行文件 —— cbom-scan 依赖 Node。')
    except subprocess.TimeoutExpired:
        raise ToolError('cbom-scan 超时（%s 秒）。' % timeout)

    # cbom-scan 退出码恒为 0，这里仍兜底检查，不把退出码当唯一成败依据
    out = proc.stdout.decode('utf-8', errors='replace').strip()
    if not out:
        raise ToolError(
            'cbom-scan 没有输出。stderr: %s' % proc.stderr.decode('utf-8', 'replace')[:300])
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        start, end = out.find('{'), out.rfind('}')
        if start < 0 or end <= start:
            raise ToolError('cbom-scan 输出不是合法 JSON（前 200 字符: %s）' % out[:200])
        data = json.loads(out[start:end + 1])

    if raw_out:
        os.makedirs(os.path.dirname(os.path.abspath(raw_out)), exist_ok=True)
        with open(raw_out, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, ensure_ascii=False, indent=1)
    return data


def to_groups(data, target):
    """cbom-scan JSON -> ToolGroup 列表。

    一个 ToolGroup = 一个 (file, 归一化算法, usage) 的工具侧证据，
    字段约定见 merge.py 的 docstring。
    """
    groups = []
    assets = data.get('assets') or []
    if not isinstance(assets, list):
        # 上游格式变化（assets 不是数组）时安全归零，不迭代字符串炸掉
        assets = []
    for asset in assets:
        algo_raw = asset.get('algo', '')
        # 合并名拆词（2026-10-08 任务 1）: "Legacy cipher (Blowfish/CAST5/IDEA/SEED)"
        # 这类 asset 是多个并列算法的合并名，归一化会压成一坨永远匹配不上标签
        # （实测 94 条误报）。拆成候选后**每个算法各产出独立 ToolGroup**，
        # 与 schema 计数单位「一条 finding = (file, 算法, 用途)」对齐。
        # 带括号才拆、拆出的段必须像算法 token（详见函数 docstring）。
        candidates = split_combined_algorithm(algo_raw)
        usage = CBOM_PRIM_TO_USAGE.get(asset.get('prim', ''), 'unknown')
        # raw 逐字保留 asset 的核心判定字段（与 core/samples/example_finding.json 的
        # cbom raw 口径一致；algo 保留**原始合并名**供溯源，repl / why 等
        # asset 级长文本不重复塞进每条证据）
        raw = {k: asset.get(k) for k in ('id', 'algo', 'prim', 'risk')}

        # 拆开后每个候选**只继承点名自己的命中**（match 归一后与候选归一相等）。
        # 实测（2026-10-09 cryptoapi-bench）: 只用 Blowfish 的文件，拆开的
        # CAST5/IDEA/SEED 若继承全部命中会各成一条误报 —— 每个文件 1 条变 3 条。
        # match 对不上任何候选（说明性 match，如 'SSH'）或缺 match 时，
        # 保守归给全部候选 —— 行为退回拆词前，绝不丢真命中。
        tok_to_cands = {}
        for cand in candidates:
            tok_to_cands.setdefault(norm_algorithm(cand), []).append(cand)
        if candidates == ['DES', '3DES']:
            for spelling in ('TRIPLE-DES', 'TRIPLEDES', 'DESede'):
                tok_to_cands[norm_algorithm(spelling)] = ['3DES']

        # cand -> (file, usage) -> lines
        by_cand = {cand: {} for cand in candidates}
        for occ in asset.get('occurrences', []):
            rel = to_relative_path(occ.get('file'), target)
            if not rel:
                continue
            match = occ.get('match')
            line = occ.get('line')
            # 过滤字符串/注释提及（帮助文本、密码套件名、枚举表、import 路径等）：
            # 算法名作为密码学 API 参数 / 变换描述符 / 常量右值仍会保留。
            if match and isinstance(line, int):
                linetext = _read_line(target, rel, line)
                if linetext is not None and _match_mention(linetext, match):
                    continue
            tok = norm_algorithm(match) if match else ''
            owners = tok_to_cands.get(tok) if tok else None
            if owners is None:
                owners = candidates
            for cand in owners:
                alg_norm = canon_algorithm(cand)
                # 分组键是 (file, usage)：Ed25519/X25519 捆绑 asset 会被 match
                # 细分成不同用途的组 —— 与计数单位 (file, alg, usage) 对齐
                occ_usage = _refine_usage_by_match(alg_norm, usage, match)
                by_cand[cand].setdefault((rel, occ_usage), []).append(occ.get('line'))

        for cand in candidates:
            alg_norm = canon_algorithm(cand)
            by_group = by_cand[cand]

            for (rel, occ_usage), lines in by_group.items():
                clean = sorted({ln for ln in lines
                                if isinstance(ln, int) and ln >= 1})
                if not clean:
                    # 该文件全部命中行号非法 —— 一个真实命中都没有的组不许流出：
                    # 空行组会骗过 coverage 的算法级覆盖统计（算法没命中却算覆盖）
                    continue
                groups.append({
                    'tool': TOOL_NAME,
                    'file': rel,
                    'alg_norm': alg_norm,
                    'algorithm': cand,       # 拆出的具体算法名（未拆时 == algo_raw）
                    'usage': occ_usage,
                    'lines': clean,
                    'severity': None,        # cbom-scan 没有 severity 概念
                    'confidence': None,
                    'risk': asset.get('risk'),   # 主源：五档直接可用
                    'risk_types': [],            # （cryptoscan 专用字段）
                    'quantum_as_seen': [],       # （cryptoscan 专用字段）
                    'raw': raw,
                })
    return groups
