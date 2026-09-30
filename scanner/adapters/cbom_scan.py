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
    to_relative_path,
)

TOOL_NAME = 'cbom-scan'


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
    for asset in data.get('assets', []):
        algo_raw = asset.get('algo', '')
        alg_norm = canon_algorithm(algo_raw)
        usage = CBOM_PRIM_TO_USAGE.get(asset.get('prim', ''), 'unknown')
        # raw 逐字保留 asset 的核心判定字段（与 core/samples/example_finding.json 的
        # cbom raw 口径一致；repl / why 等 asset 级长文本不重复塞进每条证据）
        raw = {k: asset.get(k) for k in ('id', 'algo', 'prim', 'risk')}

        by_file = {}
        for occ in asset.get('occurrences', []):
            rel = to_relative_path(occ.get('file'), target)
            if not rel:
                continue
            by_file.setdefault(rel, []).append(occ.get('line'))

        for rel, lines in by_file.items():
            groups.append({
                'tool': TOOL_NAME,
                'file': rel,
                'alg_norm': alg_norm,
                'algorithm': algo_raw,
                'usage': usage,
                'lines': sorted({ln for ln in lines if isinstance(ln, int) and ln >= 1}),
                'severity': None,           # cbom-scan 没有 severity 概念
                'confidence': None,
                'risk': asset.get('risk'),  # 主源：五档直接可用
                'risk_types': [],           # （cryptoscan 专用字段）
                'quantum_as_seen': [],      # （cryptoscan 专用字段）
                'raw': raw,
            })
    return groups
