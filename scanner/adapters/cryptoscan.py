"""CryptoScan adapter —— 调用工具并把输出转成 scanner 内部分组。

CryptoScan 在流水线里的角色（scanner/README.md 的定位）是**补充源**：
它的 purpose（用途）比 cbom-scan 的 prim 细，severity / confidence 可用，
type 的元数据（实测值域 78 种，zh_map 初版覆盖 25 种）后续由 C 搬进
core/rules/ 规则库。

实测踩过的坑（setup/README.md / scanner/README.md，本机 2026-09-30 复测属实）:
    1. 只要有密码发现就返回 exit 1（没设 --fail-on 也这样）——
       绝不能用退出码判成败，改为「输出文件存在 + JSON 可解析」。
    2. 加了 --output 之后屏幕静默是正常的，内容全进了文件。
    3. file 是绝对路径（反斜杠），必须剥成项目内相对路径。
    4. findings[].severity 是整数 0-4；summary.bySeverity 的键是字符串 ——
       只取 findings 一侧，不碰 summary。

调用形态:
    cryptoscan.exe scan <目标目录> --format json --output <文件>
"""
import json
import os
import subprocess

from scanner.normalize import (
    CONFIDENCE_MAP,
    CRYPTOSCAN_PURPOSE_TO_USAGE,
    CRYPTOSCAN_QUANTUM_RISK_AS_SEEN,
    CRYPTOSCAN_SEVERITY_TO_ENUM,
    SEVERITY_ORDER,
    canon_algorithm,
    norm_algorithm,
    to_relative_path,
)
from scanner.adapters.source_filter import keep_record

TOOL_NAME = 'cryptoscan'

#: finding 级字段里逐字保留进 raw 的部分。
#: 刻意排除三块（体积与职责，不是加工）:
#:   - sourceContext: 每条 7 行源码上下文，180KB 输出的大头，调试走 raw 文件
#:   - description / remediation / impact / effort: type 级的公共元数据
#:     （同一 type 的所有 finding 重复同一份），按 README 的定位由 C 搬进
#:     core/rules/，不在每条证据里重复
#:   - tags: 工具自家标签，与我们的 tags 语义无关
RAW_FIELDS = (
    'id', 'type', 'findingType', 'category', 'algorithm', 'primitive',
    'migrationStatus', 'file', 'line', 'column', 'match', 'context',
    'severity', 'quantumRisk', 'confidence', 'purpose', 'language',
)


class ToolError(RuntimeError):
    """工具没找到 / 没跑起来 / 输出无法解析。"""


def find_tool(tools_dir, platform_name=None):
    """Find the OS-specific binary under an external tools directory."""
    name = 'cryptoscan.exe' if (platform_name or os.name) == 'nt' else 'cryptoscan'
    cands = [
        os.path.join(tools_dir, 'cryptoscan', name),
        os.path.join(tools_dir, name),
    ]
    for cand in cands:
        if os.path.isfile(cand):
            return cand
    raise ToolError(
        '找不到 cryptoscan。期望位置之一: %s\n'
        '安装方式见 setup/README.md（工具本体不入库，需自行下载到 tools/）。'
        % ' ; '.join(cands))


def run(target, tools_dir, raw_out=None, timeout=300):
    """跑一次扫描，返回解析后的 JSON dict。

    JSON 落在 raw_out 指定的文件里（这就是我们传给 --output 的路径），
    成败判定 = 文件存在且可解析；退出码被显式忽略（见模块 docstring 坑 1）。
    raw_out 为空时落到临时目录（调用方不想保留原始输出时用）。
    """
    exe = find_tool(tools_dir)
    if raw_out is None:
        import tempfile
        raw_out = os.path.join(
            tempfile.mkdtemp(prefix='acg-cryptoscan-'), 'cryptoscan.json')
    raw_out = os.path.abspath(raw_out)
    os.makedirs(os.path.dirname(raw_out), exist_ok=True)
    # 同目录重跑时，上次留下的同名文件必须先删：本次工具若失败根本不写文件，
    # 不删的话下面「文件存在即成功」会把**上一次的旧 JSON**当成本次结果读进来
    if os.path.isfile(raw_out):
        os.remove(raw_out)

    cmd = [exe, 'scan', os.path.abspath(target),
           '--format', 'json', '--output', raw_out]
    try:
        # check=False 是故意的：有发现时 exit 1，退出码不代表成败
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                              check=False)
    except FileNotFoundError:
        raise ToolError('无法执行 %s' % exe)
    except subprocess.TimeoutExpired:
        raise ToolError('cryptoscan 超时（%s 秒）。' % timeout)

    if not os.path.isfile(raw_out):
        raise ToolError('cryptoscan 未产出 JSON（%s 不存在）。exit=%s stderr: %s'
                        % (raw_out, proc.returncode,
                           proc.stderr.decode('utf-8', 'replace')[:300]))
    try:
        with open(raw_out, encoding='utf-8') as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        raise ToolError('cryptoscan 输出无法解析: %s' % exc)


def to_groups(data, target):
    """CryptoScan JSON -> ToolGroup 列表（分组单位与 cbom_scan 相同）。

    algorithm 为空的 finding（TLS 配置 / 证书 / 硬编码密钥类）**不再退化成
    拿 type 当算法名**（2026-10-08 任务 2：type 回答「发现了什么问题」，
    不是「用了什么算法」，实测 45 条误报 + 报告出「算法: Mutual TLS (mTLS)」
    这种洋相）。这类发现保留（C 的凭据检测要用线索），但分组键用 TYPE:
    前缀 —— 明显不是算法、不会被 startswith 系列规则误判、同文件不同
    type 也不撞桶；merge 输出时算法字段如实留空并打 no-algorithm 标记。
    """
    buckets = {}
    findings = data.get('findings') or []
    if not isinstance(findings, list):
        # 上游格式变化（findings 不是数组）时安全归零，不迭代字符串炸掉
        findings = []
    for f in findings:
        algo_raw = f.get('algorithm') or ''
        if algo_raw:
            alg_norm = canon_algorithm(algo_raw)
        else:
            t = f.get('type') or ''
            if not t:
                continue        # 无 algorithm 也无 type：定位不了任何东西
            alg_norm = 'TYPE:' + norm_algorithm(t)
        usage = CRYPTOSCAN_PURPOSE_TO_USAGE.get(f.get('purpose', ''), 'unknown')
        rel = to_relative_path(f.get('file'), target)
        line = f.get('line')
        if not rel or not isinstance(line, int) or line < 1:
            continue
        # 过滤字符串/注释提及（帮助文本、密码套件名、枚举表等）：算法名作为
        # 密码学 API 参数 / 变换描述符 / 常量右值 / 代码符号仍会保留。
        rec = {k: f.get(k) for k in RAW_FIELDS}
        if not keep_record(rec):
            continue
        key = (rel, alg_norm, usage)
        g = buckets.get(key)
        if g is None:
            g = {
                'tool': TOOL_NAME,
                'file': rel,
                'alg_norm': alg_norm,
                'algorithm': algo_raw,
                'usage': usage,
                'lines': [],
                # 组内取最大（schema 合并规则：severity/confidence 取最大值）
                'severity': None,
                'confidence': None,
                'risk': None,             # 不透传 quantumRisk（见 normalize.py）
                'risk_types': [],         # type 落到 RISK_BY_TYPE 做兜底裁决
                'quantum_as_seen': [],    # 字面翻译，仅用于打纠正标记
                'raw': {'records': []},
            }
            buckets[key] = g
        g['lines'].append(line)
        sev = CRYPTOSCAN_SEVERITY_TO_ENUM.get(f.get('severity'))
        if sev is not None:
            if g['severity'] is None or SEVERITY_ORDER[sev] > SEVERITY_ORDER[g['severity']]:
                g['severity'] = sev
        conf = CONFIDENCE_MAP.get(f.get('confidence'))
        if conf is not None and (g['confidence'] is None or conf > g['confidence']):
            g['confidence'] = conf
        if f.get('type'):
            g['risk_types'].append(f['type'])
        qr = CRYPTOSCAN_QUANTUM_RISK_AS_SEEN.get(f.get('quantumRisk'))
        if qr:
            g['quantum_as_seen'].append(qr)
        g['raw']['records'].append(rec)

    # ---- 同 (file, alg) 的 usage 摆动合流 ----
    # purpose 是逐行启发式: 同文件同算法的命中行常被拆成 authentication/
    # encryption 两个桶（PBKDF2 实测高发）——那不是两种用途, 是同一处使用
    # 的判定摆动。计数单位 (file, algorithm) 之下它只能是一条: 合到**行数
    # 最多的具体用途**桶, 行号与上游记录全并, severity/confidence 照取 max。
    # unknown 桶的行留给 merge 的行号吸收按精确行号细分 —— 不到那一步不猜。
    by_falg = {}
    for g in buckets.values():
        by_falg.setdefault((g['file'], g['alg_norm']), []).append(g)
    for same in by_falg.values():
        if len(same) < 2:
            continue
        specific = [g for g in same if g['usage'] != 'unknown']
        if not specific:
            continue
        main = max(specific, key=lambda g: (len(g['lines']), g['usage']))
        for g in same:
            if g is main:
                continue
            main['lines'] += g['lines']
            if g['severity'] is not None and (
                    main['severity'] is None or
                    SEVERITY_ORDER[g['severity']] > SEVERITY_ORDER[main['severity']]):
                main['severity'] = g['severity']
            if g['confidence'] is not None and (
                    main['confidence'] is None or
                    g['confidence'] > main['confidence']):
                main['confidence'] = g['confidence']
            main['risk_types'] += g['risk_types']
            main['quantum_as_seen'] += g['quantum_as_seen']
            main['raw']['records'] += g['raw']['records']
            g['lines'] = []          # 置空 = 后续过滤掉该组

    groups = []
    for g in buckets.values():
        if not g['lines']:
            continue
        g['lines'] = sorted(set(g['lines']))
        g['risk_types'] = sorted(set(g['risk_types']))
        g['quantum_as_seen'] = sorted(set(g['quantum_as_seen']))
        groups.append(g)
    return groups
