"""scanner 主入口 —— 输入一个项目目录，输出统一格式的 findings.json。

验收标准（scanner/README.md）:
    python scanner/scan.py D:\\某个项目 -o out\\findings.json
    python core/schema/validate.py out\\findings.json     # 必须退出码 0

流程:
    定位工具(tools/) -> cbom-scan + CryptoScan 各跑一次 -> 各自转成 ToolGroup
    -> merge 融合 -> 写 findings.json（+ 原始输出与 meta 留档）-> 打印汇总

退出码:
    0  成功（包括「扫描完成但零发现」；单工具失败但另一工具可用时也返回 0，
        会打醒目警告 —— 流水线不该被半路炸掉，但问题必须看得见）
    2  用法 / 环境错误（目录不存在、一个工具都没有）
    3  所有选用的工具都失败

注意:
    - 扫描产物（findings.json / _raw/ / meta）**绝不能 git add** —— 含绝对
      路径与上游抓到的原文（方案 §19）。out/ 目录已按此约定使用。
"""
import argparse
import json
import os
import sys
import time

# 支持 `python scanner/scan.py ...` 直接运行（把仓库根加进 sys.path）
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from scanner.adapters import cbom_scan, cryptoscan   # noqa: E402
from scanner.cbom_report import render_cbom          # noqa: E402
from scanner.coverage import coverage_diff           # noqa: E402
from scanner.merge import merge                       # noqa: E402
from scanner.merge import TAG_UPSTREAM_RISK_CORRECTED  # noqa: E402


def _print_safe(text):
    """中文控制台（GBK）打印兜底：编码不了的字符替换掉，绝不让汇总挂掉。"""
    try:
        print(text)
    except UnicodeEncodeError:
        sys.stdout.buffer.write(text.encode('gbk', errors='replace'))
        sys.stdout.buffer.write(b'\n')


def find_tools_dir(explicit):
    """工具目录定位: --tools-dir > 环境变量 ACG_TOOLS_DIR > <仓库根>/tools/。"""
    if explicit:
        return explicit
    env = os.environ.get('ACG_TOOLS_DIR')
    if env:
        return env
    return os.path.join(_ROOT, 'tools')


def run_tool(adapter, target, tools_dir, raw_path, timeout):
    """跑一个工具，返回 (data, groups)。失败抛 adapter.ToolError。"""
    data = adapter.run(target, tools_dir, raw_out=raw_path, timeout=timeout)
    groups = adapter.to_groups(data, target)
    return data, groups


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='scanner/scan.py',
        description='输入一个项目目录，输出统一 Finding 格式（core/schema v0.1）'
                    '的问题清单 findings.json')
    parser.add_argument('target', help='要扫描的项目目录')
    parser.add_argument('-o', '--output', default='out/findings.json',
                        help='输出文件（默认 out/findings.json）')
    parser.add_argument('--tools-dir', default=None,
                        help='工具目录（默认 <仓库根>/tools/ 或环境变量 ACG_TOOLS_DIR）')
    parser.add_argument('--tool', choices=['both', 'cbom-scan', 'cryptoscan'],
                        default='both', help='选用哪些工具（默认 both）')
    parser.add_argument('--timeout', type=int, default=300,
                        help='单个工具的超时秒数（默认 300）')
    parser.add_argument('--no-raw', action='store_true',
                        help='不保留上游原始 JSON（默认保存在 <输出目录>/_raw/）')
    parser.add_argument('--cbom', action='store_true',
                        help='同时输出融合版 CycloneDX 1.6 CBOM（<输出文件>.cbom.json）')
    parser.add_argument('--no-coverage', action='store_true',
                        help='不生成覆盖差异报告（默认写 <输出目录>/coverage_diff.json）')
    args = parser.parse_args(argv)

    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        _print_safe('[错误] 目标目录不存在: %s' % target)
        return 2

    out_path = os.path.abspath(args.output)
    out_dir = os.path.dirname(out_path)
    os.makedirs(out_dir, exist_ok=True)
    raw_dir = None if args.no_raw else os.path.join(out_dir, '_raw')
    if raw_dir:
        os.makedirs(raw_dir, exist_ok=True)

    tools_dir = find_tools_dir(args.tools_dir)

    plan = []
    if args.tool in ('both', 'cbom-scan'):
        plan.append(('cbom-scan', cbom_scan,
                     None if raw_dir is None else os.path.join(raw_dir, 'cbom-scan.json')))
    if args.tool in ('both', 'cryptoscan'):
        plan.append(('cryptoscan', cryptoscan,
                     None if raw_dir is None else os.path.join(raw_dir, 'cryptoscan.json')))

    all_groups = []
    groups_by_tool = {}     # 吸收前的原始分组 —— 覆盖差异审计用
    meta_tools = {}
    failures = []
    t_all = time.time()

    for name, adapter, raw_path in plan:
        t0 = time.time()
        try:
            data, groups = run_tool(adapter, target, tools_dir, raw_path, args.timeout)
        except adapter.ToolError as exc:
            failures.append((name, str(exc)))
            _print_safe('[警告] %s 失败，已跳过: %s' % (name, exc))
            continue
        secs = round(time.time() - t0, 2)
        all_groups.extend(groups)
        groups_by_tool[name] = groups
        meta_tools[name] = {
            'ok': True,
            'seconds': secs,
            'groups': len(groups),
            'raw': raw_path,
            'summary': data.get('summary') if isinstance(data, dict) else None,
        }
        _print_safe('[ok] %s 完成（%.2fs，产出 %d 个工具分组）'
                    % (name, secs, len(groups)))

    if len(failures) == len(plan):
        _print_safe('[错误] 选用的工具全部失败，无法继续。')
        return 3

    findings = merge(all_groups)

    with open(out_path, 'w', encoding='utf-8') as fh:
        json.dump(findings, fh, ensure_ascii=False, indent=1)

    meta = {
        'target': target,
        'tools_dir': tools_dir,
        'tools': meta_tools,
        'failures': {name: msg for name, msg in failures},
        'counts': {
            'tool_groups': len(all_groups),
            'findings': len(findings),
            'by_risk': _count_by(findings, 'risk'),
            'by_severity': _count_by(findings, 'severity'),
            'by_usage': _count_by(findings, 'usage'),
            'multi_evidence': sum(1 for f in findings if len(f['evidence']) > 1),
            'risk_corrected': sum(
                1 for f in findings
                if TAG_UPSTREAM_RISK_CORRECTED in f.get('tags', [])),
        },
        'seconds_total': round(time.time() - t_all, 2),
    }

    # ---- 覆盖差异审计（两家都成功时才有意义）
    cov = None
    if not args.no_coverage and len(groups_by_tool) >= 2:
        cov = coverage_diff(groups_by_tool)
        cov_path = os.path.join(out_dir, 'coverage_diff.json')
        with open(cov_path, 'w', encoding='utf-8') as fh:
            json.dump(cov, fh, ensure_ascii=False, indent=1)
        meta['coverage'] = cov['summary']

    # ---- 融合版 CBOM（可选）
    cbom_path = None
    if args.cbom:
        cbom_path = os.path.splitext(out_path)[0] + '.cbom.json'
        with open(cbom_path, 'w', encoding='utf-8') as fh:
            json.dump(render_cbom(findings, target), fh,
                      ensure_ascii=False, indent=1)
    meta_path = os.path.join(out_dir, os.path.splitext(os.path.basename(out_path))[0]
                             + '.meta.json')
    with open(meta_path, 'w', encoding='utf-8') as fh:
        json.dump(meta, fh, ensure_ascii=False, indent=1)

    _print_summary(findings, meta, out_path, meta_path, cov, cbom_path)
    return 0


def _count_by(findings, field):
    counts = {}
    for f in findings:
        counts[f[field]] = counts.get(f[field], 0) + 1
    return dict(sorted(counts.items()))


def _print_summary(findings, meta, out_path, meta_path, cov=None, cbom_path=None):
    c = meta['counts']
    _print_safe('')
    _print_safe('====== 扫描完成 ======')
    _print_safe('findings      : %d 条（来自 %d 个工具分组）' % (c['findings'], c['tool_groups']))
    _print_safe('按量子风险    : %s' % json.dumps(c['by_risk'], ensure_ascii=True))
    _print_safe('按严重程度    : %s' % json.dumps(c['by_severity'], ensure_ascii=True))
    _print_safe('按用途        : %s' % json.dumps(c['by_usage'], ensure_ascii=True))
    _print_safe('多源证据      : %d 条（同一问题挂了多个工具）' % c['multi_evidence'])
    _print_safe('风险已纠正    : %d 条（上游量子风险判定被我方规则库推翻）' % c['risk_corrected'])
    if cov is not None:
        s = cov['summary']
        _print_safe('覆盖差异      : 双方同报 %d 行 | 仅 cbom-scan %d 行 | 仅 cryptoscan %d 行'
                    % (s.get('both', 0),
                       s.get('cbom-scan_only', 0), s.get('cryptoscan_only', 0)))
        _print_safe('差异明细      : %s'
                    % os.path.join(os.path.dirname(out_path), 'coverage_diff.json'))
    if cbom_path:
        _print_safe('CBOM 输出     : %s' % cbom_path)
    if meta.get('failures'):
        _print_safe('失败工具      : %s' % ', '.join(meta['failures']))
    _print_safe('输出          : %s' % out_path)
    _print_safe('留档          : %s' % meta_path)
    _print_safe('下一步校验    : python core/schema/validate.py "%s"' % out_path)


if __name__ == '__main__':
    sys.exit(main())
