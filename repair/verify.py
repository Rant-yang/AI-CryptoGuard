"""CLI：在临时副本执行 3 类 Repair -> Verify。"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from repair.engine import repair_and_verify  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('source', help='要验证的 Python 文件（原文件不会修改）')
    ap.add_argument('-o', '--output', default='out/repair_report.json')
    ap.add_argument('--tools-dir', help='可选：用正式 scanner 对临时副本重新扫描')
    ap.add_argument('--project-root',
                    help='可选：信任此项目时，在两份临时副本分别执行 tests/ 中的 unittest')
    ap.add_argument('--test-timeout', type=int, default=120,
                    help='每次项目测试的超时秒数（默认 120）')
    args = ap.parse_args(argv)
    if args.test_timeout <= 0:
        ap.error('--test-timeout 必须为正数')
    report = repair_and_verify(args.source, args.output, args.tools_dir,
                               args.project_root, args.test_timeout)
    print(json.dumps(report, ensure_ascii=True, indent=2))
    # Exit 0 means structural scan verification only. Project tests remain
    # NOT_RUN and manual review is still required; never imply safe deployment.
    ok = (report['original_unchanged'] and report['syntax'] == 'PASS'
          and report['independent_scan']['status'] == 'COMPLETED'
          and report['new_high_findings'] == 0
          and all(r['scanner_rescan'] == 'ELIMINATED'
                  for r in report['repairs'] if r['original_finding'] == 'PRESENT'))
    if args.project_root:
        ok = (ok and isinstance(report['tests'], dict) and
              report['tests'].get('before') == 'PASS' and
              report['tests'].get('after') == 'PASS')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
