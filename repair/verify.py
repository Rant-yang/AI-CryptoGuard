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
    args = ap.parse_args(argv)
    report = repair_and_verify(args.source, args.output)
    print(json.dumps(report, ensure_ascii=True, indent=2))
    ok = (report['original_unchanged'] and report['syntax'] == 'PASS'
          and all(r['rescan'] in ('ELIMINATED', 'NOT_PRESENT')
                  for r in report['repairs']))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
