"""校验 findings JSON 是否合规于统一 Finding 格式。

用法（在仓库根目录或任意位置都行）:
    python core/schema/validate.py core/samples/example_finding.json
    python core/schema/validate.py out/findings.json

退出码: 0 = 全部合规, 1 = 有不合规项, 2 = 用法/环境错误。

依赖 jsonschema（没装会给出安装提示）:
    pip install jsonschema
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(HERE, 'finding.v0.1.json')


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    target = sys.argv[1]
    if not os.path.exists(target):
        print('[ERROR] 找不到文件: %s' % target)
        return 2

    try:
        import jsonschema
    except ImportError:
        print('[ERROR] 缺少依赖 jsonschema。安装:  pip install jsonschema')
        return 2

    with open(SCHEMA_PATH, encoding='utf-8') as fh:
        schema = json.load(fh)

    # schema 自身先过一遍，免得 schema 写错了却去怪数据
    try:
        jsonschema.Draft7Validator.check_schema(schema)
    except jsonschema.SchemaError as exc:
        print('[ERROR] schema 本身不合法: %s' % exc.message)
        return 2

    with open(target, encoding='utf-8') as fh:
        data = json.load(fh)

    findings = data if isinstance(data, list) else [data]
    validator = jsonschema.Draft7Validator(schema)

    bad = 0
    for i, f in enumerate(findings):
        errs = sorted(validator.iter_errors(f), key=lambda e: list(e.path))
        if not errs:
            continue
        bad += 1
        label = f.get('finding_id') or '#%d' % i
        print('[FAIL] %s  (%s)' % (label, f.get('file', '?')))
        for e in errs:
            where = '/'.join(str(p) for p in e.path) or '(root)'
            print('        %-28s %s' % (where, e.message))

    print()
    print('共 %d 条, 合规 %d 条, 不合规 %d 条' % (len(findings), len(findings) - bad, bad))
    print('schema: %s' % SCHEMA_PATH)
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
