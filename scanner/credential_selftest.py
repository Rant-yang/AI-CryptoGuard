"""凭据检测器自检：8 类覆盖、Schema 合规、零明文泄露。"""
import json
import os
import sys
import tempfile

import jsonschema

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scanner.adapters import credential_scan  # noqa: E402


FIXTURE = '''
password = "OnlyForSyntheticTest!"
default_password = "admin123"
api_token = "TokAbc1234567890SyntheticValue"
aes_key = "00112233445566778899AABBCCDDEEFF"
-----BEGIN PRIVATE KEY-----
db_url = "postgres://demo:syntheticpass@localhost/app"
logger.info(password)
'''

NEGATIVE = '''
# password = "CommentMustNotTrigger"
password = os.getenv("APP_PASSWORD")
api_token = "${API_TOKEN}"
key = generate_key()
'''

FORBIDDEN = (
    'OnlyForSyntheticTest!', 'admin123',
    'TokAbc1234567890SyntheticValue',
    '00112233445566778899AABBCCDDEEFF',
    'syntheticpass',
)


def main():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, 'fixture.py')
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(FIXTURE)
        with open(os.path.join(td, 'negative.py'), 'w', encoding='utf-8') as fh:
            fh.write(NEGATIVE)
        first = credential_scan.scan(td)
        second = credential_scan.scan(td)

    rules = {f['rule_id'] for f in first}
    missing = set(credential_scan.RULES) - rules
    assert not missing, '未命中的凭据类别: %s' % sorted(missing)
    assert len(credential_scan.RULES) == 8

    # 进程随机 HMAC 会变化，但位置派生的 finding_id 必须稳定，便于 diff。
    assert [f['finding_id'] for f in first] == [f['finding_id'] for f in second]
    assert [f['evidence'][0]['raw']['fingerprint'] for f in first] != [
        f['evidence'][0]['raw']['fingerprint'] for f in second]

    rendered = json.dumps(first, ensure_ascii=False)
    for secret in FORBIDDEN:
        assert secret not in rendered, '输出泄露了合成凭据: %s' % secret
    assert all(f['finding_kind'] == 'credential' for f in first)
    assert all(f['risk'] == 'not_applicable' for f in first)
    assert all(f['evidence_refs'] == ['E1'] for f in first)
    assert all(f['remediation']['source'] == 'rule-base' for f in first)
    assert not any(f['file'] == 'negative.py' for f in first), \
        '注释、环境变量、占位符或函数返回值被误报'

    schema_path = os.path.join(ROOT, 'core', 'schema', 'finding.v0.1.json')
    with open(schema_path, encoding='utf-8') as fh:
        schema = json.load(fh)
    jsonschema.Draft7Validator.check_schema(schema)
    validator = jsonschema.Draft7Validator(schema)
    for finding in first:
        validator.validate(finding)

    print('[PASS] credential-scan 自检通过（8 类规则；输出零明文；ID 稳定）')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
