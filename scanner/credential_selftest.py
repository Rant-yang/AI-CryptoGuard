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
cloud_access_key = "AbCDef0123456789SyntheticOpaqueValue"
aes_key = "00112233445566778899AABBCCDDEEFF"
-----BEGIN PRIVATE KEY-----
db_url = "postgres://demo:syntheticpass@localhost/app"
logger.info(password)
g_key = b"0123456789abcdef"
cipher = AES.new(b"fedcba9876543210", AES.MODE_GCM)
char [] defaultKey = {'a', 'b', 'c'};
'''

NEGATIVE = '''
# password = "CommentMustNotTrigger"
password = os.getenv("APP_PASSWORD")
api_token = "${API_TOKEN}"
key = generate_key()
user_password = input("Enter your password: ")
user_password2 = getpass.getpass("Password: ")
'''

IMPORT_CONTEXT = '''
from Crypto.Cipher import AES
g_key = b"0123456789abcdef"
'''

PASSWORD_CONTEXT = '''
import java.security.KeyStore;
String key = "SyntheticStorePassword";
KeyStore ks = KeyStore.getInstance("JKS");
'''

JAVA_CONSTRUCTOR_NEGATIVE = '''
byte[] keyBytes = generatedKey.getEncoded();
SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "DES");
SecretKeySpec nextSpec = new SecretKeySpec(keyBytes, "DESede");
'''

JAVA_CONSTRUCTOR_POSITIVE = '''
SecretKeySpec spec = new SecretKeySpec("Synthetic16ByteKey", "AES");
'''

MAP_AND_HEADER_POSITIVE = '''
{"api_token": "SyntheticJsonToken9876543210"}
password: 'SyntheticYamlPassword!'
headers = {"Authorization": "Basic dXNlcjpzeW50aGV0aWMtcGFzcw=="}
'''

MAP_AND_HEADER_NEGATIVE = '''
{"api_token": "${TOKEN_FROM_ENV}"}
password: "<SET_AT_RUNTIME>"
headers = {"Authorization": "Bearer ${TOKEN_FROM_ENV}"}
'''

FORBIDDEN = (
    'OnlyForSyntheticTest!', 'admin123',
    'TokAbc1234567890SyntheticValue',
    'AbCDef0123456789SyntheticOpaqueValue',
    '00112233445566778899AABBCCDDEEFF',
    'syntheticpass', '0123456789abcdef', 'fedcba9876543210',
    'Synthetic16ByteKey',
    'SyntheticJsonToken9876543210', 'SyntheticYamlPassword!',
    'dXNlcjpzeW50aGV0aWMtcGFzcw==',
)


def main():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, 'fixture.py')
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(FIXTURE)
        with open(os.path.join(td, 'negative.py'), 'w', encoding='utf-8') as fh:
            fh.write(NEGATIVE)
        with open(os.path.join(td, 'import_context.py'), 'w', encoding='utf-8') as fh:
            fh.write(IMPORT_CONTEXT)
        with open(os.path.join(td, 'password_context.java'), 'w', encoding='utf-8') as fh:
            fh.write(PASSWORD_CONTEXT)
        with open(os.path.join(td, 'java_constructor_negative.java'), 'w', encoding='utf-8') as fh:
            fh.write(JAVA_CONSTRUCTOR_NEGATIVE)
        with open(os.path.join(td, 'java_constructor_positive.java'), 'w', encoding='utf-8') as fh:
            fh.write(JAVA_CONSTRUCTOR_POSITIVE)
        with open(os.path.join(td, 'map_and_header_positive.py'), 'w', encoding='utf-8') as fh:
            fh.write(MAP_AND_HEADER_POSITIVE)
        with open(os.path.join(td, 'map_and_header_negative.py'), 'w', encoding='utf-8') as fh:
            fh.write(MAP_AND_HEADER_NEGATIVE)
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

    # Two distinct values may be recognized at the same coordinate by
    # overlapping patterns. Keep both without deriving a stable ID from a
    # low-entropy secret (which would allow an offline dictionary attack).
    def same_site(pepper):
        return credential_scan._dedup([
            credential_scan._finding('sample.py', 7, 2,
                'CRED-HARDCODED-PASSWORD', value, pepper, kind='pattern')
            for value in ('first-synthetic', 'second-synthetic')
        ])

    pair_a = same_site(b'first-ephemeral-hmac-key')
    pair_b = same_site(b'second-ephemeral-hmac-key')
    assert len(pair_a) == len(pair_b) == 2
    assert len({f['finding_id'] for f in pair_a}) == 2
    assert [f['finding_id'] for f in pair_a] == [f['finding_id'] for f in pair_b]
    assert [f['evidence'][0]['raw']['fingerprint'] for f in pair_a] != [
        f['evidence'][0]['raw']['fingerprint'] for f in pair_b]

    rendered = json.dumps(first, ensure_ascii=False)
    for secret in FORBIDDEN:
        assert secret not in rendered, '输出泄露了合成凭据: %s' % secret
    assert all(f['finding_kind'] == 'credential' for f in first)
    assert all(f['risk'] == 'not_applicable' for f in first)
    assert all(f['evidence_refs'] == ['E1'] for f in first)
    assert all(f['remediation']['source'] == 'rule-base' for f in first)
    assert any(f['file'] == 'import_context.py' and
               f['rule_id'] == 'CRED-HARDCODED-CRYPTO-KEY' for f in first), \
        '密码库导入必须建立通用 key 的上下文'
    assert any(f['file'] == 'password_context.java' and
               f['rule_id'] == 'CRED-HARDCODED-PASSWORD' for f in first), \
        'KeyStore/PBE 上下文里的通用 key 必须按口令裁决'
    assert not any(f['file'] == 'negative.py' for f in first), \
        '注释、环境变量、占位符或函数返回值被误报'
    assert not any(f['file'] == 'java_constructor_negative.java' for f in first), \
        'SecretKeySpec 的算法名参数被误报为硬编码 token'
    assert any(f['file'] == 'java_constructor_positive.java' and
               f['rule_id'] == 'CRED-HARDCODED-CRYPTO-KEY' for f in first), \
        'SecretKeySpec 第一参数的合成硬编码密钥必须继续检出'
    mapped = [f for f in first if f['file'] == 'map_and_header_positive.py']
    assert {f['rule_id'] for f in mapped} >= {
        'CRED-HARDCODED-TOKEN', 'CRED-HARDCODED-PASSWORD'}, \
        'JSON/YAML 凭据键与 HTTP Basic 头必须被检出'
    assert any(f['line'] == 4 and f['rule_id'] == 'CRED-HARDCODED-TOKEN'
               for f in mapped), 'HTTP Basic 头的可逆凭据必须被检出'
    assert not any(f['file'] == 'map_and_header_negative.py' for f in first), \
        '占位符和运行时 Bearer 头被误报'

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
