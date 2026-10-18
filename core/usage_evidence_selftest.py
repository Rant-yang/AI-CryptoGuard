"""Offline contract check for bounded Java JCA consumer evidence."""
import tempfile
from pathlib import Path

from ai.redact import redact_evidence
from core.usage_evidence import attach_java_consumers


def main():
    with tempfile.TemporaryDirectory(prefix='acg-jca-consumer-') as tmp:
        root = Path(tmp)
        (root / 'Signing.java').write_text(
            '// Signature.getInstance("SHA1withRSA");\n'
            'String decoy = "Signature.getInstance(\\\"SHA1withRSA\\\")";\n'
            '/* KeyAgreement.getInstance("ECDH"); */\n'
            'Signature signer = Signature.getInstance("SHA256withRSA");\n'
            'signer.initSign(privateKey);\n'
            'signer.sign();\n}\n', encoding='utf-8')
        (root / 'Agreement.java').write_text(
            'KeyAgreement exchange = KeyAgreement.getInstance("ECDH");\n'
            'exchange.init(privateKey);\n'
            'exchange.doPhase(peerKey, true);\n'
            'exchange.generateSecret();\n}\n', encoding='utf-8')
        (root / 'TextBlock.java').write_text(
            'String note = """\n'
            'Signature x = Signature.getInstance("SHA256withRSA");\n'
            'x.initSign(key); x.sign();\n'
            '""";\n', encoding='utf-8')
        (root / 'Cipher.java').write_text(
            'String decoy = "Cipher.getInstance(\\\"AES/ECB/PKCS5Padding\\\")";\n'
            'Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");\n'
            'String trick = "cipher.init(Cipher.ENCRYPT_MODE, key)";\n'
            'other.init(Cipher.ENCRYPT_MODE, key);\n'
            'cipher.init(Cipher.ENCRYPT_MODE, key);\n}\n', encoding='utf-8')
        (root / 'CipherDecoy.java').write_text(
            'Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");\n'
            'other.init(Cipher.ENCRYPT_MODE, key);\n}\n', encoding='utf-8')
        rows = [
            {'file': 'Signing.java', 'algorithm_normalized': 'RSA', 'usage': 'signing',
             'evidence': [{'tool': 'cbom-scan', 'lines': [4]}]},
            {'file': 'Agreement.java', 'algorithm_normalized': 'ECDH',
             'usage': 'key_exchange',
             'evidence': [{'tool': 'cbom-scan', 'lines': [1]}]},
            {'file': 'Agreement.java', 'algorithm_normalized': 'ECC', 'evidence': []},
            {'file': '../Signing.java', 'algorithm_normalized': 'RSA', 'evidence': []},
            {'file': 'Signing.java', 'algorithm_normalized': 'RSA',
             'usage': 'encryption', 'evidence': [{'tool': 'cbom-scan', 'lines': [4]}]},
            {'file': 'Signing.java', 'algorithm_normalized': 'RSA',
             'usage': 'signing', 'evidence': [{'tool': 'cbom-scan', 'lines': [100]}]},
            {'file': 'TextBlock.java', 'algorithm_normalized': 'RSA',
             'usage': 'signing', 'evidence': [{'tool': 'cbom-scan', 'lines': [2]}]},
            {'file': 'Cipher.java', 'algorithm_normalized': 'AESECB',
             'usage': 'encryption', 'evidence': [{'tool': 'cryptoscan', 'lines': [2]}]},
            {'file': 'CipherDecoy.java', 'algorithm_normalized': 'AESECB',
             'usage': 'encryption', 'evidence': [{'tool': 'cryptoscan', 'lines': [1]}]},
        ]
        assert attach_java_consumers(rows, root) == 7
        assert [(r['evidence'][1]['lines'], r['evidence'][1]['raw']['api'])
                for r in rows[:2]] == [([4], 'Signature.getInstance'),
                                       ([1], 'KeyAgreement.getInstance')]
        assert rows[0]['evidence'][2]['lines'] == [6]
        assert rows[0]['evidence'][2]['raw']['api'] == 'Signature.sign'
        assert rows[1]['evidence'][2]['lines'] == [4]
        assert rows[1]['evidence'][2]['raw']['api'] == 'KeyAgreement.generateSecret'
        assert not rows[2]['evidence'] and not rows[3]['evidence']
        assert len(rows[4]['evidence']) == len(rows[5]['evidence']) == 1
        assert len(rows[6]['evidence']) == 1
        assert [(e['lines'], e['raw']['api']) for e in rows[7]['evidence'][1:]] == [
            ([2], 'Cipher.getInstance'), ([5], 'Cipher.init(ENCRYPT_MODE)')]
        assert [(e['lines'], e['raw']['api']) for e in rows[8]['evidence'][1:]] == [
            ([1], 'Cipher.getInstance')]
        assert attach_java_consumers(rows, root) == 0  # idempotent
        safe = redact_evidence(rows[0]['evidence'][1], 'shape')
        assert safe['call_shape'] == ['Signature.getInstance']
        assert 'raw' not in safe and 'SHA256withRSA' not in str(safe)
        unsafe = {'tool': 'local-literal', 'kind': 'pattern', 'lines': [1],
                  'raw': {'kind': 'java-jca-consumer', 'api': 'secret.example()'}}
        assert redact_evidence(unsafe, 'shape')['call_shape'] == []
        cipher_safe = redact_evidence(rows[7]['evidence'][2], 'shape')
        assert cipher_safe['call_shape'] == ['Cipher.init(ENCRYPT_MODE)']
        assert 'raw' not in cipher_safe and 'key' not in str(cipher_safe)
    print('PASS: Java JCA consumer evidence is bounded, source-free and idempotent')


if __name__ == '__main__':
    main()
