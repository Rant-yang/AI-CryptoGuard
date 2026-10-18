"""按归一化算法名给出统一五档风险；供没有上游 type 的深度工具使用。

CryptoScan 的 type 仍由 zh_map.json 裁决；CrySentry 只有算法常量时走本模块。
未知值必须返回 review，不猜。
"""
import re

SHOR = ("RSA", "ECC", "ECDSA", "ECDH", "ED25519", "X25519", "EDDSA",
        "DSA", "DH")
BROKEN = ("MD2", "MD4", "MD5", "SHA1", "DES", "3DES", "DESEDE", "RC2",
          "RC4", "RC5", "BLOWFISH", "CAST", "IDEA", "TEA", "XTEA",
          "NULLCIPHER")
GROVER = ("AES", "CHACHA20", "XCHACHA20", "POLY1305", "HMAC", "PBKDF2",
          "BCRYPT", "ARGON2", "HKDF", "KMAC", "SHA2", "SHA3", "SHA256",
          "SHA384", "SHA512", "SM3", "SM4")
SAFE = ("MLKEM", "MLDSA", "FNDSA", "SLHDSA", "XMSS", "LMS")


def normalize(value):
    return re.sub(r"[^A-Z0-9]", "", str(value or "").upper())


def risk_for(value):
    key = normalize(value)
    if "ECB" in key:
        return "broken"
    # 精确淘汰项先于 DES 前缀等泛化；SHA1 必须先于 SHA2/SHA3。
    for names, risk in ((BROKEN, "broken"), (SHOR, "shor"),
                        (SAFE, "safe"), (GROVER, "grover")):
        if any(key.startswith(name) for name in names):
            return risk
    return "review"


def _selftest():
    cases = {"Blowfish": "broken", "SHA-1": "broken", "RSA-2048": "shor",
             "AES/GCM/NoPadding": "grover", "AES/ECB/PKCS5Padding": "broken",
             "ML-KEM": "safe",
             "MysteryProvider": "review"}
    for value, expected in cases.items():
        got = risk_for(value)
        if got != expected:
            raise AssertionError("%s: %s != %s" % (value, got, expected))
    print("[PASS] algorithm_risk 统一算法风险表自检通过")


if __name__ == "__main__":
    _selftest()
