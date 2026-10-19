"""Deterministic facts for directly observed weak RSA key generation."""

RSA_WEAK_KEY_SIZE_RULE = "PY-RSA-KEYSIZE-LT2048"
RSA_MIN_CLASSICAL_BITS = 2048
RSA_WEAK_KEY_ACTION = (
    "该处新生成的 RSA 密钥长度低于 2048 位。先确认密钥用途、持有者与兼容性，"
    "按当前适用标准重新生成并轮换足够长度的密钥，然后运行签名/加解密及部署测试；"
    "仅增加 RSA 位数不能消除未来的量子公钥风险。"
)
RSA_KEY_SIZE_REFERENCE = "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"
