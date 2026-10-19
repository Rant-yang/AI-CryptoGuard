"""Deterministic facts for direct literal IV/nonce at encryption APIs."""

FIXED_CBC_IV_RULE = "PY-CBC-FIXED-IV-DIRECT"
FIXED_GCM_NONCE_RULE = "PY-GCM-FIXED-NONCE-DIRECT"

CBC_REFERENCE = "https://csrc.nist.gov/pubs/sp/800/38/a/final"
GCM_REFERENCE = "https://csrc.nist.gov/pubs/sp/800/38/d/final"

CBC_ACTION = (
    "该 CBC 加密调用直接使用固定字节 IV。每次加密应生成不可预测的新 IV，"
    "并按协议与密文一起保存或传输；核对解密兼容性后复扫及测试。"
)
GCM_ACTION = (
    "该 GCM 加密调用直接使用固定字节 Nonce。先确认同一密钥下是否多次调用；"
    "若存在重复，应设计并验证逐次唯一的 Nonce 生成策略，轮换受影响密钥，"
    "并运行协议兼容性与复扫测试。单个静态调用点不能证明实际发生了重复。"
)
