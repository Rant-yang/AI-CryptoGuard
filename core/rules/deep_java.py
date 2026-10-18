"""Deterministic rule facts for high-confidence Java data-flow findings."""

PREDICTABLE_KEY_RULE = "JAVA-WEAK-PRNG-KEY"
PREDICTABLE_KEY_SUBJECT = "可预测随机源生成的密码学密钥"
PREDICTABLE_KEY_NORMALIZED = "PREDICTABLEKEYSOURCE"
PREDICTABLE_KEY_ACTION = (
    "先核对来源分支在实际调用中是否可达、该字节流是否构成实际密钥；"
    "若可达，在已定位的密钥来源处改用密码学安全随机源或受控密钥生成服务；"
    "保持密钥长度与调用协议兼容，重新编译并运行项目测试。"
)
