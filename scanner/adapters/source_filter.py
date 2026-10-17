"""命中来源过滤 —— 区分「算法被真实使用」与「算法名只出现在字符串/注释里」。

cbom-scan / cryptoscan 都是正则级匹配，会把算法名在**帮助文本、密码套件名、
枚举表、import 路径、测试向量、字典键**里的出现也报出来 —— 这些不是算法使用，
是误报。但有几类字符串里的算法名**必须保留**（真实使用）：

  1. 密码学 API 调用的字符串参数：`Cipher.getInstance("AES/CBC")`、
     `SecretKeySpec(..., "HmacSHA256")`
  2. 变换/算法描述符：`"AES/ECB/PKCS5Padding"` —— 无论它是 getInstance 实参、
     常量定义右值（`String crypto = "AES/ECB/PKCS5Padding"`）还是普通方法实参，
     都是「用了哪个算法」的实据（上游对这些用法的 match 恰恰落在字符串里）
  3. 常量定义右值：`String algo = "MD5"` 之类（左值是密码学命名）
  4. 代码符号：`hashes.SHA1()`、`EVP_md5()`、`aes.NewCipher`（match 不在字符串里）

判据（对单行源码）:
  1. 整行是注释行                              -> 误报（过滤）
  2. match 不在字符串里（引号成对）            -> 代码符号，保留
  3. match 在字符串里，且字符串是变换描述符     -> 真实使用，保留
  4. match 在字符串里，且是密码学 API 参数       -> 真实使用，保留
  5. match 在字符串里，且是密码学命名变量的常量右值 -> 真实使用，保留
  6. 其余（帮助文本 / 套件名 / import 路径 / 测试向量 / 字典键）-> 误报（过滤）

本模块是纯函数，不读文件 —— cryptoscan 自带 `context`（整行），cbom-scan 侧
由调用方把源文件行读进来再调这里。
"""
import re


#: 密码学 API 调用形态：这些调用里，字符串参数是「用了哪个算法」的真实证据。
_CRYPTO_API_CALL_RE = re.compile(
    r'(?i)(?:getInstance|SecretKeySpec|IvParameterSpec|PBEKeySpec|'
    r'PBEParameterSpec|GCMParameterSpec|EVP_[a-z0-9_]+byname)\s*\(')

#: 变换/算法描述符：算法/模式/填充用斜杠连接的形态（"AES/ECB/PKCS5Padding"）。
#: 单算法名（"MD5"）不进这里 —— 它需要靠上下文（API 实参 / 常量右值）区分。
_TRANSFORM_RE = re.compile(r'^[A-Za-z0-9]+(?:/[A-Za-z0-9]+)+$')

#: 密码学相关的变量名（常量定义 `String crypto = "AES"` 的左值）。
_CRYPTO_NAME_RE = re.compile(
    r'(?i)(?:crypto|cipher|algorithm|algo|transformation|digest|hash|mac|'
    r'secret|key|scheme|suite|mode|padding|keystore|signature|kdf|prf)')

#: C/C++ 预处理器指令 —— 不是注释（`#include <openssl/blowfish.h>` 是真实使用）。
_PREPROCESSOR_RE = re.compile(
    r'^\s*#\s*(?:include|define|undef|if|ifdef|ifndef|elif|else|endif|'
    r'pragma|error|warning|import|using|line)\b')

#: Python `from X import Y` 声明 —— 导入语句里的算法名是模块路径/符号
#: 声明，不是算法使用（实测 af10278 `from ...rsa import RSAPublicKey`、
#: af10123 `from Crypto.PublicKey import RSA` 被误报）。使用点在后续行，
#: import 行本身不该报。Java/C 的 import/include 不走这里（后者是真实引入）。
_FROM_IMPORT_RE = re.compile(r'^\s*from\s+[\w.]+\s+import\b')


def _quote_parity(before):
    """before 里单/双引号是否各自成对（忽略反斜杠转义）。

    任一引号数不成对，说明光标落在该种引号的字符串字面量内。
    """
    dq = sq = 0
    i = 0
    while i < len(before):
        c = before[i]
        if c == '\\':
            i += 2
            continue
        if c == '"':
            dq += 1
        elif c == "'":
            sq += 1
        i += 1
    return (dq % 2 == 0) and (sq % 2 == 0)


def _enclosing_string(line, idx):
    """返回 match（line[idx]）所在的字符串字面量内容与起始引号位置。

    找不到边界时返回 (None, None)。"""
    # 往回找起始引号
    start = -1
    for j in range(idx - 1, -1, -1):
        c = line[j]
        if c in ('"', "'"):
            # 检查是否被转义
            backslashes = 0
            k = j - 1
            while k >= 0 and line[k] == '\\':
                backslashes += 1
                k -= 1
            if backslashes % 2 == 0:
                start = j
                break
        elif c in ('\n', '\r'):
            break
    if start < 0:
        return None, None
    q = line[start]
    end = -1
    for j in range(idx + 1, len(line)):
        c = line[j]
        if c == q:
            backslashes = 0
            k = j - 1
            while k >= 0 and line[k] == '\\':
                backslashes += 1
                k -= 1
            if backslashes % 2 == 0:
                end = j
                break
    if end < 0:
        return None, None
    return start, line[start + 1:end]


def _string_is_crypto_arg(line, qpos):
    """qpos 处的字符串是否落在密码学 API 调用的参数位置。"""
    before = line[:qpos]
    calls = list(_CRYPTO_API_CALL_RE.finditer(before))
    if not calls:
        return False
    open_paren = calls[-1].end() - 1
    tail = before[open_paren + 1:]
    return tail.count('(') == tail.count(')')


def _is_crypto_const_rhs(line, qpos):
    """qpos 处的字符串是否是一个密码学命名变量的常量定义右值。

    `String crypto = "MD5"` / `DEFAULT_CRYPTO = "HmacSHA256"` 是真实使用；
    左侧紧邻 `=`，且 `=` 左侧的标识符含密码学词。
    """
    before = line[:qpos].rstrip()
    if not before.endswith('='):
        return False
    lhs = before[:-1].rstrip()
    # 取 lhs 末尾的标识符（跨 `final` / 类型名等）
    m = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*$', lhs)
    if not m:
        return False
    return bool(_CRYPTO_NAME_RE.search(m.group(1)))


def is_string_or_comment_mention(line, match):
    """单行 `line` 上的 `match` 是否只是字符串/注释提及（应过滤）。

    返回 True 表示该命中应被过滤掉（不是真实算法使用）。
    """
    if not line or not match:
        return False
    stripped = line.lstrip()
    if _FROM_IMPORT_RE.match(stripped):
        return True
    if _PREPROCESSOR_RE.match(stripped):
        return False
    if stripped.startswith(('//', '/*', '*', '<!--')):
        return True
    if stripped.startswith('#'):
        # 非预处理器的 '#'（Python / shell 注释）
        return True
    idx = line.lower().find(match.lower())
    if idx < 0:
        # 找不到 match：不越权过滤，保守保留
        return False
    before = line[:idx]
    # match 不在字符串里（引号成对）-> 是代码符号，保留
    if _quote_parity(before):
        return False
    # match 在字符串里：变换描述符 -> 真实使用
    start, content = _enclosing_string(line, idx)
    if content is not None and _TRANSFORM_RE.match(content.strip()):
        return False
    # 密码学 API 实参 / 密码学命名变量的常量右值 -> 真实使用
    # （这两处要传字符串起始引号位置，而不是 match 位置）
    if start is not None and _string_is_crypto_arg(line, start):
        return False
    if start is not None and _is_crypto_const_rhs(line, start):
        return False
    return True


def keep_record(record):
    """对一条带 `context`/`match` 的上游记录判断是否保留。

    context 缺省或 match 缺省时保守保留（不越权丢弃证据）。
    """
    ctx = record.get('context') or ''
    m = record.get('match') or ''
    if not ctx or not m:
        return True
    return not is_string_or_comment_mention(ctx, m)
