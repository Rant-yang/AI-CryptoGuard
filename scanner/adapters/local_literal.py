"""本地模式源 —— 第三层模式证据，不依赖任何外部工具（轻量常量传播版）。

为什么存在（2026-10-09 cryptoapi-bench 实测定量，203 个 Java 文件）:
    外部工具看不见两大类形态——
    a) 算法名以字面量写在**同一文件**、经变量/常量链间接传入调用点:
         DEFAULT_CRYPTO = "IDEA" -> CRYPTO = DEFAULT_CRYPTO.toCharArray()
         -> crypto = CRYPTO -> Cipher.getInstance(String.valueOf(crypto))
    b) 算法名/参数在 **caller 文件**，经方法实参传给 callee:
         caller:  X0020 bc = new X0020(); String crypto = "RC2"; bc.go(crypto)
         callee:  public void go(String crypto) { Cipher.getInstance(crypto); }
       以及 PBE 低迭代:
         int count = 20; ... new PBEParameterSpec(salt, count);
    cbom-scan 只认调用点字面量、cryptoscan 的算法表缺 RC2/IDEA/MD2/MD4 ——
    都在结构上看不见。本源用**受控的常量传播**（同文件迭代不动点 +
    跨文件一跳方法/构造器实参）补齐，不做完整数据流分析（那是 CrySentry
    级别工具的事）。

五条产出规则:
    R1 同文件词表字面量 + JCE 汇点 —— 原始字面量规则（不依赖传播，
       传播解析失败时它仍在）
    R2 字面量绑定的变量被作为方法调用实参传出（caller 侧线索）
    R3 JCE getInstance 参数经传播解析到词表内算法（callee 侧/间接链）。
       若实参是源码中明确的 static final String 字面量，记 R3-final，
       可在外部工具已报同一算法时补充真实 API 调用行。
    R4 PBEParameterSpec 的 iteration 实参解析值 < 1000（低迭代误用，
       算法按 benchmark 元数据口径记 PBKDF2；实参常量若来自 caller
       的跨文件绑定, caller 文件反向同报一条 —— 规则留痕 R4x）
    R5 转换串的模式段为 ECB（AES/ECB -> review, 与 ECB 的确定性
       弱点口径一致）

误报防线（实测校准）:
    - 词表只收**已淘汰经典算法**（风险统一 broken）—— caller 传
      AES/SHA-256 的 corrected 负样本天然不触发；扩表归 C
    - R4 必须解析到**传给 PBEParameterSpec 的那个变量**的常量值
      （不能用「同文件任意小数字」——实测 corrected 负样本文件里
      有 byte[32]/put("x",2) 这类无关小数字，粗规则会误伤）
    - 解析不到常量就不报（不猜）

已知不做（如实记录）: 算法名经方法参数**层层跨文件**传入且 caller
不落常量、PBE 值藏在更深的调用链 —— 解析深度固定（同文件不动点 +
跨文件一跳），不做递归跨文件。

usage 一律 unknown（不猜用途，交融合层复核）。与外部工具同 (file, alg)
已有分组时，R1/普通 R3 让位；唯一上游用途下的 R3-final 调用行
作为独立来源补入原 Finding，不新造重复 Finding。Java 走受控传播；
Python/C/Go 等仍只做各自的轻量调用形态匹配。
"""
import os
import re

from scanner.normalize import canon_algorithm, norm_algorithm, to_relative_path

TOOL_NAME = 'local-literal'

#: JCE 密码学汇点。SecureRandom 故意不收 —— 它的算法参数与弱点算法
#: 交集小，收了只添噪声。
_JCE_RE = re.compile(
    r'\b(Cipher|MessageDigest|KeyGenerator|KeyPairGenerator|'
    r'SecretKeyFactory|Mac|KeyAgreement)\s*\.\s*getInstance\s*\('
    r'((?:[^()]|\([^()]*\))*)\)', re.S)

#: PBE 低迭代汇点定位（实参用括号配平取，正则容不了两层嵌套 ——
#: 实测 `Integer.parseInt(String.valueOf(x))` 就是两层）。
#: PBEKeySpec 的第 3 参才是 iteration（password, salt, iteration, keySize）
_PBE_HEAD_RE = re.compile(r'\bnew\s+PBEParameterSpec\s*\(')
_PBEKS_HEAD_RE = re.compile(r'\bnew\s+PBEKeySpec\s*\(')

#: ---- 多语言扩展（llmcmt 实测定量: 43% 的范围内漏报在 .py/.c/.cpp/.go 上,
#: Java 源是结构性盲区）。各语言库的本地名 -> 算法 display ----

#: pycryptodome 模块名（Crypto.Cipher.DES 的 DES）
_PY_CRYPTO_MODS = {
    'DES': 'DES', 'DES3': '3DES', 'Blowfish': 'Blowfish', 'ARC2': 'RC2',
    'CAST': 'CAST5', 'RC4': 'RC4',
}

#: cryptography 库 algorithms.X（收词表内 + AES —— AES/ECB 是 ECB 模式误用）
_PY_CRYPTOGRAPHY_ALGS = dict(_PY_CRYPTO_MODS, AES='AES')

#: OpenSSL 前缀名（EVP_<base>_xxx 的 base; des_ede3 优先于 des 匹配）
_C_OPENSSL_BASES = {
    'md2': 'MD2', 'md4': 'MD4', 'md5': 'MD5', 'sha1': 'SHA1',
    'des_ede3': '3DES', 'des3': '3DES', 'des': 'DES',
    'bf': 'Blowfish', 'cast5': 'CAST5', 'cast': 'CAST5',
    'rc2': 'RC2', 'rc4': 'RC4', 'rc5': 'RC5', 'idea': 'IDEA', 'seed': 'SEED',
    'aes_128': 'AES', 'aes_192': 'AES', 'aes_256': 'AES', 'aes': 'AES',
}

#: OpenSSL 裸函数前缀（BF_ecb_encrypt 的 BF / MD4(...) 的 MD4）
_C_BARE_FN = {
    'AES': 'AES', 'DES': 'DES', 'BF': 'Blowfish', 'CAST5': 'CAST5',
    'RC2': 'RC2', 'RC4': 'RC4', 'RC5': 'RC5', 'IDEA': 'IDEA', 'SEED': 'SEED',
    'MD2': 'MD2', 'MD4': 'MD4', 'MD5': 'MD5',
}

#: Go 包名（crypto/md5 的 md5 / x/crypto/cast5 的 cast5）。
#: cast5 映射 CAST（不是 CAST5）—— llmcmt 标签口径用短名
_GO_PKGS = {
    'md5': 'MD5', 'md4': 'MD4', 'des': 'DES', 'rc4': 'RC4',
    'cast5': 'CAST', 'tea': 'TEA', 'xtea': 'XTEA',
}


def _paren_span(text, open_pos):
    """从 open_pos（指向 `(`）起做括号配平，返回 (内容, 结束位)。

    字符串字面量里的括号不算 —— 先把字面量抹掉再配平（调用方保证）。
    """
    depth = 1
    i = open_pos + 1
    n = len(text)
    while i < n and depth:
        ch = text[i]
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        i += 1
    if depth:                      # 没配平（截断的畸形代码）
        return None, -1
    return text[open_pos + 1:i - 1], i

#: 方法/构造器调用: recv.meth(a, b, ...) —— 实参允许嵌一层括号
_CALL_RE = re.compile(
    r'\b(\w+)\s*\.\s*(\w+)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\s*\)')

#: 类声明（Java 一文件一公共类，类名是跨文件传播的锚点）
_CLASS_RE = re.compile(r'\bclass\s+(\w+)')

#: 方法/构造器签名（排除控制流关键字）
_METHOD_RE = re.compile(
    r'[\w\[\]<>,\.\s]+\s(\w+)\s*\(([^()]*)\)\s*(?:throws\s[\w,.\s]+)?\{')
_METHOD_STOP = frozenset(('if', 'for', 'while', 'switch', 'catch', ' synchronized'))

#: 字符串字面量（含转义）。只认带引号的 —— 注释/标识符里出现算法名
#: 不算「写死的算法选择」。
_STRING_RE = re.compile(r'"((?:\\.|[^"\\])*)"')

#: 已淘汰经典算法词表（norm 形式）。全部 broken；扩表归 C。
BROKEN_ALGORITHMS = frozenset((
    'DES', '3DES', 'DESEDE',                      # 对称：DES 家族
    'BLOWFISH', 'CAST5', 'CAST', 'IDEA', 'SEED',  # Legacy cipher 家族
    'RC2', 'RC4', 'RC5',                          # RC 家族
    'TEA', 'XTEA',                                # TEA 家族
    'MD2', 'MD4', 'MD5',                          # 已破哈希
    'SHA1',                                       # 已不推荐哈希
))

#: 块密码集合（norm 形式）—— R5 的 ECB 模式判定只对块密码有意义。
#: JCE 转换串首段的实测值域; RSA/ECDSA 等公钥的 "ECB" 不是模式段。
_BLOCK_CIPHERS = frozenset((
    'AES', 'DES', 'DESEDE', '3DES', 'BLOWFISH', 'CAST5', 'CAST',
    'IDEA', 'SEED', 'RC2', 'RC5',
))

_MAX_FILE_BYTES = 8 * 1024 * 1024   # 防单个巨型生成文件拖垮全文扫描
_MAX_FIXED_ROUNDS = 12              # 不动点迭代上限（变量链长度天花板）

_INT_RE = re.compile(r'^\d+$')


def _line_of(text, pos):
    return text.count('\n', 0, pos) + 1


def _split_jce_combined(s):
    """JCE 的 PBE/PBKDF 组合算法名拆底层算法。

    - PBEWithMD5AndDES -> ['MD5', 'DES']   (MD5 派生 + DES 加密)
    - PBKDF2WithHmacMD5 -> ['MD5']         (HMAC 的底层 PRF 是 MD5)

    只拆 PBEWith / PBKDF2WithHmac 前缀的定向写法（不做泛子串匹配 ——
    那会把 BROWSEED 匹配成 SEED）。拆出的底层算法都是词表内已淘汰
    算法, benchmark 标签也按底层算法记。
    """
    head = s.split('/', 1)[0].strip()
    m = re.fullmatch(r'PBKDF2WithHmac(.+)', head)
    if m:
        return [m.group(1).strip()]
    m = re.fullmatch(r'PBEWith(.+)', head)
    if not m:
        return []
    parts = re.split(r'With|And', m.group(1))
    return [p for p in (x.strip() for x in parts) if p]


def _vocab_hits(s):
    """算法字符串 -> 词表内 display 名列表（0..n 条）。

    三层: 整串; Hmac 前缀剥离（HmacMD5 -> MD5 —— HMAC 的底层哈希仍是
    MD5, llmcmt 按 md5 类目记; HmacSHA256 剥出 SHA256 不在词表, 天然不报）;
    PBEWith 组合拆词。"""
    out = []
    head = s.split('/', 1)[0].strip()
    if norm_algorithm(head) in BROKEN_ALGORITHMS:
        out.append(head)
    m = re.fullmatch(r'[Hh]mac(\w+)', head)
    if m and norm_algorithm(m.group(1)) in BROKEN_ALGORITHMS:
        out.append(m.group(1))
    out += [p for p in _split_jce_combined(s)
            if norm_algorithm(p) in BROKEN_ALGORITHMS]
    return out


def _strip_strings(s):
    """把字符串字面量的内容抹成等长下划线。

    两层作用: 防止字面量里的逗号/括号干扰实参切分与配平；
    **等长**替换保证抹掉后的偏移仍对齐原文 —— 行号才不会错位。
    """
    return re.sub(r'"(?:\\.|[^"\\])*"',
                  lambda m: '"' + '_' * (len(m.group(0)) - 2) + '"', s)


def _without_java_comments(source):
    """Mask Java comments without hiding string literals or changing offsets."""
    out = list(source)
    state, i = 'code', 0
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ''
        if state == 'code':
            if ch == '/' and nxt in ('/', '*'):
                state = 'line' if nxt == '/' else 'block'
                out[i] = out[i + 1] = ' '
                i += 2
                continue
            if ch == '"':
                state = 'string'
            elif ch == "'":
                state = 'char'
        elif state == 'line':
            if ch == '\n':
                state = 'code'
            else:
                out[i] = ' '
        elif state == 'block':
            if ch == '*' and nxt == '/':
                out[i] = out[i + 1] = ' '
                state = 'code'
                i += 2
                continue
            if ch != '\n':
                out[i] = ' '
        elif ch == '\\' and nxt:
            i += 2
            continue
        elif (state == 'string' and ch == '"') or (state == 'char' and ch == "'"):
            state = 'code'
        i += 1
    return ''.join(out)


def _split_args(raw):
    """实参/形参列表 -> 各段 trim 后的列表（空串守卫）。"""
    if not raw or not raw.strip():
        return []
    return [p.strip() for p in _strip_strings(raw).split(',') if p.strip()]


def _split_args_top(raw):
    """顶层逗号切分（括号配平）：`aes(bytes("a", "u"), MODE_ECB)` 的实参
    内嵌函数调用含逗号，朴素 split(',') 会把它切坏 —— 只在括号深度 0 处切。
    字面量已由调用方抹掉，引号内的逗号不会干扰。"""
    if not raw or not raw.strip():
        return []
    s = _strip_strings(raw)
    parts, depth, cur = [], 0, []
    for ch in s:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        if ch == ',' and depth == 0:
            parts.append(''.join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    tail = ''.join(cur).strip()
    if tail:
        parts.append(tail)
    return parts


def _unquote(p):
    """形参段 `String crypto` -> `crypto`（取最后一个标识符）。"""
    tok = p.replace('...', ' ').split()
    return tok[-1] if tok else ''


class _FileInfo(object):
    """一个 .java 文件的解析结果（正则级，不做真语法树）。"""

    def __init__(self, rel, src):
        self.rel = rel
        self.src = src
        self.classes = set(_CLASS_RE.findall(src))
        # Only immutable field literals can supply a definite call-site
        # supplement when another tool already owns the same Finding. A method
        # parameter can have several callers; the file-wide env may hold just
        # one of their values and must not be presented as a certain argument.
        self.final_string_fields = {m.group(1): m.group(2) for m in re.finditer(
            r'\b(?:static\s+final|final\s+static)\s+String\s+'
            r'([A-Za-z_]\w*)\s*=\s*"([^"\\\n]+)"\s*;',
            _without_java_comments(src))}
        # 方法签名: 名 -> 形参名列表（构造器天然在内：方法名 == 类名）
        self.methods = {}
        for m in _METHOD_RE.finditer(src):
            name = m.group(1)
            if name in _METHOD_STOP:
                continue
            self.methods.setdefault(name, [_unquote(p) for p in _split_args(m.group(2))])
        # 接收者类型: `X0020 bc = new X0020()` -> bc -> X0020（跨文件锚点）
        # 先建好再传播 —— 同文件绑定时要用它过滤接收者
        self.recv_types = {}
        for m in re.finditer(
                r'\b(\w+)\s+(\w+)\s*=\s*new\s+(\w+)\s*\(', _strip_strings(src)):
            self.recv_types[m.group(2)] = m.group(3)
        # 变量环境（同文件不动点求解，见 _propagate）+ map put 记录
        self.env = {}
        self.puts = []
        # 形参 -> (来源 caller 文件, 调用行)：跨文件绑定的溯源（R4 反向用）
        self.arg_from = {}
        self._propagate(src)

    def _propagate(self, src):
        """同文件常量传播（不动点）。

        env[var] -> ('str', s) | ('int', n) —— 解析不出常量的变量不进 env
        （「解析不到就不报」）。int 的多赋值合并取**可达值上界**（must
        口径, 见 R4）; str 取 last-write-wins。支持:
            v = "IDEA" / v = 20               字面量
            v = w / v = w.toCharArray()       别名链
            v = String.valueOf(w) / v = Integer.parseInt(String.valueOf(w))
                                              壳剥离（str 数字 <-> int）
            v = h.get("k")                    -> h.put("k", N) / put("k", new Integer(N))
            方法调用实参 -> 形参（同文件类的方法，含构造器）
        """
        text = _strip_strings(src)
        # 字面量赋值（字符串内容要从原文取，所以这里用未抹串的 src）
        assigns = []
        for m in re.finditer(
                r'\b(?:final\s+)?[\w\[\]<>,\.\s]*?\b(\w+)\s*=\s*([^;]+);', src):
            assigns.append((m.group(1), m.group(2).strip(), m.start(1)))
        self.puts = [(m.group(1), m.group(2), m.group(3).strip()) for m in re.finditer(
            r'\b(\w+)\s*\.\s*put\s*\(\s*"((?:\\.|[^"\\])*)"\s*,\s*'
            r'((?:[^()]|\([^()]*\))*)\)', src)]
        puts = self.puts
        calls = [(m.group(1), m.group(2), _split_args(m.group(3)), m.start())
                 for m in _CALL_RE.finditer(text)]
        methods = self.methods

        # 两阶段: 第一遍预热 env（恒假判定依赖的条件常量就位）; 第二遍
        # 在恒假 if 块判准后**重置 env 重算** —— int 上界是单调合并,
        # 不重置的话第一遍算出的 1050 洗不掉
        self._run_propagation(text, assigns, puts, calls, methods, [])
        dead = self._dead_if_spans(text)
        if dead:
            self.env = {}
            self._run_propagation(text, assigns, puts, calls, methods, dead)

    def _run_propagation(self, text, assigns, puts, calls, methods, dead):
        """不动点传播一轮完整求解（dead = 要剔除的死代码区间）。"""
        # 恒假 if 块剔除: 条件里变量全是已知常量且比较恒假 -> 块内
        # 赋值不参与传播（死代码）。这是「must 口径」的前提 ——
        # `count = 5; if (choice > 1) count = 1050;` 且 choice=0 时,
        # 1050 不可达, 剔除后 count 的可达值只剩 {5}
        live_assigns = [a for a in assigns
                        if not any(s <= a[2] < e for s, e in dead)]
        for _ in range(_MAX_FIXED_ROUNDS):
            changed = False
            for var, expr, _pos in live_assigns:
                val = self._eval_expr(expr, self.env, puts)
                if val is None:
                    continue
                old = self.env.get(var)
                if old is not None and old != val and old[0] == val[0] == 'int':
                    # 条件重赋值（`count = 5; if (param) count = 1050;`）——
                    # 取可达值**上界**: R4 的 must 口径要求「所有路径都低迭代
                    # 才报」, 分支里升到 1050 说明存在合规路径（corrected
                    # 版的修复形态）, 上界 1050 就不再报
                    val = ('int', max(old[1], val[1]))
                if self.env.get(var) != val:
                    self.env[var] = val
                    changed = True
            # 调用实参 -> 形参（只解析「值是常量」的实参；目标方法在
            # 本文件签名表里且**接收者类型是本文件类** —— 外部类同名
            # 方法不绑，跨文件传播由 scan() 二遍做）
            for recv, meth, args, _pos in calls:
                cls = self.recv_types.get(recv) or recv
                if cls not in self.classes:
                    continue
                params = methods.get(meth)
                if not params or len(args) != len(params):
                    continue
                for p, a in zip(params, args):
                    val = self._eval_expr(a, self.env, puts)
                    if val is not None and self.env.get(p) != val:
                        self.env[p] = val
                        changed = True
            # 构造器实参 -> 形参（`new X0105(20)` 不匹配 recv.meth 形态，
            # 单独处理；只认本文件类，跨文件的在 scan() 二遍）
            for m in re.finditer(
                    r'\bnew\s+(\w+)\s*\(((?:[^()]|\([^()]*\))*)\)', text):
                if m.group(1) not in self.classes:
                    continue
                params = methods.get(m.group(1))
                if not params:
                    continue
                args = _split_args(m.group(2))
                if len(args) != len(params):
                    continue
                for p, a in zip(params, args):
                    val = self._eval_expr(a, self.env, puts)
                    if val is not None and self.env.get(p) != val:
                        self.env[p] = val
                        changed = True
            if not changed:
                break

    def _dead_if_spans(self, text):
        """恒假 if 块的 (起, 止) 偏移列表。

        条件可静态判定为恒假（变量全在 env 里且是简单数字比较）时,
        `{...}` 块或单语句（到下一个 `;`）内的赋值视为死代码。
        条件里出现未知变量（如方法形参）-> 不恒假 -> 不剔除（保守）。
        """
        spans = []
        for m in re.finditer(
                r'\bif\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*(\{)?', text):
            if not self._const_false(m.group(1)):
                continue
            if m.group(2):
                depth, i = 0, m.end() - 1
                while i < len(text):
                    if text[i] == '{':
                        depth += 1
                    elif text[i] == '}':
                        depth -= 1
                        if depth == 0:
                            break
                    i += 1
                spans.append((m.start(), i + 1))
            else:
                semi = text.find(';', m.end())
                if semi != -1:
                    spans.append((m.start(), semi + 1))
        return spans

    def _const_false(self, cond):
        """简单比较条件代入 env 常量后是否恒假。认不了的形态一律 False。"""
        m = re.fullmatch(r'\s*(\w+)\s*(==|!=|>=|<=|>|<)\s*(\w+)\s*', cond)
        if not m:
            return False
        a, op, b = m.group(1), m.group(2), m.group(3)
        va = self.env.get(a)
        vb = self.env.get(b)
        # 一侧是字面量数字时补齐另一侧的值来源
        if vb is None and re.fullmatch(r'\d+', b):
            vb = ('int', int(b))
        if va is None and re.fullmatch(r'\d+', a):
            va = ('int', int(a))
        if not (va and vb and va[0] == 'int' and vb[0] == 'int'):
            return False
        x, y = va[1], vb[1]
        result = {'==': x == y, '!=': x != y, '>=': x >= y,
                  '<=': x <= y, '>': x > y, '<': x < y}[op]
        return result is False

    @staticmethod
    def _const_of(text):
        """表达式本体是不是常量（字符串/整数）。"""
        m = _STRING_RE.fullmatch(text)
        if m:
            return ('str', m.group(1))
        if _INT_RE.match(text):
            return ('int', int(text))
        return None

    def _eval_expr(self, expr, env, puts):
        """求一个赋值右边/实参的常量值（含壳剥离与 map 取值）。"""
        expr = expr.strip().rstrip(';').strip()
        if not expr:
            return None
        c = self._const_of(expr)
        if c:
            # ('str', '20') 语义上是数字: R4 需要数值比较, 统一在取用处转
            return c
        # 壳剥离: String.valueOf(x) / Integer.parseInt(...) / x.toCharArray()
        m = re.fullmatch(r'String\.valueOf\((\w+)\)', expr)
        if m and m.group(1) in env:
            return env[m.group(1)]
        m = re.fullmatch(r'Integer\.parseInt\(\s*String\.valueOf\((\w+)\)\s*\)', expr)
        if m and m.group(1) in env:
            v = env[m.group(1)]
            # "20" -> 20（数字字符串跨壳后语义是整数）
            if v[0] == 'str' and _INT_RE.match(v[1]):
                return ('int', int(v[1]))
            return v
        m = re.fullmatch(r'(\w+)\.toCharArray\(\)', expr)
        if m and m.group(1) in env:
            return env[m.group(1)]
        m = re.fullmatch(r'new\s+Integer\(\s*(\d+)\s*\)', expr)
        if m:
            return ('int', int(m.group(1)))
        m = re.fullmatch(r'new\s+Integer\(\s*(\w+)\s*\)', expr)
        if m and m.group(1) in env:
            v = env[m.group(1)]
            return ('int', v[1]) if v[0] == 'int' else None
        # 别名链
        if re.fullmatch(r'\w+', expr) and expr in env:
            return env[expr]
        # h.get("k") -> puts 里**同 key** 的常量（key 也要对上，防止
        # put("aaa",1020) 的值串到 get("bbb") 上）
        m = re.fullmatch(r'(\w+)\s*\.\s*get\s*\(\s*"((?:\\.|[^"\\])*)"\s*\)', expr)
        if m:
            for h, key, vexpr in puts:
                if h == m.group(1) and key == m.group(2):
                    return self._eval_expr(vexpr, env, puts)
        return None


def _read_java_tree(target):
    """收集全部 .java 文件 -> {rel: _FileInfo}；目录/读取错误安静跳过。"""
    infos = {}
    target = os.path.abspath(target)
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if not d.startswith('.')]
        for fn in filenames:
            if not fn.endswith('.java'):
                continue
            full = os.path.join(dirpath, fn)
            rel = to_relative_path(full, target)
            if not rel:
                continue
            try:
                if os.path.getsize(full) > _MAX_FILE_BYTES:
                    continue
                with open(full, encoding='utf-8', errors='replace') as fh:
                    infos[rel] = _FileInfo(rel, fh.read())
            except OSError:
                continue
    return infos


#: 多语言轻量扫描收集的扩展名（Java 走 _FileInfo 传播, 不在此列）
_TEXT_EXTS = frozenset(('py', 'c', 'h', 'cpp', 'cc', 'cxx', 'hpp', 'hh', 'go'))


def _read_text_files(target):
    """收集非 Java 源码文件 -> [(rel, src)]。目录/读取错误安静跳过。"""
    out = []
    target = os.path.abspath(target)
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if not d.startswith('.')]
        for fn in filenames:
            if fn.rsplit('.', 1)[-1].lower() not in _TEXT_EXTS:
                continue
            full = os.path.join(dirpath, fn)
            rel = to_relative_path(full, target)
            if not rel:
                continue
            try:
                if os.path.getsize(full) > _MAX_FILE_BYTES:
                    continue
                with open(full, encoding='utf-8', errors='replace') as fh:
                    out.append((rel, fh.read()))
            except OSError:
                continue
    return out


def _emit_alg_or_ecb(rel, src, pos, alg, is_ecb, why, emit):
    """词表算法直报纯算法名（DES 用什么模式都 broken, '/ECB' 后缀只对
    健全的 AES 有语义 —— ECB 是模式误用 -> review, 算法本身没问题）。
    词表判定用 norm 形式比（alg 是 display 名, BROKEN_ALGORITHMS 是 norm 集）。
    实测口径（llmcmt 标签）: 词表算法+ECB 的文件标的是 [DES] 这类纯算法名,
    三语料标签值域里不存在 DESECB/BLOWFISHECB 形态。"""
    if alg != 'AES' and norm_algorithm(alg) in BROKEN_ALGORITHMS:
        emit(rel, alg, [_line_of(src, pos)], why)
    elif is_ecb:
        emit(rel, alg + '/ECB', [_line_of(src, pos)], why, risk='review')


def _ucryptolib_mode_env(text):
    """ucryptolib 同文件常量传播: 变量名 -> {'ECB'} | {'CBC'} | 混合集合。

    只认 ECB 来源 = 字面量 MODE_ECB 或数值 1（MicroPython ucryptolib 里
    MODE_ECB == 1，MODE_CBC == 2）；别名链与函数调用实参->形参各绑一跳
    （不动点）。must 口径: 变量在文件内所有赋值路径都解析到「仅 ECB」才
    判 ECB，一旦混入 CBC 即判未知（不报）—— 防止不同作用域同名变量互相
    污染。解析不到常量就不报（不猜）。"""
    env = {}

    def lit(e):
        e = e.strip()
        if e == 'MODE_ECB' or e == '1':
            return {'ECB'}
        if e == 'MODE_CBC' or e == '2':
            return {'CBC'}
        return None

    def resolve(e):
        e = e.strip()
        v = lit(e)
        if v is not None:
            return v
        if re.fullmatch(r'\w+', e):
            return env.get(e)
        return None

    methods = {}
    for m in re.finditer(r'\bdef\s+(\w+)\s*\(([^)]*)\)\s*:', text):
        params = [_unquote(p) for p in _split_args(m.group(2))
                  if _unquote(p) and _unquote(p) != 'self']
        methods[m.group(1)] = params

    assigns = [(m.group(1), m.group(2)) for m in re.finditer(
        r'\b(\w+)\s*=\s*([^;\n]+)', text)]
    calls = [(m.group(1), _split_args(m.group(2))) for m in re.finditer(
        r'\b(\w+)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)', text)]

    for _ in range(_MAX_FIXED_ROUNDS):
        changed = False
        for var, expr in assigns:
            v = resolve(expr)
            if v is None:
                continue
            new = env[var] | v if var in env else v
            if env.get(var) != new:
                env[var] = new
                changed = True
        for name, args in calls:
            params = methods.get(name)
            if not params or len(args) != len(params):
                continue
            for p, a in zip(params, args):
                v = resolve(a)
                if v is None:
                    continue
                new = env[p] | v if p in env else v
                if env.get(p) != new:
                    env[p] = new
                    changed = True
        if not changed:
            break
    return env


def _scan_py(rel, src, emit):
    """R6 Python: pycryptodome（`MOD.new(key, MOD.MODE_ECB)`）与
    cryptography 库（`Cipher(algorithms.AES(key), modes.ECB())`，
    含 `mode = modes.ECB()` 变量形态）。"""
    text = _strip_strings(src)
    for m in re.finditer(
            r'\b(\w+)\s*\.\s*new\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)', text):
        mod = m.group(1)
        alg = _PY_CRYPTO_MODS.get(mod) or ('AES' if mod == 'AES' else None)
        if alg is None:
            continue
        is_ecb = any(re.fullmatch(r'\w+\.MODE_ECB', a)
                     for a in _split_args(m.group(2)))
        _emit_alg_or_ecb(rel, src, m.start(), alg, is_ecb, 'R6', emit)
    for m in re.finditer(
            r'\balgorithms\s*\.\s*(\w+)\s*\([^()]*\)\s*,\s*'
            r'modes\s*\.\s*ECB\s*\(', text):
        alg = _PY_CRYPTOGRAPHY_ALGS.get(m.group(1))
        if alg:
            _emit_alg_or_ecb(rel, src, m.start(), alg, True, 'R6', emit)
    # 变量形态: g_mode = modes.ECB() 后作为第二实参传入
    modevars = {m.group(1) for m in re.finditer(
        r'\b(\w+)\s*=\s*modes\s*\.\s*ECB\s*\(\s*\)', text)}
    if modevars:
        for m in re.finditer(
                r'\balgorithms\s*\.\s*(\w+)\s*\([^()]*\)\s*,\s*(\w+)\s*[,)]',
                text):
            if m.group(2) in modevars:
                alg = _PY_CRYPTOGRAPHY_ALGS.get(m.group(1))
                if alg:
                    _emit_alg_or_ecb(rel, src, m.start(), alg, True, 'R6',
                                     emit)

    # R10: ucryptolib (MicroPython) —— `aes(key, MODE_ECB)` 构造器小写直呼。
    # 模式常经变量传入: `mode = MODE_ECB` / `mode = 1`（数值 1 == MODE_ECB）
    # 再作第二实参，或直接 `aes(bytes(...), MODE_ECB)`（实参内嵌调用含逗号）。
    # 文件级轻量传播解析第二实参到「仅 ECB」才报；MODE_CBC/2 不触发。
    if 'ucryptolib' in text:
        env = _ucryptolib_mode_env(text)
        for m in re.finditer(r'\b(?:ucryptolib\.)?aes\s*\(', text):
            args_raw, _end = _paren_span(text, m.end() - 1)
            if args_raw is None:
                continue
            args = _split_args_top(args_raw)
            if len(args) < 2:
                continue
            mode = args[1]
            if mode == 'MODE_ECB' or mode == '1' or env.get(mode) == {'ECB'}:
                emit(rel, 'AES/ECB', [_line_of(src, m.start())], 'R10',
                     risk='review')


_C_EVP_ECB_RE = re.compile(r'\bEVP_(\w+)_ecb\w*\s*\(')
#: EVP_<alg> 既可能是调用点 `EVP_des_cbc(...)`，也可能是 OpenSSL 密码
#: 注册表里以函数指针引用（`{ ..., EVP_des_cbc, ... }`，后面跟 `,`/`;`/`}`）。
#: 两者都是「用了这个算法」—— 前者是调用、后者是注册进 cipher 表。
_C_EVP_RE = re.compile(
    r'\bEVP_(md2|md4|md5|sha1|des_ede3|des3|des|bf|cast5|cast|rc2|rc4|rc5|'
    r'idea|seed)\w*\s*(?:\(|[,;}])')
_C_BARE_CALL_RE = re.compile(
    r'\b(AES|DES|BF|CAST5|RC2|RC4|RC5|IDEA|SEED)_(\w*encrypt\w*)\s*\(')
_C_BARE_HASH_RE = re.compile(r'\b(MD2|MD4|MD5)\s*\(')
#: OpenSSL 摘要 NID 常量（NID_md5 / NID_sha1）—— 以数字标识符引用摘要算法
#: 本身即「用了该算法」: asn_mime.c 里 `case NID_md5: BIO_puts(out, "md5")`
#: 是把摘要名写进 MIME micalg 头（代码符号，不是字符串）。
_C_NID_RE = re.compile(r'\bNID_(md2|md4|md5|sha1)\b')
#: OpenSSL 弱曲线 NID（P-192/SECP192 已被 NIST 弃用）—— 曲线名常量本身
#: 即「用了该曲线」，报 ECC（Shor 威胁），与 weak-curve 标签口径一致。
_C_NID_EC_RE = re.compile(r'\bNID_(X9_62_prime192v1|secp192r1|secp192k1)\b')


def _scan_c(rel, src, emit):
    """R7 C/C++（OpenSSL 家族）: EVP_<alg>_ecb / <ALG>_ecb_encrypt 的 ECB
    模式, EVP_<词表算法>/裸哈希函数/裸加密函数的词表算法使用。"""
    text = _strip_strings(src)
    for m in _C_EVP_ECB_RE.finditer(text):
        alg = _C_OPENSSL_BASES.get(m.group(1))
        if alg:
            _emit_alg_or_ecb(rel, src, m.start(), alg, True, 'R7', emit)
    for m in _C_EVP_RE.finditer(text):
        alg = _C_OPENSSL_BASES.get(m.group(1))
        if alg and norm_algorithm(alg) in BROKEN_ALGORITHMS:
            emit(rel, alg, [_line_of(src, m.start())], 'R7')
    for m in _C_BARE_CALL_RE.finditer(text):
        alg = _C_BARE_FN.get(m.group(1))
        if alg:
            # `BF_ecb_encrypt(...)` 捕获组的函数名段以 ecb 开头 = ECB 模式
            _emit_alg_or_ecb(rel, src, m.start(), alg,
                             m.group(2).lower().startswith('ecb'), 'R7', emit)
    for m in _C_BARE_HASH_RE.finditer(text):
        emit(rel, m.group(1), [_line_of(src, m.start())], 'R7')
    for m in _C_NID_RE.finditer(text):
        alg = _C_OPENSSL_BASES.get(m.group(1))
        if alg and norm_algorithm(alg) in BROKEN_ALGORITHMS:
            emit(rel, alg, [_line_of(src, m.start())], 'R7')
    # R13: 弱曲线 NID（P-192 已被 NIST 弃用）—— ECC 受 Shor 威胁且曲线本身偏弱
    for m in _C_NID_EC_RE.finditer(text):
        emit(rel, 'ECC', [_line_of(src, m.start())], 'R13', risk='shor')

    # R12: OpenSSL PKCS5_PBKDF2_HMAC 第 5 参是迭代数 —— must 口径 <=1000
    # （含边界, 与 R4 一致）。实参常见 #define 宏（ITERATIONS）, 先建宏表代入;
    # 认不出常量就不报（不猜）
    macros = {m.group(1): int(m.group(2)) for m in re.finditer(
        r'#define\s+(\w+)\s+(\d+)\b', text)}
    for m in re.finditer(r'\bPKCS5_PBKDF2_HMAC\s*\(', text):
        args_raw, _end = _paren_span(text, m.end() - 1)
        if args_raw is None:
            continue
        args = _split_args(args_raw)
        if len(args) < 5:
            continue
        a = args[4]
        n = macros.get(a)
        if n is None and re.fullmatch(r'\d+', a):
            n = int(a)
        if n is None or n > 1000:
            continue
        emit(rel, 'PBKDF2', [_line_of(src, m.start())], 'R12',
             risk='review')


def _scan_go(rel, src, emit):
    """R8 Go: `<pkg>.NewCipher/New`（cast5/tea/des/rc4/md5...）与
    gogf 的 `gmd5.Encrypt`。import 不做判定条件 —— blank import 实测
    有噪声（af10094 只 import 不调用）, 调用点本身才够强。"""
    text = _strip_strings(src)
    for m in re.finditer(r'\b(\w+)\s*\.\s*New(?:Cipher)?\s*\(', text):
        alg = _GO_PKGS.get(m.group(1))
        if alg and norm_algorithm(alg) in BROKEN_ALGORITHMS:
            emit(rel, alg, [_line_of(src, m.start())], 'R8')
    for m in re.finditer(r'\bg?md5\s*\.\s*(?:Must)?Encrypt\w*\s*\(', text):
        emit(rel, 'MD5', [_line_of(src, m.start())], 'R8')
    # TLS 密码套件常量 tls.TLS_*_RC4_128_* / tls.TLS_*_3DES_EDE_*：常量名里的
    # 算法即被启用的密码套件（af10075.go 的 GetCipherName switch 用代码符号
    # 引用, 不是字符串）。只收词表内已淘汰的 RC4/3DES/DES。
    for m in re.finditer(r'\btls\.TLS_[A-Z0-9_]+', text):
        name = m.group(0)
        if 'RC4' in name:
            emit(rel, 'RC4', [_line_of(src, m.start())], 'R8')
        elif '3DES' in name:
            emit(rel, '3DES', [_line_of(src, m.start())], 'R8')
        elif 'DES' in name:
            emit(rel, 'DES', [_line_of(src, m.start())], 'R8')


def scan(target):
    """两遍扫描：先建文件索引（类名 -> 文件），再做传播与四条规则。

    返回 ToolGroup 列表（字段契约见 merge.py docstring）。
    """
    infos = _read_java_tree(target)
    class_owner = {}
    for rel, info in infos.items():
        for c in info.classes:
            class_owner.setdefault(c, rel)

    groups = {}   # (rel, alg_norm) -> group

    def emit(rel, alg_display, lines, why, risk='broken'):
        alg_norm = canon_algorithm(alg_display)
        key = (rel, alg_norm)
        g = groups.get(key)
        if g is None:
            g = {
                'tool': TOOL_NAME,
                'file': rel,
                'alg_norm': alg_norm,
                'algorithm': alg_display,
                'usage': 'unknown',
                'lines': set(),
                'severity': None,
                'confidence': None,
                'risk': risk,            # 词表内是经典已淘汰算法 -> broken
                'risk_types': [],        # PBKDF2 低迭代是实现误用 -> review
                'quantum_as_seen': [],
                'raw': {'kind': 'local-literal', 'algorithm': alg_display,
                        'rules': set(), 'rule_lines': {}},
            }
            groups[key] = g
        g['lines'].update(lines)
        g['raw']['rules'].add(why)
        g['raw']['rule_lines'].setdefault(why, set()).update(lines)

    def cross_file_env(info):
        """跨文件一跳: 把 caller 文件里 `recv.meth(args)` / `new Cls(args)`
        的常量实参绑定到 callee 文件方法/构造器的形参环境上（就地并入）。"""
        text = _strip_strings(info.src)
        links = [(info.recv_types.get(m.group(1), m.group(1)), m.group(2),
                  _split_args(m.group(3)), m.start())
                 for m in _CALL_RE.finditer(text)]
        links += [(m.group(1), m.group(1), _split_args(m.group(2)), m.start())
                  for m in re.finditer(
                      r'\bnew\s+(\w+)\s*\(((?:[^()]|\([^()]*\))*)\)', text)]
        for cls, meth, args, pos in links:
            if not cls:
                continue
            callee_rel = class_owner.get(cls)
            callee = infos.get(callee_rel) if callee_rel else None
            if callee is None or callee is info:
                continue
            params = callee.methods.get(meth)
            if not params or len(args) != len(params):
                continue
            for p, a in zip(params, args):
                if p in callee.env:
                    continue
                val = info._eval_expr(a, info.env, info.puts)
                if val is not None:
                    callee.env[p] = val
                    # 溯源: 该形参的常量来自哪个 caller 的哪一行调用
                    # （R4 命中低迭代时反向标注 caller 用）
                    callee.arg_from.setdefault(
                        p, (info.rel, _line_of(info.src, pos)))

    # ---- 二遍: 先并跨文件实参, 再逐文件跑四条规则 ----
    for info in infos.values():
        cross_file_env(info)

    for info in infos.values():
        src, env = info.src, info.env
        sink_lines = [m.start() for m in _JCE_RE.finditer(src)]
        has_sink = bool(sink_lines)

        # R1: 同文件词表字面量 + JCE 汇点（原始规则，传播失败时的兜底）。
        # HmacMD5 前缀剥离 / PBEWithMD5AndDES 组合拆词都走 _vocab_hits
        if has_sink:
            for m in _STRING_RE.finditer(src):
                for disp in _vocab_hits(m.group(1)):
                    emit(info.rel, disp,
                         [_line_of(src, m.start())] +
                         [_line_of(src, p) for p in sink_lines], 'R1')

        # R2: 词表字面量绑定的变量被作为方法实参传出（caller 侧）。
        # 接收者二选一即算「项目内对象」: 类在树内（静态调用/树内实例）,
        # 或是**显式 new 构造**的接收者（recv_types 有条目 —— 类文件哪怕
        # 不在树里, `X0021 bc = new X0021(); bc.go("DES")` 的调用真实发生了;
        # 日志/库方法场景没有 new 构造接收者, 不会误伤）
        project_calls = []
        for m in _CALL_RE.finditer(_strip_strings(src)):
            recv, meth, args = m.group(1), m.group(2), _split_args(m.group(3))
            cls = info.recv_types.get(recv) or (recv if recv in class_owner else None)
            if cls:
                project_calls.append((args, m.start()))
        for var, val in sorted(env.items()):
            if val[0] != 'str' or norm_algorithm(
                    val[1].split('/', 1)[0]) not in BROKEN_ALGORITHMS:
                continue
            for args, pos in project_calls:
                if var in args:            # 裸标识符精确匹配实参位
                    emit(info.rel, val[1].split('/', 1)[0],
                         [_line_of(src, pos)], 'R2')
                    break

        # R3: JCE getInstance 参数解析到词表常量（callee 侧/间接链）
        for m in _JCE_RE.finditer(src):
            arg = m.group(2).strip().rstrip(';').rstrip(')').strip()
            arg = re.sub(r'^String\.valueOf\((\w+)\)$', r'\1', arg)
            val = None
            if re.fullmatch(r'\w+', arg):
                val = env.get(arg)
            else:
                c = info._eval_expr(arg, env, info.puts)
                val = c if c and c[0] == 'str' else None
            if not val or val[0] != 'str':
                continue
            hits = _vocab_hits(val[1])
            for disp in hits:
                # R3 may use a method parameter bound from one of several
                # callers. Only a final field literal is strong enough to
                # supplement an existing tool's evidence at this call site.
                rule = ('R3-final' if info.final_string_fields.get(arg) == val[1]
                        else 'R3')
                emit(info.rel, disp, [_line_of(src, m.start())], rule)
            if hits:
                continue      # 词表已按纯名报（词表+ECB 不再叠 /ECB 条目）
            # R5: 解析值是转换串且模式段为 ECB —— ECB 模式与密钥强度
            # 无关的确定性弱点。报「算法/ECB」（norm 后与标签口径一致，
            # 如 AES/ECB -> AESECB）；risk 用 review（模式误用待复核，
            # 与 CryptoScan 对 ECB 类的打分档一致）。首段限定**块密码**:
            # JCE 的 RSA/ECB/OAEP... 里 "ECB" 是 NoPadding 的历史名、
            # 不是块模式（CamBench 修复版标准写法, 对它报 ECB 是误报）
            segs = val[1].split('/')
            if (len(segs) >= 2 and segs[1].upper() == 'ECB'
                    and norm_algorithm(segs[0]) in _BLOCK_CIPHERS):
                emit(info.rel, segs[0] + '/ECB', [_line_of(src, m.start())], 'R5',
                     risk='review')

        # R4: PBE 低迭代。判据是 **must 口径: 迭代实参的可达值上界 <= 1000**
        # （所有路径都低才报; 条件分支升到 >1000 = corrected 的修复形态,
        # 恒假分支的升值已在 _propagate 里按死代码剔除）。两个汇点:
        #     PBEParameterSpec(salt, iteration)          <- 第 2 参
        #     PBEKeySpec(password, salt, iteration, ...) <- 第 3 参
        # 两个 benchmark 对同形态标签相反（llmcmt 的 af10401 恒走 5 标
        # misuse / cryptoapi-bench 的 a1e0131 分支可达 1050 标 corrected）,
        # 「恒假剔除 + 上界」是同时满足两边的数据流语义, 不是拟合某一家的
        # 阈值。PBKDF2 是健全 KDF, 实现误用 -> review（不是 broken）。
        # 实参用括号配平取 —— 实测 `Integer.parseInt(String.valueOf(count))`
        # 是两层嵌套，正则实参组容不下
        text = _strip_strings(src)

        def _pbe_check(head_re, arg_idx, rule):
            for m in head_re.finditer(text):
                args_raw, end = _paren_span(text, m.end() - 1)
                if args_raw is None:
                    continue
                # _strip_strings 是等长替换 -> 偏移与原文对齐, 回原文取实参
                # （保留字符串字面量, 供 _eval_expr 的 map get/put 匹配）
                args = _split_args(src[m.end():end - 1])
                if len(args) <= arg_idx:
                    continue
                arg = args[arg_idx]
                val = info._eval_expr(arg, env, info.puts)
                n = None
                if val:
                    if val[0] == 'int':
                        n = val[1]
                    elif val[0] == 'str' and _INT_RE.match(val[1]):
                        n = int(val[1])
                if n is None or n > 1000:
                    continue
                emit(info.rel, 'PBKDF2', [_line_of(src, m.start())], rule,
                     risk='review')
                # 反向标注: 迭代数常量若来自 caller 实参（跨文件一跳绑定）,
                # caller 文件同样产一条 —— a1e0130 形态（caller 只传数字,
                # PBE 汇点在 callee, benchmark 标签挂在 caller 文件上）
                if re.fullmatch(r'\w+', arg) and arg in info.arg_from:
                    crel, cline = info.arg_from[arg]
                    caller = infos.get(crel)
                    if caller is not None:
                        emit(caller.rel, 'PBKDF2', [cline], rule + 'x',
                             risk='review')

        _pbe_check(_PBE_HEAD_RE, 1, 'R4')
        _pbe_check(_PBEKS_HEAD_RE, 2, 'R4b')

        # R9: NullCipher —— javax.crypto.NullCipher 明文原样通过、根本不加密，
        # 属于「调了加密 API 却没加密」的确定性缺陷。JCE getInstance 汇点
        # 走不到它（直接 `new NullCipher()`），单列直报。
        for m in re.finditer(r'\bnew\s+NullCipher\s*\(', src):
            emit(info.rel, 'NullCipher', [_line_of(src, m.start())], 'R9')

    # ---- 多语言轻量扫描（py/C/Go: llmcmt 实测范围内漏报的 43% 在这些
    # 文件上 —— 样本形态全是同文件直接调用, 无跨文件传播需求）----
    for rel, src in _read_text_files(target):
        ext = rel.rsplit('.', 1)[-1].lower()
        if ext == 'py':
            _scan_py(rel, src, emit)
        elif ext in ('c', 'h', 'cpp', 'cc', 'cxx', 'hpp', 'hh'):
            _scan_c(rel, src, emit)
        elif ext == 'go':
            _scan_go(rel, src, emit)

    out = []
    for g in groups.values():
        g['lines'] = sorted(g['lines'])
        g['raw']['rules'] = sorted(g['raw']['rules'])
        g['raw']['rule_lines'] = {
            rule: sorted(lines) for rule, lines in
            sorted(g['raw']['rule_lines'].items())}
        out.append(g)
    return out
