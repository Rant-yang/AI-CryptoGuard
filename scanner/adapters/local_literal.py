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
    R3 JCE getInstance 参数经传播解析到词表内算法（callee 侧/间接链）
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
已有分组时本源让位（merge 侧剔除）——只补盲区。只扫 .java（三个
benchmark 语料都是 Java；Python/Go 的汇点形态不同，后续按需扩）。
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
#: 实测 `Integer.parseInt(String.valueOf(x))` 就是两层）
_PBE_HEAD_RE = re.compile(r'\bnew\s+PBEParameterSpec\s*\(')


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

_MAX_FILE_BYTES = 8 * 1024 * 1024   # 防单个巨型生成文件拖垮全文扫描
_MAX_FIXED_ROUNDS = 12              # 不动点迭代上限（变量链长度天花板）

_INT_RE = re.compile(r'^\d+$')


def _line_of(text, pos):
    return text.count('\n', 0, pos) + 1


def _strip_strings(s):
    """把字符串字面量的内容抹成等长下划线。

    两层作用: 防止字面量里的逗号/括号干扰实参切分与配平；
    **等长**替换保证抹掉后的偏移仍对齐原文 —— 行号才不会错位。
    """
    return re.sub(r'"(?:\\.|[^"\\])*"',
                  lambda m: '"' + '_' * (len(m.group(0)) - 2) + '"', s)


def _split_args(raw):
    """实参/形参列表 -> 各段 trim 后的列表（空串守卫）。"""
    if not raw or not raw.strip():
        return []
    return [p.strip() for p in _strip_strings(raw).split(',') if p.strip()]


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
        （「解析不到就不报」）。支持:
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
            assigns.append((m.group(1), m.group(2).strip()))
        self.puts = [(m.group(1), m.group(2), m.group(3).strip()) for m in re.finditer(
            r'\b(\w+)\s*\.\s*put\s*\(\s*"((?:\\.|[^"\\])*)"\s*,\s*'
            r'((?:[^()]|\([^()]*\))*)\)', src)]
        puts = self.puts
        calls = [(m.group(1), m.group(2), _split_args(m.group(3)), m.start())
                 for m in _CALL_RE.finditer(text)]
        methods = self.methods

        for _ in range(_MAX_FIXED_ROUNDS):
            changed = False
            for var, expr in assigns:
                val = self._eval_expr(expr, self.env, puts)
                if val is not None and self.env.get(var) != val:
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

    def emit(info, alg_display, lines, why, risk='broken'):
        alg_norm = canon_algorithm(alg_display)
        key = (info.rel, alg_norm)
        g = groups.get(key)
        if g is None:
            g = {
                'tool': TOOL_NAME,
                'file': info.rel,
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
                        'rules': set()},
            }
            groups[key] = g
        g['lines'].update(lines)
        g['raw']['rules'].add(why)

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

        # R1: 同文件词表字面量 + JCE 汇点（原始规则，传播失败时的兜底）
        if has_sink:
            for m in _STRING_RE.finditer(src):
                tok = norm_algorithm(m.group(1).split('/', 1)[0])
                if tok in BROKEN_ALGORITHMS:
                    emit(info, m.group(1).split('/', 1)[0],
                         [_line_of(src, m.start())] +
                         [_line_of(src, p) for p in sink_lines], 'R1')

        # R2: 词表字面量绑定的变量被作为方法实参传出（caller 侧）。
        # 只认接收者是**树内类**的调用（`new T()` 的实例方法 / 类名静态调用）
        # —— 传给库方法（log/put 等）的字面量不是「算法在项目内落地」
        project_calls = []
        for m in _CALL_RE.finditer(_strip_strings(src)):
            recv, meth, args = m.group(1), m.group(2), _split_args(m.group(3))
            cls = info.recv_types.get(recv) or (recv if recv in class_owner else None)
            if cls and cls in class_owner:
                project_calls.append((args, m.start()))
        for var, val in sorted(env.items()):
            if val[0] != 'str' or norm_algorithm(
                    val[1].split('/', 1)[0]) not in BROKEN_ALGORITHMS:
                continue
            for args, pos in project_calls:
                if var in args:            # 裸标识符精确匹配实参位
                    emit(info, val[1].split('/', 1)[0],
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
            tok = norm_algorithm(val[1].split('/', 1)[0])
            if tok in BROKEN_ALGORITHMS:
                emit(info, val[1].split('/', 1)[0],
                     [_line_of(src, m.start())], 'R3')
                continue
            # R5: 解析值是转换串且模式段为 ECB —— ECB 模式与密钥强度
            # 无关的确定性弱点。报「算法/ECB」（norm 后与标签口径一致，
            # 如 AES/ECB -> AESECB）；risk 用 review（模式误用待复核，
            # 与 CryptoScan 对 ECB 类的打分档一致）
            segs = val[1].split('/')
            if len(segs) >= 2 and segs[1].upper() == 'ECB':
                emit(info, segs[0] + '/ECB', [_line_of(src, m.start())], 'R5',
                     risk='review')

        # R4: PBEParameterSpec 低迭代（< 1000）。必须解析到**传给它的
        # 那个实参**的常量值 —— 同文件任意小数字会误伤 corrected 负样本
        # （实测它们有 byte[32]/put("x",2) 这类无关小数字）。
        # PBKDF2 本身是健全 KDF，风险是实现误用 -> review（不是 broken）。
        # 实参用括号配平取 —— 实测 `Integer.parseInt(String.valueOf(count))`
        # 是两层嵌套，正则实参组容不下
        text = _strip_strings(src)
        for m in _PBE_HEAD_RE.finditer(text):
            args_raw, end = _paren_span(text, m.end() - 1)
            if args_raw is None:
                continue
            # _strip_strings 是等长替换 -> 偏移与原文对齐, 回原文取实参
            # （保留字符串字面量, 供 _eval_expr 的 map get/put 匹配）
            args = _split_args(src[m.end():end - 1])
            if len(args) < 2:
                continue
            val = info._eval_expr(args[1], env, info.puts)
            n = None
            if val:
                if val[0] == 'int':
                    n = val[1]
                elif val[0] == 'str' and _INT_RE.match(val[1]):
                    n = int(val[1])
            if n is not None and n < 1000:
                emit(info, 'PBKDF2', [_line_of(src, m.start())], 'R4',
                     risk='review')
                # 反向标注: 迭代数常量若来自 caller 实参（跨文件一跳绑定）,
                # caller 文件同样产一条 —— a1e0130 形态（caller 只传数字,
                # PBE 汇点在 callee, benchmark 标签挂在 caller 文件上）
                if re.fullmatch(r'\w+', args[1]) and args[1] in info.arg_from:
                    crel, cline = info.arg_from[args[1]]
                    caller = infos.get(crel)
                    if caller is not None:
                        emit(caller, 'PBKDF2', [cline], 'R4x', risk='review')

    out = []
    for g in groups.values():
        g['lines'] = sorted(g['lines'])
        g['raw']['rules'] = sorted(g['raw']['rules'])
        out.append(g)
    return out
