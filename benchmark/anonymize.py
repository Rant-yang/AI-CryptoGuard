"""把 benchmark 的源码树匿名化 —— 跑分前必须做，否则指标是假的。

**为什么必须做**
----------------
这些 benchmark 的命名**直接就是答案**：

    src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java
                      ^^^^^^^^^^^ 包名=类别      ^^^^^^^^^^^^^^^^^^^ 类名=类别

    Dsub/crawl/nomisuses/          ← 这个目录名意思是「这些是干净样本」
    Cambench_Cap/basic/ecbmode/CorrectedEcbMode.java   ← Corrected = 正确写法

我们的 `ai/redact.py` 保留 `basename(path)` —— 那是**生产环境**的正确行为
（用户要知道是哪个文件）。但跑 benchmark 时，文件名会把答案直接送进提示词，
大模型照着念就能「检测」出来。**指标会虚高，而评委问一句就崩。**

**所以这里是两套模式，不是改产品：**
    生产管线  —— 保留文件名（用户需要）
    benchmark —— 匿名化（不然没有意义）

改三个地方，缺一不可
--------------------
1. **文件名** —— `BrokenCryptoABICase1.java` -> `f0001.java`
2. **目录名** —— `brokencrypto/` -> `d003/`，`nomisuses/` 尤其致命
3. **文件内容** —— `public class BrokenCryptoABICase1` 和
   `package org.cryptoapi.bench.brokencrypto;` 都在源码里，光改路径不够

映射表写到 `_anon/<name>.map.json`，**放在仓库外** ——
它把匿名名映射回原名，等于另一份答案。

⚠️ 已知取舍：重命名目录会破坏 Java 的包结构，**扫过的树编译不过**。
   这是可接受的：我们的证据类型目前 100% 是 `pattern`（正则），
   不需要编译。但 **CrySentry 走字节码，用不了这棵树** —— 它要 .jar。
   将来若要跑字节码工具，得另想办法（例如只改内容不改路径）。
"""

import json
import os
import re
import shutil

#: 参与匿名化的源码扩展名
SOURCE_EXT = {'.java', '.py', '.c', '.cpp', '.cc', '.h', '.hpp', '.go', '.js'}

#: 匿名名长度。够用即可，长了没用。
ID_WIDTH = 4

#: 这些词出现在**路径或源码标识符**里就说明答案漏了。
#: 唯一权威来源 —— 清理和检查都用这一份，避免两边各写一套然后对不上。
LEAK_WORDS = [
    'brokencrypto', 'brokenhash', 'brokenmac', 'ecbcrypto', 'ecbmode',
    'staticinitializationvector', 'staticsalts', 'predictableseeds',
    'predictablecryptographickey', 'predictablepbepassword',
    'predictablekeystorepassword', 'credentialinstring', 'untrustedprng',
    'dummycertvalidation', 'dummyhostnameverifier',
    'impropersslsocketfactory', 'insecureasymmetriccrypto',
    'pbeiteration', 'smallkeysize', 'insecurerandom', 'staticiv',
    'nomisuses', 'corrected', 'misuse',
]

#: 注释里用的普通标识符正则。注释里没有字符串转义，不需要状态机。
_IDENT_RE = re.compile(r'[A-Za-z_]\w*')

#: 注意：主体扫描**故意不用一条大正则**。
#:
#: 最初的写法是一条正则：
#:     "(?:\\.|[^"\\])*" | '(?:\\.|[^'\\])*' | //[^\n]* | /\*.*?\*/ | [A-Za-z_]\w*
#: 它被一个撇号打穿了 —— Java 文件里某个 `'` 被当成「单引号字符串」的开头，
#: 一路吞掉十几行。正则做不了「未闭合就退回」这件事，所以改成状态机逐字符扫。
#:
#: 三类的处理**不一样**，这是有意的：
#:     标识符  清 —— 类名/包名里就写着答案
#:     注释    清 —— 没证据价值，却会写「这是修正版」（实测踩到）
#:     字符串  留 —— `"AES/CBC/PKCS5Padding"` 是扫描证据本身，改了就没得扫


def _is_leaky(ident):
    low = ident.lower()
    return any(w in low for w in LEAK_WORDS)


class AnonMap:
    """原名 -> 匿名名 的双向映射。"""

    def __init__(self, benchmark):
        self.benchmark = benchmark
        self.files = {}   # 原相对路径 -> 新相对路径
        self.dirs = {}    # 原相对路径(目录) -> 新相对路径
        self.tokens = {}  # 需要替换的源码标识符 -> 替换成什么

    def to_json(self):
        return {
            'benchmark': self.benchmark,
            'files': self.files,
            'dirs': self.dirs,
            'tokens': self.tokens,
            '_note': '本文件把匿名名映射回原名，等价于另一份答案 —— '
                     '只放在仓库外，绝不可入库，也不可给大模型看。',
        }


def _is_source(name):
    return os.path.splitext(name)[1].lower() in SOURCE_EXT


def _sanitize_source(text, amap):
    """把源码里**含泄漏词的标识符**换成中性名。

    为什么不是「拿文件名去替换」
    ---------------------------
    最初的写法是收集一批 token（文件名、目录名）再逐个 replace。**它漏了**，
    而且是自检抓出来的，不是我想到的：

        L21  class CryptoPBEIteration1 {     ← 文件里的**内部类**，不是文件名
        L15  crypto = new CryptoPBEIteration1(20);

    内部类名、以及大小写不同的变体（目录叫 `pbeiteration`，
    类叫 `PBEIteration`）全都漏网。手工 token 表**必然**会漏 ——
    因为它要靠人去枚举所有变体。

    所以改成**从 LEAK_WORDS 反推**：只要一个标识符**含有**泄漏词
    （不分大小写），整个标识符换掉。这样变体再多也躲不掉。

    字符串与注释**不动** —— `Cipher.getInstance("AES/ECB/PKCS5Padding")`
    里的字符串是扫描证据本身，改了就没得扫了。`_LEX` 靠把字面量
    排在标识符前面来保证这一点。

    映射是稳定的（同一个标识符永远换成同一个名字），
    所以替换后代码虽然编译不过，但结构还读得懂，便于人工复核。
    """
    def rename(tok):
        # Compile-compatible paired cohorts may pre-register public class
        # names. Honor those explicit aliases before the generic leak-word
        # rule so class references and declarations receive the same name.
        if tok in amap.tokens:
            return amap.tokens[tok]
        if not _is_leaky(tok):
            return tok
        if tok not in amap.tokens:
            amap.tokens[tok] = 'X%0*d' % (ID_WIDTH, len(amap.tokens) + 1)
        return amap.tokens[tok]

    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]

        # 行注释：吃到行尾。**注释要清，不能原样留** ——
        # 实测踩到过：文件里有一段被注释掉的原始类
        #     /*
        #     public class StaticInitializationVectorCorrected {
        # 注释里没有扫描证据，却把「这是修正版」直接写在那儿。
        # 注释里不会有字符串转义，所以这里用普通标识符正则扫一遍就够了。
        if c == '/' and i + 1 < n and text[i + 1] == '/':
            j = text.find('\n', i)
            j = n if j < 0 else j
            out.append(_IDENT_RE.sub(lambda m: rename(m.group(0)), text[i:j]))
            i = j; continue

        # 块注释：吃到 */
        if c == '/' and i + 1 < n and text[i + 1] == '*':
            j = text.find('*/', i + 2)
            j = n if j < 0 else j + 2
            out.append(_IDENT_RE.sub(lambda m: rename(m.group(0)), text[i:j]))
            i = j; continue

        # 字符串 / 字符字面量：原样保留（里面的算法名是扫描证据，改了就没得扫）
        if c in '"\'':
            q, j = c, i + 1
            while j < n:
                if text[j] == '\\':
                    j += 2; continue
                if text[j] == q:
                    j += 1; break
                # **未闭合**（常见于注释里的撇号）→ 到行尾就放弃，
                # 当作普通字符处理。正则做不到这一点，就是这里漏的。
                if text[j] == '\n':
                    break
                j += 1
            if j <= n and j > i and text[j - 1:j] == q:
                out.append(text[i:j]); i = j; continue
            out.append(c); i += 1; continue

        # 标识符
        if c.isalpha() or c == '_':
            j = i
            while j < n and (text[j].isalnum() or text[j] == '_'):
                j += 1
            out.append(rename(text[i:j])); i = j; continue

        out.append(c); i += 1

    return ''.join(out)


def anonymize_tree(src_root, dst_root, benchmark, map_path=None, subtree=''):
    """把 src_root 匿名化复制到 dst_root。

    Args:
        src_root: 原始树（`_benchmarks/<name>`）
        dst_root: 输出树（`_benchmarks/_anon/<name>`），会被清空重建
        benchmark: benchmark 名，用于编号前缀
        map_path: 映射表输出路径；None 则与 dst_root 同级
        subtree: **只匿名化这个子树**。空串 = 整棵树。
                 必须只扫有标签的那部分 —— 否则没标签的文件
                 会把 Precision 稀释掉，而那个数字毫无意义。

    Returns:
        AnonMap（路径均相对 **subtree 的根**）
    """
    src_root = os.path.abspath(src_root)
    dst_root = os.path.abspath(dst_root)
    if not os.path.isdir(src_root):
        raise NotADirectoryError('找不到 benchmark 源目录: %s' % src_root)

    walk_root = os.path.join(src_root, subtree) if subtree else src_root
    if not os.path.isdir(walk_root):
        raise NotADirectoryError('subtree 不存在: %s' % walk_root)

    # 安全检查：绝不往源树里写
    if dst_root.startswith(walk_root + os.sep) or dst_root == walk_root:
        raise ValueError('输出目录不能位于源目录内部: %s' % dst_root)

    if os.path.isdir(dst_root):
        shutil.rmtree(dst_root)
    os.makedirs(dst_root)

    amap = AnonMap(benchmark)

    # ---- 第一趟：收集路径，分配匿名名 ----
    # 先给目录编号。`.` 之外的每一层目录都换名，保持层级但抹掉语义。
    all_dirs = []
    all_files = []
    for dirpath, dirnames, filenames in os.walk(walk_root):
        dirnames[:] = [d for d in dirnames if d != '.git']
        # **一律归一成正斜杠**。Windows 上 os.walk / relpath 给的是反斜杠，
        # 而后面算文件所在目录时用的是正斜杠 —— 两边不一致的话
        # `amap.dirs.get(d)` 永远查不到，整棵树会被**拍平**到根目录。
        # 实测就是这么拍平的：203 个 java 全躺在匿名树根下，
        # 于是不同 benchmark 的 `f0008.java` 互相撞名，
        # 评测时 cryptoapi-bench 的检出被算到 cambench-cap 头上。
        rel = os.path.relpath(dirpath, walk_root).replace('\\', '/')
        if rel != '.':
            all_dirs.append(rel)
        for fn in filenames:
            if fn == '.git':
                continue
            all_files.append(rel + '/' + fn if rel != '.' else fn)

    # 目录逐个编号，且**同一层前缀复用同一个号** —— 这样层级关系保留，
    # 但名字完全不带语义。
    dir_index = {}
    for rel in sorted(all_dirs):
        parts = rel.split('/')
        new_parts = []
        for depth in range(len(parts)):
            prefix = '/'.join(parts[:depth + 1])
            if prefix not in dir_index:
                dir_index[prefix] = 'd%03d' % (len(dir_index) + 1)
            new_parts.append(dir_index[prefix])
        amap.dirs[rel] = '/'.join(new_parts)

    # 文件名带一个**每个 benchmark 不同**的短标签，避免跨 benchmark 撞名。
    # 撞名会让评测把 A 的检出算到 B 头上（实测踩过）。
    # 用哈希而不是可读名：虽然「这是哪个 benchmark」不是我们要藏的答案，
    # 但没必要给出去。
    import hashlib
    tag = hashlib.sha1(benchmark.encode('utf-8')).hexdigest()[:3]

    anon_files = {}
    for i, rel in enumerate(sorted(all_files), 1):
        d = rel.rsplit('/', 1)[0] if '/' in rel else ''
        new_dir = amap.dirs.get(d, '')
        stem, ext = os.path.splitext(rel.rsplit('/', 1)[-1])
        new_name = '%s%0*d%s' % (tag, ID_WIDTH, i, ext)
        new_rel = (new_dir + '/' + new_name) if new_dir else new_name
        anon_files[rel] = new_rel
    amap.files = anon_files

    # ---- 第二趟：写文件，顺便清理源码里的泄漏标识符 ----
    for rel_norm, new_rel in anon_files.items():
        s = os.path.join(walk_root, rel_norm.replace('/', os.sep))
        d = os.path.join(dst_root, new_rel.replace('/', os.sep))
        os.makedirs(os.path.dirname(d), exist_ok=True)
        if _is_source(rel_norm):
            with open(s, 'r', encoding='utf-8', errors='replace') as f:
                text = f.read()
            text = _sanitize_source(text, amap)
            with open(d, 'w', encoding='utf-8') as f:
                f.write(text)
        else:
            shutil.copy2(s, d)

    if map_path is None:
        map_path = os.path.join(os.path.dirname(dst_root),
                                '%s.map.json' % benchmark)
    os.makedirs(os.path.dirname(map_path), exist_ok=True)
    with open(map_path, 'w', encoding='utf-8') as f:
        json.dump(amap.to_json(), f, ensure_ascii=False, indent=2)

    amap.map_path = map_path
    return amap


def leak_check(text):
    """在匿名化之后的文本里找残留的泄漏词。

    **与数据无关**的兜底检查：不管扫哪个 benchmark，只要路径或源码里
    还留着这些词，就说明匿名化漏了。用的是模块级的 `LEAK_WORDS` ——
    与清理逻辑同一份，避免两边各写一套然后对不上（`scope.py` 的学习）。
    """
    low = text.lower()
    return [w for w in LEAK_WORDS if w in low]


def _selftest():
    """自检：拿一个真 benchmark 跑一遍匿名化，再验证泄漏词确实没了。

    **不是复述实现，是端到端验一件事：匿名化之后还能不能看出答案。**
    """
    import tempfile
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = os.path.join(os.path.dirname(here), '_benchmarks', 'CryptoAPI-Bench')
    if not os.path.isdir(src):
        print('[SKIP] 找不到 %s，跳过（先跑 benchmark/fetch.sh 下载）' % src)
        return True

    fails = []
    tmp = tempfile.mkdtemp(prefix='anon-selftest-')
    dst = os.path.join(tmp, 'out')
    amap = anonymize_tree(src, dst, 'cryptoapi-bench',
                          map_path=os.path.join(tmp, 'map.json'))

    # 1) 原树的路径里**必须**能看出答案（否则这个测试没有意义 ——
    #    如果原树本来就不泄漏，那匿名化通过也证明不了什么）
    orig_leaks = [p for p in amap.files if leak_check(p)]
    if not orig_leaks:
        fails.append('原树里居然找不到泄漏词 —— 测试前提不成立，请检查')

    # 2) 匿名化之后的路径与内容里**必须**一个都找不到
    str_lit = re.compile(r'"(?:\\.|[^"\\])*"')
    n_str_checked = 0
    for dirpath, _, filenames in os.walk(dst):
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            # 归一成正斜杠再比对 —— `amap.files` 的值是正斜杠，
            # 用 OS 默认分隔符查会**永远查不到**，那样下面第 3 条
            # 「字面量未被改动」会静默退化成空断言（实测从 353 掉到 0）。
            rel = os.path.relpath(full, dst).replace('\\', '/')
            hits = leak_check(rel)
            if hits:
                fails.append('路径仍泄漏: %s -> %s' % (rel, hits))
            if not _is_source(fn):
                continue
            with open(full, 'r', encoding='utf-8', errors='replace') as f:
                text = f.read()
            hits = leak_check(text)
            if hits:
                fails.append('内容仍泄漏: %s -> %s' % (rel, hits))

            # 3) **反向不变量**：字符串字面量必须一个都没动。
            #    这是「只查泄漏没了」那半边测试的补集 —— 光查泄漏，
            #    把整个文件清空也能过。而字符串正是扫描证据本身
            #    （`"AES/CBC/PKCS5Padding"`），动了 benchmark 就废了。
            orig_rel = next((k for k, v in amap.files.items() if v == rel), None)
            if orig_rel:
                with open(os.path.join(src, orig_rel.replace('/', os.sep)),
                          'r', encoding='utf-8', errors='replace') as f:
                    orig_text = f.read()
                a, b = sorted(str_lit.findall(orig_text)), sorted(str_lit.findall(text))
                if a != b:
                    missing = [s for s in a if s not in b][:3]
                    fails.append('字符串字面量被改动了: %s 丢了 %s' % (rel, missing))
                n_str_checked += len(a)

    # 4) 「比了 0 条」本身要算失败。
    #    上面第 3 条曾经因为路径分隔符不匹配而**默默退化成空断言**：
    #    一个字面量都没比，却报 PASS。空断言比没有断言更危险 ——
    #    它给人「检查过了」的错觉。
    if n_str_checked == 0:
        fails.append('字面量核对一条都没比到 —— 第 3 条断言已失效')

    shutil.rmtree(tmp, ignore_errors=True)

    if fails:
        print('[FAIL] anonymize.py 自检未通过:')
        for f in fails[:10]:
            print('  - ' + f)
        return False
    print('[PASS] anonymize.py 自检通过  '
          '（原树 %d 个泄漏路径 -> 匿名化后 0 个；'
          '另核对 %d 个字面量未被改动）' % (len(orig_leaks), n_str_checked))
    return True


if __name__ == '__main__':
    import sys
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except (AttributeError, OSError):
        pass
    sys.exit(0 if _selftest() else 1)
