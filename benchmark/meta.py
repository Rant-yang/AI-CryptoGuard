"""从 benchmark **自带的元数据**里读逐文件真值 —— 算法清单不许手写。

为什么要有这个文件
------------------
2026-10-04 复核发现：`scope.py` 里每个类别的算法清单是**人手写死的**，
而手写的清单会漂。写的是 `cambench-cap/brokencrypto -> (DES, 3DES)`，
可那个目录里实际躺着 DES / Blowfish / RC2 / RC4 / RC5 五种
（CamBench 自己的 `BrokenCrypto{2,3,4,5}_meta1.yaml` 逐条写了）。

后果不是「少认一条」那么轻 —— 一次**正确的** Blowfish 检出会被同时记成
漏报（Recall ↓）和误报（Precision ↓），一笔扣两次。

所以规矩改成：**算法从 benchmark 自己的元数据里读。**

    关键区分 —— 这是**事实**与**翻译**的区别：

      · 「brokencrypto 这个类别里有哪些算法」= **事实**
        事实只能去读数据，人一写就会错。
      · 「benchmark 说 `DES used`，我方叫 `DES`」= **翻译**
        翻译必须人写，因为两边的词汇表本来就不一样。

    本文件负责「事实」；`scope.py` 只保留「翻译」与裁定。
    两者的**一致性由自检强制**（见 `scope._selftest`）——
    人写的声明和机器抽的事实对不上就报错，而不是悄悄按人写的算。

数据来源
--------
    CamBench_Cap    每个 `.java` 旁边有 `*_meta*.yaml`，
                    其中 `description` 逐条点名算法（`(Blowfish)`），
                    且 `crypto-usage.location.line` 给了**精确行号**。
    CryptoAPI-Bench `CryptoAPI-Bench_details.xlsx` 的 `Vulnerabilities` 表，
                    逐文件的 `Type of Vulnerability`（`DES used`）、
                    `Vulnerability Exists?`、`Line number`。

    LLM-CMT / CamBench_Real 的标签本身就是逐文件的（自由文本 / FUM），
    不经过本文件 —— 它们已经在 `adapters.py` 里逐条读。

⚠️ `_benchmarks/` **不在仓库里**（数据是从第三方派生的，见 .gitignore）。
   所以本文件的每个入口在数据缺席时必须**返回空**而不是抛错，
   并且调用方必须**明说「跳过了什么」** —— 不许把「没数据」说成「一致」。
"""

import glob
import os
import re

#: 四个 benchmark 的克隆目录名（与 adapters.ADAPTERS 一致）
CRYPTOAPI_BENCH = 'CryptoAPI-Bench'
CAMBENCH_CAP_SUBTREE = 'CamBench/CamBench_Cap/src/main/java/org/cambench/cap/basic'


def default_bench_dir():
    """`<仓库父目录>/_benchmarks` —— 数据不在仓库里。

    本文件在 `<仓库>/benchmark/meta.py`，所以要退**三级**才到仓库的父目录。
    （`adapters.py` 的 `__main__` 里是同一个算式，两边必须一致。）
    """
    here = os.path.dirname(os.path.abspath(__file__))          # <仓库>/benchmark
    repo = os.path.dirname(here)                              # <仓库>
    return os.path.join(os.path.dirname(repo), '_benchmarks')  # <仓库父目录>/_benchmarks


def _norm_rel(p):
    return str(p).replace('\\', '/').lstrip('./')


def _algo(name):
    """算法名归一 —— 与 `eval._norm_algo` 同一口径：只留字母数字，转大写。"""
    return ''.join(ch for ch in str(name).upper() if ch.isalnum())


# ------------------------------------------------------------------ 翻译表

#: CryptoAPI-Bench `Type of Vulnerability` -> 我方算法名。
#:
#: **这是翻译，不是事实** —— 左边是 benchmark 的原话，右边是我方的写法。
#: 顺序有意义（先匹配先赢）。
CRYPTOAPI_VULN_TO_ALGO = (
    # 「DES used」/「Blowfish used」/「MD4 used」…… 这个名字直接就是算法
    (re.compile(r'^([A-Za-z][A-Za-z0-9\-]*)\s+used$'), None),
    # 「Usage of ECB」-> 工作模式，我方记为 AESECB（与 scope 的 ecbcrypto 同口径）
    (re.compile(r'^Usage of ECB$'), 'AESECB'),
    # 「RSA keysize 1024 bits」-> 算法是 RSA，位数是参数（参数我们不校验）
    (re.compile(r'^(RSA)\s+keysize\b'), 'RSA'),
    # 「PBE iteration < 1000」-> PBE 家族，我方规则库只有 PBKDF2 一条
    (re.compile(r'^PBE iteration\b'), 'PBKDF2'),
    (re.compile(r'^Hmac\.?(MD5|SHA1|SHA256)$', re.I), None),   # HmacMD5 -> MD5？
)

#: **明确不指向任何算法**的 `Type of Vulnerability` 取值。
#:
#: 必须逐条列出来，而不是「不在上表里就算 None」——
#: 那样新冒出来的取值会被静默当成「没有算法」，正确做法是报 unknown。
#: （与 `scope.verdict_for` 拒绝未裁定类别是同一条原则。）
CRYPTOAPI_NOT_ALGO = {
    '---',                                  # benchmark 自己留的空占位
    'Constant Seed', 'Static/Constant Password', 'Static/Constant IV',
    'Static/Contant Key', 'Static/Contant password', 'Static/Constant Salt',
    'Static/Constant Key',
    'Credential in String', 'HTTP',
    'Dummy Certificate', 'Dummy Verifier',
    'Socket Hostname w/o verification',
    'Usage of Random Method from Library',
}

#: `HmacMD5` 这类要还原成哪个我方算法名。
#:
#: 记**底层哈希还是 HMAC 本身**，两处口径必须一致：
#: `scope.CRYPTOAPI_BENCH['brokenmac']` 声明的是 `HMAC`，
#: 而 `scope.LLMCMT_LABEL_KEYWORDS['hmacmd5']` 声明的是 `MD5` ——
#: 这处不一致是**已知待收口项**，不在这里偷偷选一个。
_HMAC_AS = 'hmac'                            # 'hmac' | 'underlying'


def _hmac_name(algo):
    """`MD5` -> `HMACMD5` 或 `MD5`，取决于 `_HMAC_AS`。"""
    return ('HMAC' + algo) if _HMAC_AS == 'hmac' else algo


#: CamBench_Cap `description` -> 我方算法名。
#:
#: 描述是**模板句**，实测全部落在下面三条里（见模块 docstring 的样例）。
#: 顺序有意义：「ECB mode」必须排在「The AES algorithm」前面 ——
#: `EcbMode1` 的描述是「The AES algorithm is configured and initialized
#: with the ECB mode of operation.」，先撞上 AES 就把**模式问题**错记成算法问题了。
CAMBENCH_CAP_PATTERNS = (
    (re.compile(r'\bECB mode\b', re.I), 'AESECB'),
    # 「an insecure algorithm (DES)」「a secure cipher (AES/GCM/NoPadding)」
    (re.compile(r'\b(?:algorithm|cipher)\s*\(([^)]+)\)', re.I), None),
    # 「The RSA algorithm is initialized with a key size (1024 bits)」
    (re.compile(r'\bThe\s+([A-Za-z0-9]+)\s+algorithm\b'), None),
)


def _cap_algo_from_description(desc):
    """从 CamBench_Cap 的描述里取算法名。取不到就返回 None（不猜）。"""
    for pat, fixed in CAMBENCH_CAP_PATTERNS:
        m = pat.search(desc)
        if not m:
            continue
        raw = fixed if fixed else m.group(1)
        # 「AES/GCM/NoPadding」-> 取第一段；模式/填充由 scope 的类别裁定管，
        # 不在这里重复判断。
        return _algo(raw.split('/')[0])
    return None


# ------------------------------------------------------------------ 抽取

def cambench_cap_meta(src_root):
    """抽 CamBench_Cap 的逐文件真值。

    Args:
        src_root: subtree 根（`.../cap/basic`），与 `adapters` 传进来的一致。

    Returns:
        (index, unknown)
          index   {相对 src_root 的路径: {'algorithms', 'line', 'violation'}}
          unknown [(文件, 原因)] —— **不静默丢弃**
    """
    index, unknown = {}, []
    try:
        import yaml
    except ImportError:
        return {}, [('(全部)', '缺少 PyYAML，CamBench_Cap 元数据未读（pip install pyyaml）')]

    pat = os.path.join(src_root, '**', '*_meta*.yaml')
    for path in sorted(glob.glob(pat, recursive=True)):
        rel = _norm_rel(os.path.relpath(path, src_root))
        stem = os.path.basename(rel)
        # `BrokenCrypto1_meta1.yaml` -> `BrokenCrypto1.java`
        java_stem = re.split(r'_meta\d*', os.path.splitext(stem)[0])[0]
        if not java_stem:
            unknown.append((rel, '元数据文件名里取不出用例名'))
            continue
        java_rel = _norm_rel(os.path.join(os.path.dirname(rel), java_stem + '.java'))

        try:
            with open(path, encoding='utf-8', errors='replace') as f:
                doc = yaml.safe_load(f) or {}
        except Exception as e:                              # noqa: BLE001
            unknown.append((rel, 'yaml 解析失败: %s' % e))
            continue

        usage = doc.get('crypto-usage') or {}
        desc = ' '.join(str(doc.get('description') or '').split())
        alg = _cap_algo_from_description(desc)

        loc = usage.get('location') or {}
        try:
            line = int(loc.get('line') or 0) or None
        except (TypeError, ValueError):
            line = None

        rec = index.setdefault(java_rel, {'algorithms': set(), 'line': None,
                                          'violation': None, 'descriptions': []})
        if alg:
            rec['algorithms'].add(alg)
        rec['descriptions'].append(desc)
        if line and rec['line'] is None:
            rec['line'] = line
        # 一个用例可能有多个 meta（meta1/meta2 分别标 cipher 与 KeyGenerator），
        # 只要有一条说 violation，就该用例就是误用。
        rec['violation'] = bool(usage.get('violation')) or bool(rec['violation'])

    for rec in index.values():
        rec['algorithms'] = tuple(sorted(rec['algorithms']))
    return index, unknown


def cryptoapi_bench_meta(src_root, xlsx_path):
    """抽 CryptoAPI-Bench 的逐文件真值（读 `_details.xlsx`）。

    类别从**真实目录**取（`.../bench/<类别>/`），算法/存在性/行号从 xlsx 取。
    两边靠**文件名**对上。

    Returns:
        (index, unknown)；index 的键是相对 src_root 的路径。
    """
    index, unknown = {}, []
    if not os.path.isfile(xlsx_path):
        return {}, [('(xlsx)', '找不到 %s' % xlsx_path)]
    try:
        import openpyxl
    except ImportError:
        return {}, [('(xlsx)', '缺少 openpyxl，CryptoAPI-Bench 元数据未读')]

    # ---- 先按用例名读 xlsx
    #
    # ⚠️ `Files` 单元格**一格可以装两个文件名**，用换行分隔 ——
    #    `Multiple java classes` 那批就是这样：
    #      "PredictableCryptographicKeyABMCCase1.java\n
    #       PredictableCryptographicKeyABMC1.java"
    #    一个 Case 文件 + 一个它调用的辅助类，同一行元数据管两个文件。
    #    早先按单元格整体取 basename，这 55 个文件全部落成「xlsx 里没有」。
    #    另外有的格子**不带 `.java` 后缀**（`EcbInSymmCryptoABMCCase1`），
    #    所以一律按**去后缀的名字**对齐。
    wb = openpyxl.load_workbook(xlsx_path, read_only=True, data_only=True)
    ws = wb['Vulnerabilities'] if 'Vulnerabilities' in wb.sheetnames else wb.worksheets[0]
    by_name, dup = {}, []
    for i, row in enumerate(ws.iter_rows(values_only=True)):
        if i == 0:
            continue
        fname, exists, vtype, line_raw = row[1], row[3], row[4], row[6]
        if not fname:
            continue
        vtype = (str(vtype).strip() if vtype is not None else '')
        alg, matched = _cryptoapi_vuln_to_algo(vtype)
        if not matched:
            unknown.append((str(fname), 'Type of Vulnerability 未收录: %r' % vtype))
            continue
        rec = {
            'algorithms': (alg,) if alg else (),
            'violation': str(exists).strip().lower() == 'true',
            'line': _first_int(line_raw),
            'vuln_type': vtype,
        }
        for one in str(fname).split('\n'):
            stem = os.path.splitext(one.strip())[0]
            if not stem:
                continue
            if stem in by_name:
                # 同一个用例被两行覆盖（meta 粒度差异）—— 冲突要看得见
                dup.append(stem)
                continue
            by_name[stem] = rec

    # ---- 再走真实目录：类别从路径取，元数据按用例名挂上去
    for path in sorted(glob.glob(os.path.join(src_root, '**', '*.java'),
                                 recursive=True)):
        rel = _norm_rel(os.path.relpath(path, src_root))
        parts = rel.split('/')
        cat = None
        for i, seg in enumerate(parts):
            if seg == 'bench' and i + 1 < len(parts):
                cat = parts[i + 1]
                break
        if cat is None:
            continue
        stem = os.path.splitext(os.path.basename(rel))[0]
        rec = by_name.get(stem)
        if rec is None:
            unknown.append((rel, 'xlsx 里没有这个用例'))
            continue
        entry = dict(rec)
        entry['category'] = cat
        index[rel] = entry

    for stem in sorted(set(dup)):
        unknown.append((stem, 'xlsx 里被两行覆盖（元数据粒度不一致）'))
    return index, unknown


def _cryptoapi_vuln_to_algo(vtype):
    """`Type of Vulnerability` -> (算法名 or None, 是否已收录)。

    第二项为 False 表示**这个取值我们没见过** —— 调用方必须报 unknown，
    不能当成「没有算法」放过去。
    """
    if vtype in CRYPTOAPI_NOT_ALGO:
        return None, True
    for pat, fixed in CRYPTOAPI_VULN_TO_ALGO:
        m = pat.match(vtype)
        if not m:
            continue
        if fixed:
            return fixed, True
        if pat.pattern.startswith('^Hmac'):
            return _hmac_name(_algo(m.group(1))), True
        return _algo(m.group(1)), True
    return None, False


def _first_int(raw):
    """`Line number` 列取值很脏：可能是 `16, 22`，也可能是日期。

    只接受纯数字/逗号/空格的写法，取第一个数；其余一律 None（不猜）。
    实测 xlsx 第 1 行那个格子装的是 `2019-09-12 00:00:00` —— 日期落进了行号列。
    """
    s = str(raw).strip() if raw is not None else ''
    if not s or not re.match(r'^[\d,\s]+$', s):
        return None
    for tok in re.split(r'[,\s]+', s):
        if tok.isdigit():
            return int(tok)
    return None


# ------------------------------------------------------------------ 自检

def _selftest(bench_dir=None):
    """**真去读一次数据**，而不是复述本文件的实现。

    数据不在（`_benchmarks/` 未下载）时**明说跳过了什么**，
    绝不打印「一致」—— 「比较了 0 项」本身就必须是问题。
    """
    bench_dir = bench_dir or default_bench_dir()
    fails, notes = [], []

    cap_root = os.path.join(bench_dir, CAMBENCH_CAP_SUBTREE)
    if os.path.isdir(cap_root):
        idx, unknown = cambench_cap_meta(cap_root)
        if not idx:
            fails.append('CamBench_Cap 目录在，却一条元数据都没抽到')
        for f, why in unknown:
            fails.append('CamBench_Cap %s: %s' % (f, why))
        # 硬编码断言：这五条是**从数据里核出来的**，不是从本文件的逻辑推的
        expect = {
            'brokencrypto/BrokenCrypto1.java': 'DES',
            'brokencrypto/BrokenCrypto2.java': 'BLOWFISH',
            'brokencrypto/BrokenCrypto3.java': 'RC2',
            'brokencrypto/BrokenCrypto4.java': 'RC4',
            'brokencrypto/BrokenCrypto5.java': 'RC5',
            'brokenhash/BrokenHash1.java': 'MD5',
            'smallkeysize/SmallKeySize1.java': 'RSA',
        }
        for rel, alg in sorted(expect.items()):
            got = idx.get(rel, {}).get('algorithms')
            if got != (alg,):
                fails.append('CamBench_Cap %s 期望 %s，实抽到 %r'
                             % (rel, alg, got))
        notes.append('CamBench_Cap 抽到 %d 个用例（含负样本）' % len(idx))
        nline = sum(1 for r in idx.values() if r['line'])
        notes.append('CamBench_Cap 有行号的用例 %d 个' % nline)

    xlsx = os.path.join(bench_dir, CRYPTOAPI_BENCH,
                        'CryptoAPI-Bench_details.xlsx')
    cb_root = os.path.join(bench_dir, CRYPTOAPI_BENCH)
    if os.path.isfile(xlsx):
        idx, unknown = cryptoapi_bench_meta(cb_root, xlsx)
        if not idx:
            fails.append('CryptoAPI-Bench xlsx 在，却一条元数据都没抽到')
        # 未收录的 `Type of Vulnerability` 只有那几种已知的重复行，
        # 去重后应该很少；多了说明翻译表需要补。
        uniq = sorted({why.split(': ')[-1] for _, why in unknown
                       if '未收录' in why})
        if uniq:
            fails.append('CryptoAPI-Bench 有未收录的 Type of Vulnerability: %s'
                         % '、'.join(uniq))
        got = idx.get('src/main/java/org/cryptoapi/bench/brokencrypto/'
                      'BrokenCryptoABICase12.java', {}).get('algorithms')
        if got != ('BLOWFISH',):
            fails.append('CryptoAPI-Bench BrokenCryptoABICase12 期望 BLOWFISH，'
                         '实抽到 %r' % (got,))
        notes.append('CryptoAPI-Bench 抽到 %d 个用例' % len(idx))

    if fails:
        print('[FAIL] meta.py 自检未通过:')
        for f in fails:
            print('  - ' + f)
        return False

    if not notes:
        print('[SKIP] meta.py 自检**未执行** —— %s 不存在，没有任何数据被检查。'
              % bench_dir)
        print('       （这不是通过。要跑：把 benchmark 下到该目录，或设 '
              'BENCH_DIR 环境变量。）')
        return True

    print('[PASS] meta.py 自检通过')
    for n in notes:
        print('       · ' + n)
    return True


if __name__ == '__main__':
    import sys
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except (AttributeError, OSError):
        pass
    root = os.environ.get('BENCH_DIR') or default_bench_dir()
    print('benchmark 元数据目录: %s' % root)
    sys.exit(0 if _selftest(root) else 1)
