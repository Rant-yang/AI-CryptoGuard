"""把各家 benchmark 的标签，转成我们的统一格式。

**统一格式**（与 `benchmark/README.md` 声明的口径一致）：

    file      匿名化后的相对路径 —— 必须与 scanner 产出的 `finding.file` 对得上
    line      行号；拿不到就是 None（不是所有 benchmark 都标到行）
    algorithm / usage / risk   我方三轴；范围外的类别为 None
    verdict   in / partial / out
    expect_misuse   True=正样本（期望报出）, False=负样本（期望不报）

**为什么要 expect_misuse**：只知道「哪些是漏洞」算不出 Precision，
还得知道「哪些是干净代码」。CryptoAPI-Bench 的 `*Corrected*`、
CamBench_Cap 的 `Corrected*`、LLM-CMT 的 `If_CAM=0`，都是现成的负样本。

**所有标签都走 `scope.verdict_for()`**，未裁定的类别会直接抛错 ——
不允许「不认识的类别 = 范围外」这种静默降级。
"""

import csv
import json
import os

from . import scope

#: 文件名里出现这些词 = 该文件是「正确写法」的负样本
NEGATIVE_MARKERS = ('corrected', 'correct', 'safe', 'secure')


def _norm_rel(p):
    """统一成 `/` 分隔的相对路径。Windows 上 bench 的标签写的是反斜杠。"""
    return p.replace('\\', '/').lstrip('./')


def _is_negative(stem):
    low = stem.lower()
    return any(m in low for m in NEGATIVE_MARKERS)


class Record(dict):
    """一条统一标签。dict 是为了直接 json.dump。"""


def _rec(bench, anon_rel, orig_rel, category, line=None, **extra):
    v = scope.verdict_for(bench, category)
    r = Record(
        benchmark=bench,
        file=_norm_rel(anon_rel),
        orig_file=_norm_rel(orig_rel),
        line=line,
        category=category,
        verdict=v.verdict,
        algorithm=v.algorithms[0] if v.algorithms else None,
        algorithms=list(v.algorithms),
        usage=v.usage,
        risk=v.risk,
        why=v.why,
    )
    r.update(extra)
    return r


# ------------------------------------------------------------------ 工具

def _invert(amap):
    """anon 路径 -> 原路径。anon 路径是唯一键。"""
    return {v: k for k, v in amap.files.items()}


def _category_under(orig_rel, anchor):
    """取路径里 `anchor` 之后的那一段。CryptoAPI-Bench 是 `bench/`。"""
    parts = _norm_rel(orig_rel).split('/')
    for i, seg in enumerate(parts):
        if seg == anchor and i + 1 < len(parts):
            return parts[i + 1]
    return None


# ------------------------------------------------------------------ 各家适配器

def adapt_cryptoapi_bench(src_root, amap):
    """CryptoAPI-Bench：类别 = `src/main/java/org/cryptoapi/bench/<类别>/` 目录名。

    标签表 `CryptoAPI-Bench_details.xlsx` 是给人看的，机器读不了；
    但**目录名本身就是标签**，所以不解析 xlsx 也拿得到 ——
    代价是只能用「文件级」粒度，标不到具体行号。
    """
    inv = _invert(amap)
    out, unknown = [], []
    for anon_rel, orig_rel in sorted(inv.items()):
        if not orig_rel.endswith('.java'):
            continue
        cat = _category_under(orig_rel, 'bench')
        if cat is None:
            continue
        stem = os.path.splitext(os.path.basename(orig_rel))[0]
        try:
            out.append(_rec('cryptoapi-bench', anon_rel, orig_rel, cat,
                            expect_misuse=not _is_negative(stem)))
        except KeyError as e:
            unknown.append((orig_rel, str(e).split('\n')[0]))
    return out, unknown


def adapt_cambench_cap(src_root, amap):
    """CamBench_Cap：类别 = `<类别>/`，目录名即标签。

    子树已经收窄到 `CamBench_Cap/.../cap/basic`，所以路径**直接以类别开头**
    （`brokencrypto/BrokenCrypto1.java`），取第一段即可。

    ⚠️ 早先锚的是 `basic` 那一段。收窄子树之后那一段不在路径里了，
    于是 25 条标签全变成 0 条 —— 而且是**静默变 0**，不报错。
    这也是为什么 `build_all` 要把每家的条数打出来。
    """
    inv = _invert(amap)
    out, unknown = [], []
    for anon_rel, orig_rel in sorted(inv.items()):
        if not orig_rel.endswith('.java'):
            continue
        parts = _norm_rel(orig_rel).split('/')
        cat = parts[0] if len(parts) > 1 else None
        if cat is None:
            continue
        stem = os.path.splitext(os.path.basename(orig_rel))[0]
        try:
            out.append(_rec('cambench-cap', anon_rel, orig_rel, cat,
                            expect_misuse=not _is_negative(stem)))
        except KeyError as e:
            unknown.append((orig_rel, str(e).split('\n')[0]))
    return out, unknown


def adapt_cambench_real(src_root, amap):
    """CamBench_Real：`usages/<项目>/<n>.yaml`，**有精确到行的标注**，质量最高。

    ⚠️ 但这个仓库**不含源码** —— 只有 `github.json`（仓库元信息），
       要自己按 `github.json` 去 clone 那 20 个 Java 项目。
       所以适配器照常产出标签，但 `file` 指向的是**尚未下载**的路径。
    """
    import glob

    try:
        import yaml
    except ImportError:
        return [], [('cambench-real', '缺少 PyYAML，跳过（pip install pyyaml）')]

    out, unknown = [], []
    # src_root 已经指向 subtree（`CamBench/CamBench_Real`），别再拼一次
    pat = os.path.join(src_root, 'usages', '*', '*.yaml')
    for path in sorted(glob.glob(pat)):
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            try:
                doc = yaml.safe_load(f)
            except Exception as e:                       # noqa: BLE001
                unknown.append((path, 'yaml 解析失败: %s' % e))
                continue
        usage = (doc or {}).get('crypto-usage') or {}
        # 有的 yaml 把 FUM 写成带引号的 `"High-Level_Constraints"`，去掉引号
        fum = (usage.get('FUM') or '').strip().strip('"').strip("'")
        if not fum:
            unknown.append((path, '没有 FUM 字段'))
            continue
        loc = usage.get('location') or {}
        target = _norm_rel(loc.get('file') or '')
        try:
            line = int(loc.get('line') or 0) or None
        except (TypeError, ValueError):
            line = None
        project = os.path.basename(os.path.dirname(path))
        try:
            out.append(_rec('cambench-real', target, target, fum, line=line,
                            project=project,
                            expect_misuse=bool(usage.get('violation')),
                            api=doc.get('api')))
        except KeyError as e:
            unknown.append((path, str(e).split('\n')[0]))
    return out, unknown


def adapt_llmcmt(src_root, amap):
    """LLM-CMT：`Dsub/labels.csv`。

    格式：`path,source,language,If_CAM,labels`
      - `If_CAM` 0/1 —— 现成的正负样本划分
      - `labels` 分号分隔的自由文本，如 `sha1 used;md5 used`
        → 按关键词前缀匹配到 `scope.LLMCMT_LABEL_KEYWORDS`

    一条用例可能命中多个标签，全部产出（评测时按 `(file, algorithm)` 去重，
    与 README 里「一条 = (文件, 算法, 用途)」的口径一致）。
    """
    # labels.csv 给的是**相对仓库根**的原路径（`Dsub/crawl/...`），
    # 而 amap.files 的键是**相对 subtree 根**的（`crawl/...`）——
    # 因为匿名化只处理 `Dsub` 子树。所以下面按**后缀**匹配。
    # 注意方向：`amap.files` 本身就是「原 -> 匿名」，直接用它。
    # （早先这里用了 `_invert`，那是「匿名 -> 原」，方向反了，
    #   结果全部匹配不上 —— 750 条未裁定里绝大部分就是它。）
    by_orig = {_norm_rel(k).lower(): v for k, v in amap.files.items()}

    # src_root 已经指向 subtree（`LLM-CMT/Dsub`），别再拼一次 Dsub
    csv_path = os.path.join(src_root, 'labels.csv')
    if not os.path.exists(csv_path):
        return [], [('llmcmt', '找不到 %s' % csv_path)]

    out, unknown = [], []
    with open(csv_path, 'r', encoding='utf-8', errors='replace', newline='') as f:
        for row in csv.DictReader(f):
            raw_path = _norm_rel(row.get('path', ''))
            if not raw_path:
                continue
            # labels.csv 里的路径是相对仓库根的；匿名树是相对 benchmark 根的，
            # 所以按后缀匹配（唯一即可）。
            # 后缀匹配，方向是「标签路径 endswith 匿名树的相对路径」——
            # 因为标签写的是 `Dsub/crawl/...`，而树里的键是 `crawl/...`。
            cand = [a for o, a in by_orig.items()
                    if raw_path.lower().endswith(o) or o.endswith(raw_path.lower())]
            if len(cand) != 1:
                unknown.append((raw_path, '匿名树里匹配到 %d 个（应为 1）' % len(cand)))
                continue
            anon_rel = cand[0]
            expect = row.get('If_CAM', '').strip() == '1'
            labels = [s.strip() for s in (row.get('labels') or '').split(';') if s.strip()]
            if not labels:
                # 干净样本：没有标签可对轴，但它是有效的负样本
                out.append(Record(
                    benchmark='llmcmt', file=_norm_rel(anon_rel),
                    orig_file=raw_path, line=None, category='(clean)',
                    verdict=scope.OUT, algorithm=None, algorithms=[],
                    usage=None, risk=None,
                    why='If_CAM=0：benchmark 标注为「无密码 API 误用」。'
                        '用作负样本测误报，不参与 Recall 分母。',
                    expect_misuse=expect,
                    raw_labels=[]))
                continue
            for lab in labels:
                cat = _match_llmcmt_label(lab)
                if cat is None:
                    unknown.append((raw_path, '标签 %r 不在裁定表里' % lab))
                    continue
                out.append(_rec('llmcmt', anon_rel, raw_path, cat,
                                expect_misuse=expect, raw_labels=labels))
    return out, unknown


def _match_llmcmt_label(label):
    """把自由文本标签匹配到 `scope.LLMCMT_LABEL_KEYWORDS` 的键。

    做**子串**匹配而不是相等 —— 标签写法不统一
    （`sha1 used` / `SHA-1 used` / `sha1`）。取最长命中，避免
    `des` 抢在 `3des` 前面匹配掉。
    """
    low = label.lower()
    hits = [k for k in scope.LLMCMT_LABEL_KEYWORDS if k in low]
    if not hits:
        return None
    return max(hits, key=len)


# ------------------------------------------------------------------ 入口

#: bench -> (仓库目录名, 适配函数, **有标签的子树**)
#:
#: 第三个元素很要紧。**必须只扫有标签的那部分。**
#: 实测踩过：CamBench 的 clone 里除了 `CamBench_Cap`（25 条标签）
#: 还有 20 个项目的 `gh_data`、logo、幻灯片 —— 全扫进去的话
#: 检出 1231 条对 25 个标签，Precision 会被稀释成接近 0，
#: 而这个数字**毫无意义**：那些文件本来就没有标签，不是我们报错了。
#:
#: 空串 = 整个仓库都有标签。
ADAPTERS = {
    'cryptoapi-bench': ('CryptoAPI-Bench', adapt_cryptoapi_bench, ''),
    # 只到 `basic/` 这一层：CamBench_Cap 共 623 个 java，其中 598 个在
    # contextsensitivity / flowsensitivity / mixedsensitivities 等目录下，
    # 那是它的**分析能力测试套件**，不在我们的标签范围。
    # `basic/` 正好 25 个 java = 25 条标签。
    'cambench-cap': ('CamBench', adapt_cambench_cap,
                     'CamBench_Cap/src/main/java/org/cambench/cap/basic'),
    'cambench-real': ('CamBench', adapt_cambench_real, 'CamBench_Real'),
    'llmcmt': ('LLM-CMT', adapt_llmcmt, 'Dsub'),
}


def build_all(bench_dir, out_dir):
    """对每个已下载的 benchmark 跑适配，产出 `labels/<name>.json`。

    Returns:
        (总记录数, 未裁定清单)
    """
    from .anonymize import anonymize_tree

    os.makedirs(out_dir, exist_ok=True)
    total, all_unknown = 0, []

    for bench, (clone_name, fn, subtree) in sorted(ADAPTERS.items()):
        src = os.path.join(bench_dir, clone_name)
        if not os.path.isdir(src):
            print('  [跳过] %-16s 未下载（%s）' % (bench, src))
            continue

        anon_root = os.path.join(bench_dir, '_anon', bench)
        amap = anonymize_tree(src, anon_root, bench,
                              map_path=os.path.join(bench_dir, '_anon',
                                                    '%s.map.json' % bench),
                              subtree=subtree)
        # 适配器看到的是 **subtree 根** 的相对路径（与匿名树一致）。
        # 所以把 src 也指向 subtree —— 两边路径才对得上。
        fn_src = os.path.join(src, subtree) if subtree else src
        recs, unknown = fn(fn_src, amap)

        out_path = os.path.join(out_dir, '%s.json' % bench)
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(recs, f, ensure_ascii=False, indent=2)

        pos = sum(1 for r in recs if r.get('expect_misuse'))
        neg = len(recs) - pos
        ins = sum(1 for r in recs if r['verdict'] == scope.IN)
        part = sum(1 for r in recs if r['verdict'] == scope.PART)
        outs = sum(1 for r in recs if r['verdict'] == scope.OUT)
        print('  %-16s %4d 条 (正 %d / 负 %d)  '
              '范围内 %d / 部分 %d / 范围外 %d'
              % (bench, len(recs), pos, neg, ins, part, outs))
        total += len(recs)
        all_unknown.extend((bench,) + u for u in unknown)

    return total, all_unknown


if __name__ == '__main__':
    import sys
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except (AttributeError, OSError):
        pass

    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    bench_dir = os.path.join(os.path.dirname(here), '_benchmarks')
    out_dir = os.path.join(here, 'benchmark', 'labels')

    print('适配 benchmark 标签  [%s]' % bench_dir)
    print('=' * 64)
    total, unknown = build_all(bench_dir, out_dir)
    print('-' * 64)
    print('共 %d 条 -> %s' % (total, out_dir))
    if unknown:
        print()
        print('[注意] %d 条未能裁定（**不静默丢弃**，逐条列出）:' % len(unknown))
        seen = set()
        for bench, item, reason in unknown:
            key = (bench, reason[:60])
            if key in seen:
                continue
            seen.add(key)
            print('  %-16s %-40s %s' % (bench, str(item)[:40], reason))
