# benchmark/ —— 用公开 benchmark 代替人工标注

> **一句话：没有标签就没有准确率，没有准确率就没有「有效性」的证明。**

---

## 2026-10-04：前提变了

这份文档原来写着「**当前标注样本数：0**」「这是纯人力活，没有技术捷径」。
**那个判断是错的** —— 已经有现成的、人工标注好的公开 benchmark，
我们不需要自己标 120 条。

现在有 **1411 条标签**，覆盖 4 个公开 benchmark、5 种语言：

| benchmark | 语言 | 标签数 | 正 / 负 | 标签形式 | 泄漏风险 |
|---|---|---|---|---|---|
| **CryptoAPI-Bench** | Java | 203 | 180 / 23 | 目录名即类别 | 🔴 严重 |
| **CamBench_Cap** | Java | 25 | 16 / 9 | 目录名 + `Corrected*` | 🔴 严重 |
| **CamBench_Real** | Java | 34 | 0 / **34** | yaml（**带行号**） | 🟢 无 |
| **LLM-CMT** | C/C++/Go/Java/**Python** | 1149 | 973 / 176 | `labels.csv` 自由文本 | 🟡 轻微 |

**Python 靠 LLM-CMT 补上了**（245 条）。PyCryptoBench 的 GitHub 仓库是空的
（`size: 0`，只有一个 README），暂时拿不到。

数据放在**仓库外** `../_benchmarks/`（源码树 89MB，绝不入库）。

---

## 三件必须先懂的事

### 1. 匿名化不是可选项 —— 不做的话指标是假的

这些 benchmark 的命名**直接就是答案**：

```
src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java
                  ^^^^^^^^^^^ 包名=类别      ^^^^^^^^^^^^^^^^^^^ 类名=类别

Dsub/crawl/nomisuses/                            ← 这个目录名意思是「干净样本」
CamBench_Cap/basic/ecbmode/CorrectedEcbMode.java ← Corrected = 正确写法
```

而我们的 `ai/redact.py` 保留 `basename(path)` —— **那是生产环境的正确行为**
（用户要知道是哪个文件）。但跑 benchmark 时，文件名会把答案直接递进提示词，
大模型照着念就能「检测」出来。

**这是两套模式，不是改产品：**

| | 文件名 | 用途 |
|---|---|---|
| 生产管线 | **保留** | 用户需要知道是哪个文件 |
| benchmark | **匿名化** | 不然失去意义 |

`anonymize.py` 改三个地方，缺一不可：文件名、目录名、**文件内容**
（`public class BrokenCryptoABICase1` 和 `package ...brokencrypto;` 都在源码里）。
字符串字面量**不动** —— `"AES/CBC/PKCS5Padding"` 是扫描证据本身。

### 2. 大半类别根本不该比 —— 范围必须先写下来

这些 benchmark 是「**加密 API 误用检测器**」的基准：它们标注的是
「你把参数写错了」（静态 IV、可预测种子、没关流）。而本项目是
「**PQC 迁移**」工具：我们回答「你的算法撑不过量子计算机」。

**两个不同的轴。** CryptoAPI-Bench 的 18 个类别里只有 6 个落在我们的轴上：

| 落在轴上 | 范围外 |
|---|---|
| `brokencrypto` `brokenhash` `brokenmac` | `staticinitializationvector` `staticsalts` |
| `insecureasymmetriccrypto` `ecbcrypto` | `predictableseeds` `credentialinstring` |
| `pbeiteration`（部分） | `dummycertvalidation` `http` … 共 12 类 |

范围外的类别**不进 Recall 分母**，也不进入同一任务的 Precision 分母；
负样本上的检出仍然计为 FP。排除数量必须由 `eval.py` 如实打印。
把范围藏起来只报好看的数字，就是造假。

裁定表在 `scope.py`。**未裁定的类别会直接抛错** ——
不允许「不认识的类别 = 范围外」这种静默降级，那正是会让分母悄悄失真的路。

### 3. 计数单位 = (文件, 算法, 用途)

三家工具对「这算一条还是三条」的答案都不一样：

| 工具 | 原始结果 | 去重后 | 按什么去重 |
|---|---|---|---|
| cbom-scan | 171 处命中 | **14** | 按「算法」 |
| CryptoScan | 110 条 | **45** | 按「文件+算法」 |
| CrySentry | 8 条 | **3** | 按「类+敏感 API」 |

**分母不一致，算出来的数字就是假的。** 统一口径：**一条 = 一个 (文件, 算法, 用途) 组合**
（见 `core/schema/README.md`）。标签按同一口径。

> 上游会给**合并名**（`DES / 3DES`），评测时会拆开，命中任一即算匹配 ——
> 不拆的话「报了 DES 也报了 3DES」会被判成没报 DES。

---

## 目录

```
benchmark/
├── README.md      本文件
├── scope.py       类别 → 我方轴 的裁定表（范围内 / 部分 / 范围外）
├── anonymize.py   跑分前匿名化（文件名 + 目录名 + 源码内容）
├── adapters.py    各家标签 → 统一格式
├── eval.py        算 P / R / F1
└── labels/        生成的标签（**gitignored**，靠 adapters 重新生成）
```

## 怎么跑

```bash
# 1. 下载 benchmark 到仓库外（见 setup/ 里的说明）
#    预期位置：../_benchmarks/{CryptoAPI-Bench,CamBench,LLM-CMT}

# 2. 匿名化 + 生成标签
python -m benchmark.adapters

# 3. 扫描匿名树
python scanner/scan.py ../_benchmarks/_anon/cryptoapi-bench \
    --tools-dir <工具目录> -o out/bench/cryptoapi-bench.json

# 4. 评测
python benchmark/eval.py out/bench/cryptoapi-bench.json --scanned cryptoapi-bench
python benchmark/eval.py out/bench/cryptoapi-bench.json --scanned cryptoapi-bench -v
python benchmark/eval.py --selftest
```

自检：

```bash
python benchmark/scope.py          # 裁定表自检（交叉核对规则库）
python benchmark/scope.py --gaps   # 规则库覆盖缺口清单
python benchmark/anonymize.py      # 匿名化自检（泄漏清零 + 字面量未动）
```

---

## 首轮实测（2026-10-04）

CryptoAPI-Bench，匿名树，cbom-scan + cryptoscan 双工具：

```
检出 92 条 · 多源交叉 28 条 · 上游风险判定被规则库纠正 46 条
Precision 35.9%   Recall 36.3%   F1 36.1%
TP=33  FP=59  FN=58
```

**这个数字低于方案目标（R≥90% / P≥85%），而且不是调参能解决的。**
原因已经查清：

- **漏掉的 47 条里，27 条算法名是经变量传入的** ——
  `Cipher.getInstance(String.valueOf(crypto))`，真正的算法名在**另一个文件**里。
  正则扫描器**在结构上就看不见**。
- 这与文献一致：专用研究工具 Cryptolation 在同类 benchmark 上也只有
  **47.4% Recall / 64.33% F1**。

**所以这个数字不是羞耻，是论据** —— 它正是「为什么需要多源融合 + 数据流分析 + 大模型」
的实证。单靠正则工具，天花板就在这里。

> ⚠️ 汇报时**务必带上口径**：分母只含范围内的正样本，
> 范围外 89 条未计入。只报一个 `36.3%` 而不说口径，比不报还糟。

---

## 规则库覆盖缺口（9 条，待补）

从 LLM-CMT 的**真实代码**里发现的 —— 这些已淘汰算法出现了，我们却答不出来：

```
BLOWFISH  CAST  IDEA  MD2  MD4  NULLCIPHER  RC5  TEA  XTEA
```

补起来便宜（`core/rules/pqc_routing.py` 的 `_BY_ALGORITHM` 加几行），
但必须先知道有这回事。`python benchmark/scope.py --gaps` 随时可查。

---

## 已知限制

- **范围内**的正样本只有 533 条
  （cryptoapi-bench 91 + cambench-cap 14 + llmcmt 428）。
- **CamBench_Real 目前 34 条全是负样本**（`violation: false`），
  贡献不了 Recall，但是极好的误报测试集。它**不含源码**，
  要按 `github.json` 自己 clone 那 20 个 Java 项目。
- **CrySentry 用不了匿名树** —— 它走字节码要 `.jar`，
  而匿名化破坏了包结构。要跑字节码工具得另想办法。
- **LLM-CMT 的标签是自由文本**（138 种写法，还有拼错的 `RC4 uesd`），
  只能子串匹配，取最长命中。
- **`scanner/scan.py --tools-dir` 传相对路径会拼错**（实测变成 `_smoke\_smoke`）
  —— 传绝对路径。
