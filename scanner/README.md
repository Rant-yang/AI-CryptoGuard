# scanner/ —— 找问题

> **负责人：A**
> **一句话：输入一个项目文件夹，输出一份统一格式的问题清单。**

```
输入：D:\某个项目\                （一个文件夹）
  ↓
自动跑 cbom-scan + CryptoScan
  ↓
输出：findings.json               （合规于 core/schema/finding.v0.1.json）
```

---

## 第一版要做什么（3~4 天）

**就一件事**：写一个程序，给一个文件夹路径，输出**通过 schema 校验**的 `findings.json`。

验收标准：

```bash
python scanner/scan.py D:\某个项目 -o out\findings.json
python core/schema/validate.py out\findings.json     # 必须退出码 0
```

两条命令都跑通，A 的任务就算完成。

**第一版不接 CrySentry。** 原因见下。

---

## 三个工具的实际情况（动手前必须知道）

| 工具 | 输入 | 能"输入路径就跑"吗 | 语言 |
|---|---|---|---|
| **cbom-scan** | 源码目录 | ✅ 能 | Go / Python / JS / Java |
| **CryptoScan** | 源码目录 | ✅ 能 | 算法正则是语言无关的 |
| **CrySentry** | **编译后的 jar** | ❌ **不能** | 只有 Java |

### 为什么 CrySentry 不进第一版

它要 **JDK 17 + 目标项目先编译成功 + 一个 options.yml 配置**。
对一个 Maven/Gradle 项目，**构建失败就没结果** —— 这是流水线里很脆的一环。

所以它是**第二阶段的独立任务**，不是第一版的第三个平级模块。
先把 cbom-scan + CryptoScan 这条线跑通，再来啃它。

### 两个工具的定位

cbom-scan 和 CryptoScan **高度重叠**（都是源码级正则找算法名），不是"各管一块"。

**建议以 cbom-scan 为模式证据主源**，因为它：
- `risk` 分类**正确**（五档：shor/broken/grover/review/safe）
- 输出标准 **CycloneDX 1.6 CBOM**，可互操作
- 已经有 `occurrences[]` 数组结构，**接近我们的计数单位**

CryptoScan 补充它没有的：25 个 `type` 每个都带 `description/remediation/impact/effort/references`，
以及一个 `purpose` 字段（用途）。**这些元数据搬进 `core/rules/` 规则库。**

---

## 调用时的坑（实测踩过，第一个就会中）

### 0. 🔴 CryptoScan 只要有发现就返回 exit 1

实测（已验证）：

| 扫描对象 | 退出码 |
|---|---|
| 有密码发现的目录 | **1** |
| 有文件、但零密码发现 | 0 |
| 空目录 | 0 |

**它没设 `--fail-on` 也这样** —— 和 `--help` 里写的不一致。

所以**不能**这么写：

```python
result = subprocess.run([...])
if result.returncode != 0:
    raise RuntimeError("scan failed")     # ❌ 每次成功扫描都会被判成失败
```

**正确做法**：忽略退出码，改为检查**输出文件是否存在 + JSON 能否解析**。

```python
subprocess.run([...], check=False)        # 明确忽略退出码
data = json.load(open(out))               # 用这个判断成败
```

> cbom-scan 没有这个问题，**永远返回 0**。
> 两个工具行为不一致 —— 这正是需要 adapter 层的原因之一。

### 0b. `--output` 一加，屏幕就没输出了

CryptoScan 默认 `--format text`、输出到 stdout、**实时流式**打印每一条发现。
一旦加了 `--output`，内容全部进文件，**屏幕上静默** —— 这不是卡住了。

调试时想看得见，就不加 `--output`。

### 1. 路径必须转相对

CryptoScan 输出**绝对路径**。必须剥成项目内相对路径，否则：
- 信息泄露（暴露你的磁盘结构）
- 结果不可移植（换台机器就废了）

### 2. 严重程度有两套表示法

CryptoScan **同一份 JSON 里**：
- `findings[].severity` 是**整数** 0–4
- `summary.bySeverity` 的**键是字符串** `"CRITICAL"`

别混用。

### 3. 量子风险不要透传 CryptoScan

CryptoScan 把 MD5 / SHA-1 / DES / 3DES / RSA-1024 全标成 `VULNERABLE`。
**这些是被经典攻击攻破的，跟量子无关。** 直接透传会写出"MD5 受 Shor 算法威胁"这种错误结论。

按 `core/schema/README.md` 里的五档口径，**由规则库重新判定**。

### 4. 去重

按 `(file, algorithm_normalized, usage)` 合并，行号收进 `evidence[].lines`。
**别一条命中一条 finding** —— 那样 171 处会变成 171 条，指标就废了。

---

## 后续（第一版之后）

- **接 CrySentry**：单独排期，先解决"目标项目怎么编译"
- **Python AST 检测**：现有工具对 Python 只有一条 import 正则，**完全不理解 Python 的 crypto API 语义**。
  用 Python 自带的 `ast` 模块写轻量局部数据流，**能追踪"这个密钥从哪来"就够**。
  ⚠️ 不要试图"照着 CrySentry 重写一个 Python 版" —— 它背后是一整套研究级程序分析引擎，
  不是可以照抄的扫描逻辑。
- **凭据检测**：方案要求 ≥8 类凭据缺陷，现有工具覆盖不到一半（CryptoScan 只有 9 条正则：
  6 个 PEM 头 + 3 个变量名，**无熵检测**）。这块要自研。

---

## 目录约定

```
scanner/
├── README.md          本文件
├── scan.py            主入口（CLI：目标目录 -> findings.json）
├── selftest.py        自检（外部行为断言，退出码 0 = 通过；合并前跑）
├── normalize.py       归一化与裁决表（算法别名 / usage / severity / risk，口径只改这一处）
├── merge.py           多源证据融合（分桶 + 行号吸收 + 字段合并裁决）
├── coverage.py        覆盖差异审计（一家报一家没报 -> 漏报复核线索）
├── cbom_report.py     融合版 CycloneDX 1.6 CBOM 渲染（--cbom）
└── adapters/          每个工具一个转换器（find_tool / run / to_groups 三同构接口）
    ├── cbom_scan.py
    └── cryptoscan.py
```

## 第一版实现说明（2026-09-30，A）

- 调用：`python scanner/scan.py <目标目录> -o out/findings.json`
  （工具默认在 `<仓库根>/tools/` 下找，可用 `--tools-dir` 或环境变量
  `ACG_TOOLS_DIR` 覆盖；`--tool` 可单选一个工具）
- 退出码：0 成功（含零发现；单工具失败降级运行时也返回 0，会打警告）、
  2 用法/环境错、3 所选工具全部失败
- 产物：`findings.json`（过 schema 校验的数组）+ 同名 `findings_raw/`
  （两个工具的原始 JSON 留档）+ `findings.meta.json`（工具耗时/原始计数/
  融合统计/覆盖差异摘要）+ `findings.coverage_diff.json`（覆盖差异明细）
  + `--cbom` 时另有 `findings.cbom.json`（融合版 CycloneDX 1.6，
  serialNumber 确定性可复现）。**所有产物文件名都跟随 `-o` 的输出名** ——
  同目录多次扫描不同目标不会互相覆盖
- 覆盖差异审计（coverage.py）：按**行级**对比两家原始命中（不受算法粒度影响，
  是漏报复核的主要线索）+ 算法级覆盖对比（受粒度干扰，仅参考）。
  crypto-samples 实测：双方同报 67 行、仅 cbom-scan 94 行、仅 CryptoScan 30 行
- **自检**：`python scanner/selftest.py`（约 60 条外部行为断言：归一化映射、
  融合规则、行号吸收、X25519 行级细分、CBOM 结构与确定性，退出码 0 = 通过）。
  建议合并前与 `core/schema/validate.py` 一起跑
- severity 裁决：**取最大只作用于上游给出的 severity**；`risk -> severity`
  兜底（表见 normalize.py）仅在没有上游 severity 的 cbom-only 条目使用，
  口径按 CryptoScan 实际打分校准（grover 类它打 info/low、broken/shor 类打
  high 居多），不会把上游按上下文的打分系统性抬高
- cbom-scan 把 `Ed25519 / X25519` 捆成一个 asset 且 prim=signature ——
  adapter 按 occurrence 的 match 命中词做**行级细分**（ed25519 行 -> signing、
  x25519 行 -> key_exchange），判不出的回落组级映射，不硬判
- 对 crypto-samples 实测：171 处命中 + 110 条 finding → 融合为 91 条
  （72 个 (file, 算法) 组，因 usage 不同拆分），双源证据 16 条，
  上游量子风险被我方裁决推翻 14 条（如 MD5 的「Shor 可破」错标）

### 已知局限（如实记录，不装没有）

1. **上游算法粒度不一致时无法合流多源证据**：cbom-scan 把椭圆曲线拆成
   `Ed25519 / X25519` 和 `ECDSA / EC`，CryptoScan 全归 `ECC`；cbom 的
   `NIST PQC` 大类对 CryptoScan 的 ML-KEM / ML-DSA 细分同理。
   别名表只收确定同义（`ECC ↔ ECDSA / EC`、DES 族），**刻意不做粒度
   强制对齐** —— 那是「聪明的错误」。
2. 行号吸收只做**精确行号匹配**（两个工具都是逐行扫描，行号对不上就是
   证据对不上，不做 ±1 模糊）。
3. cbom-scan 无 severity / confidence：severity 用
   `risk -> severity` 兜底映射（仅 cbom-only 条目使用；口径按 CryptoScan
   实际打分校准，但兜底分不出「真实调用」与「提及」，不越权打 critical），
   confidence 无来源时不填（不猜）。
4. `usage` 透传上游（CryptoScan purpose 优先，其次 cbom prim），
   确定性矛盾（如 RSA/hashing、MD5/encryption 这类实测上游误判）打
   `needs-usage-review` 标记，**复核与纠正归 ai/ 模块**。
5. CryptoScan 的 `algorithm` 为空的 finding（TLS Configuration /
   Hardcoded Key Size / PQC Library Import）不再拿 `type` 当算法名
   （2026-10-08 任务 2 修正，见下方第二版改动）——分组键用 `TYPE:` 前缀，
   输出的 algorithm/algorithm_normalized 如实留空并打 `no-algorithm` 标记，
   不进 CBOM。这类线索保留给 C 的凭据检测用。
6. `raw` 里不保留 CryptoScan 的 `sourceContext`（每条 7 行源码上下文，
   180KB 输出的大头，调试走 `<输出名>_raw/` 留档）与 description / remediation
   等 type 级元数据（按定位搬进 `core/rules/`，不在 110 条里重复 110 份）。
7. **`RISK_BY_TYPE` 只覆盖 zh_map 初版的 25 个 type；CryptoScan 实际 type
   值域 78 种**（冒烟真实仓库实测）。未覆盖的（证书运维类、凭据暴露类、
   Blowfish/RC4、SHA-3 等 53 种）risk 落 `review`（不猜）。
   实测值域统计与分档建议见 `out/type_coverage_for_core_rules.json`
   （线下传给 C，定稿归 core/rules，scanner 随后切换引用）。

### 依赖

- Python 3.8+（标准库即可运行 scan.py 本体）
- 工具本体按 `setup/README.md` 装到 `tools/`（不入库）
- `core/schema/validate.py` 校验需要 `pip install jsonschema`

## 第二版改动（2026-10-09，A）

对应 `docs/任务清单_2026-10-08.md` 任务 1/2，外加一个实测定量后新增的
本地字面量源（超出任务清单分工，待与 C 对齐后定稿）。

### 任务 1：合并名拆词（normalize.split_combined_algorithm）

- cbom-scan 的合并名 asset（`Legacy cipher (Blowfish/CAST5/IDEA/SEED)`、
  `SSH (RSA/ECDSA/Ed25519)`）拆成独立算法各成一组，与 schema 计数单位对齐。
- 拆词规则保守：**带括号且括号内按 `/` 拆出的每段无空格**才拆；
  `AES/GCM/NoPadding`（参数写法）、`PKCS#8 private key (alg unspecified)`
  （说明文字）、`SHA-384/512 (SHA-2)`（家族名单段）都不拆。
- 拆开后每个候选**只继承 `match` 点名自己的命中**（match 归一后与候选
  归一相等）；match 对不上任何候选或缺 match 时保守归给全部候选。
  实测定量：只用 Blowfish 的文件若让 4 个候选继承全部命中，每文件
  1 条误报变 3 条（FP +13、TP 不动）——match 归属修复后消失。

### 任务 2：type 不许当算法

- CryptoScan 无 `algorithm` 的 finding 分组键用 `TYPE:` + 归一化 type
  （不撞算法桶、不被前缀规则误判、同文件不同 type 不撞 finding_id），
  输出 algorithm/algorithm_normalized 如实留空 + `no-algorithm` 标签，
  不进 CBOM。「没有算法」不许伪装成一个算法名。

### 新增：本地字面量源（adapters/local_literal.py）

- 动机（cryptoapi-bench 203 文件实测定量）：43 条范围内漏报里 24 条，
  算法名以字符串字面量写在同一文件、只是经变量间接传入调用点
  （`DEFAULT_CRYPTO = "IDEA"` -> `Cipher.getInstance(String.valueOf(c))`），
  或 cbom-scan/cryptoscan 算法表压根没有 RC2/IDEA/MD2/MD4。
- 双条件判定：同文件存在 JCE 汇点调用 + 词表内算法名字符串字面量
  （转换串只取首段）。词表 = 已淘汰经典算法（DES 族/Legacy cipher 族/
  RC 族/TEA 族/MD2/MD4/MD5/SHA1，风险统一 broken），**扩表归 C**。
- usage 一律 unknown；与外部工具同 (file, alg) 重叠时让位（merge 侧
  剔除）——只补盲区。只扫 .java（三个 benchmark 语料都是 Java）。
- **schema 对接点（待 C）**：`core/schema/finding.v0.1.json` 的
  `evidence[].tool` 枚举需加 `'local-literal'` 一行。schema 自己的
  描述要求「自研模块也要如实填写，不要伪装成第三方」——在 C 加枚举前，
  `validate.py` 会对本源产出的条目报红，这是预期行为，不是数据错误。

### cryptoapi-bench 实测数字（2026-10-09，匿名树，双工具 + 本地源）

| 版本 | P | R | TP | FP | FN | F1 |
|---|---|---|---|---|---|---|
| 第二版前（59705da） | 46.7% | 50.0% | 43 | 49 | 43 | 48.3% |
| 任务 1+2 完成 | 51.2% | 50.0% | 43 | 41 | 43 | 50.6% |
| + 本地字面量源 | **58.2%** | **74.4%** | 64 | 46 | 22 | **65.3%** |

- 验收命令：合并名残留 0、拿 type 当算法的残留 0；selftest 103 项全过；
  逐字节复现一致；除上述 schema 枚举待加外全部合规。
- 剩余 22 条 FN 的构成：算法名以方法参数传入（文件里没有字面量）、
  PBE 低迭代次数类（算法名从未出现）、ECB 模式类 —— 均为正则层结构性
  天花板，正是 ai/ 模块（LLM 复核）的存在理由。
- 本地源新增的 4 条负样本误报：查证过那 4 个 corrected 文件里确实存在
  `Cipher.getInstance("RC2")` 这类字面量调用（try/fallback 写法），
  报出的是真实模式命中，与 benchmark 的负样本口径分歧如实记录。
