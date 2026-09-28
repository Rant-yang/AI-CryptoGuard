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

## 转换时的坑（实测踩过）

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
├── scan.py            主入口（待写）
└── adapters/          每个工具一个转换器
    ├── cbom_scan.py
    └── cryptoscan.py
```
