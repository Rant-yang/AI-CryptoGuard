# setup/ —— 三个工具怎么装

> 🔴 **工具本体不入库。** 这个目录只放"怎么下载"和"踩过的坑"。
> CrySentry 解包后 **444MB**，塞进仓库就废了，而且历史里删不掉。

---

## 三个工具的实际情况

| 工具 | 需要什么环境 | 装起来难吗 | 许可证 |
|---|---|---|---|
| **CryptoScan** | 无（预编译 exe） | ⭐ 直接用 | Apache-2.0 |
| **cbom-scan** | Node | ⭐ 零依赖 | 见仓库 |
| **CrySentry** | **JDK 17** + Gradle | ⭐⭐⭐ 坑多 | **LGPL-3.0** |

**第一版只需要前两个。** CrySentry 是独立的第二阶段任务。

---

## 1. CryptoScan

预编译的二进制，**不需要装 Go**。

**默认就是 text 格式、实时流式打印到屏幕**（每个发现一条，会有几千行）：

```cmd
cryptoscan.exe scan <源码目录>
```

**要 JSON 才加 `--format json --output`** —— 注意是 `--output`，**不是 `-o`**：

```cmd
cryptoscan.exe scan <源码目录> --format json --output out.json
```

> ⚠️ 加了 `--output` 之后**屏幕上什么都不显示是正常的**，内容全进文件了。

其他格式：`text`（默认）/ `json` / `csv` / `sarif` / `cbom`

### 🔴 退出码陷阱：只要有发现就返回 1

| 扫描对象 | 退出码 |
|---|---|
| 有密码发现的目录 | **1** |
| 有文件、但零密码发现 | 0 |
| 空目录 | 0 |

**没设 `--fail-on` 也这样。** 脚本里**不要**用退出码判断成败 ——
改用"输出文件是否存在 + JSON 能否解析"。详见 `scanner/README.md`。

---

## 2. cbom-scan

零依赖，只要 Node。

```cmd
node cbom.js <源码目录>              :: 人读的报告
node cbom.js <源码目录> --json       :: 机器可读 JSON
node cbom.js <源码目录> --cbom out.json   :: CycloneDX 1.6 CBOM
node verify.js                       :: 自测（54 项）
```

**装完先跑 `node verify.js`**，看到 54 项全过就说明环境没问题。

实测：扫 `crypto-samples` 得到 **171 处命中 → 14 个算法**，覆盖
`.go` / `.py` / `.js` / `.java` 四种语言。

---

## 3. CrySentry（坑最多，单独说）

### 它是什么

Tai-e 全程序指针分析框架 + 密码误用插件。**做的是 Java 字节码层的数据流分析**，
比前两个的正则匹配深得多 —— 能给出 source → sink 的污点证据链。

### 🔴 关键限制：它要的是**编译后的 jar**，不是源码

所以"输入一个项目路径就能跑"**做不到**。必须先让目标项目构建成功。
对 Maven / Gradle 项目，**构建失败就没结果** —— 这是流水线里很脆的一环。

### 环境要求

**必须 JDK 17。** 它的 `buildSrc` 里硬编码了 `JavaLanguageVersion.of(17)`，
而 Gradle 8.7 的 wrapper 在 JDK 25 下**根本起不来**。

```cmd
set "JAVA_HOME=D:\path\to\jdk-17"
set "PATH=%JAVA_HOME%\bin;%PATH%"
java -version          :: 必须先确认是 17.x
```

> 建议用便携版 JDK，**不要改系统 PATH/JAVA_HOME**，免得影响别的项目。

### 构建

```cmd
cd <CrySentry 目录>
gradlew.bat fatJar -I <本目录>\mirror.init.gradle
```

产物：`build\tai-e-all-0.5.1-SNAPSHOT.jar`

### 运行

```cmd
java -jar build\tai-e-all-0.5.1-SNAPSHOT.jar --options-file options.yml
```

结果默认落在 `crypto-output\<目标名>.json`。

---

## 🕳️ 国内网络下会踩的三个坑（都已解决）

### 坑 1：`docs` 子项目会让构建无限挂起

CrySentry 的 `settings.gradle.kts` 里 include 了一个 `docs` 子项目，
它的 `build.gradle.kts` 要从 **plugins.gradle.org** 解析 asciidoctor 插件 ——
**在国内网络下会无限挂起**，没有任何报错，就是卡住。

**解决**：注释掉 `settings.gradle.kts` 里的 `"docs"`。我们只需要 `fatJar`，
去掉这个子项目就够了。原始内容：

```kotlin
include(
    ":", // root project
    "docs",   // ← 注释掉这一行
)
```

### 坑 2：`repo1.maven.org` 卡死

Gradle 的 `mavenCentral()` 默认走 `repo1.maven.org`。实测**单个 jar 要 20 秒然后断流**；
而 `repo.maven.apache.org` 只要 3.7 秒。

**解决**：用阿里云镜像。已经写好 `mirror.init.gradle`（就在本目录），
用 `-I` 传进去，**不需要改仓库里的任何文件**：

```cmd
gradlew.bat fatJar -I "%CD%\mirror.init.gradle"
```

### 坑 3：cmd 不搜索当前目录

如果这台机器设了 `NoDefaultCurrentDirectoryInExePath`，
cmd **不会**在当前目录找可执行文件，裸写 `gradlew.bat` 会报"不是内部或外部命令"。

**解决**：写全路径。

```cmd
call "D:\full\path\to\gradlew.bat" fatJar -I "D:\full\path\to\mirror.init.gradle"
```

### ⚠️ 附加：`.bat` 必须纯 ASCII

cmd 按**系统代码页**（中文 Windows 是 GBK）解析批处理文件。
**UTF-8 的中文注释会破坏行结构**，脚本会报一堆莫名其妙的"不是内部或外部命令"。

**批处理里只写英文注释。** （`.py` 文件不受影响，可以写中文。）

---

## 验证清单

装完按这个顺序验一遍：

```cmd
:: 1. CryptoScan
cryptoscan.exe version

:: 2. cbom-scan
node cbom.js verify.js        :: 或 node verify.js，应看到 54 项通过

:: 3. CrySentry
java -version                 :: 必须是 17.x
call <全路径>\gradlew.bat fatJar -I <全路径>\mirror.init.gradle
```

三个都过了，再开始写代码。

---

## 目录

```
setup/
├── README.md              本文件
└── mirror.init.gradle     阿里云镜像 init script（CrySentry 构建用）
```
