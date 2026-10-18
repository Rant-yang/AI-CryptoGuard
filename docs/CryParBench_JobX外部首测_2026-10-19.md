# CryParBench / JobX 外部首次诊断（2026-10-19）

## 预冻结对象与口径

这是一个**独立于现有开发语料的专项诊断**，不是全系统 Precision/Recall。外部标签来自 [CryParBench 所在的 MUBench fork](https://github.com/akwick/MUBench) 的 `JCA-Param-All` 分组，元数据提交为 `162a89374d4a1e7ee31790ffde361f71a94c8c66`。该分组当前列出 199 条正标注、涉及 42 个项目；另一可运行分组列出 162 条。它没有穷尽标注每个项目中所有安全与不安全调用，不能仅凭这个分组计算完整 Precision。

扫描前固定选择了该分组中单项目标注最多的 [JobX](https://github.com/jobxhub/JobX)，项目提交 `414503ffa4938e09ece04d4b6cbf85a5fe19ad67`。仅取 `jobx-common/src/main/java/` 下元数据指向的三个源码文件；三份文件的 SHA-256 分别为：

| 文件 | SHA-256 |
|---|---|
| `com/jobxhub/common/util/RSAUtils.java` | `7fd5c152ead9c99366fd2bf1cacf1e7f62c6e5fee31e7fd9a3353bb4b923a340` |
| `com/jobxhub/common/util/DigestUtils.java` | `78415298f7a2626efc387cbc329361af7330ab330f52788f4d7bc05ccb46a1c6` |
| `com/jobxhub/common/io/Bytes.java` | `a459b347a2f1833f3c3e761078fae1cde0426e4a0833a94c8616d1e2d78107bc` |

在首次扫描前另存预登记，固定了全部 14 条正标签、被测代码 `1d116734ac804d8e634e1c065d2c6acd6850f22c`、fast 模式及匹配标准：只有证据定位**同一 API 调用点或其真实参数**且问题成因相同才算命中；同文件扫到另一处算法不算。预登记、外部源码和原始扫描产物保留在仓库外，不随提交包分发。

## 首测结果（无 AI、未调参）

统一入口正常完成快速扫描与本地量子评估，输出 6 条 Finding；本表只对照 CryParBench 的 14 条**已知正标签**，不把另外 4 条 Finding 未经审阅就称作误报。

| 外部标注调用点 | 首测覆盖 | 判定依据 |
|---|---|---|
| `Bytes.java:877`，MD5 摘要 | 是 | MD5 Finding 的两份 pattern 证据均指向 877 行 |
| `DigestUtils.java:147`，SHA-1 摘要 | 是 | SHA-1 Finding 的 evidence.lines 包含 147 行 |
| `RSAUtils.java:117,139`，`Signature.getInstance(SIGNATURE_ALGORITHM)` | 否（2） | 扫到文件中的 RSA 名称，但证据不在签名 API 的两处调用点，不能据此声称发现了 `MD5withRSA` 参数误用 |
| `DigestUtils.java:401,461`，`Cipher.getInstance(DES)` | 否（2） | 扫到文件中的 DES 常量，但没有定位这两处使用该常量的 Cipher 调用点 |
| `DigestUtils.java:481,513`，`Cipher.getInstance("AES")` | 否（2） | 未单独报告模式/填充未显式指定；不得把裸 `AES` 自动写成确定的 ECB |
| `DigestUtils.java:404,464,480,482,512,514`，密钥构造或使用条件 | 否（6） | 快速模式缺少能证明这些参数来源/安全性的对应调用点证据 |

**已知正标签覆盖 2/14（14.3%）**。这是 JobX 三个文件的**fast 模式专项**，不能与开发集 `(文件, 算法, 用途)` 指标相加；也不能推出 CrySentry 深度模式的效果，因为本次没有编译该历史项目或运行深扫。14 条标签中有同一文件多处不同调用点，若改按文件/算法计数，分母与问题都变了，不能在看到结果后改口径。

## 产品含义与下一步验证

这次首测揭示的主要缺口是 Java 参数传播/默认配置，而不是“算法名字没收进规则库”。[Java 17 `Cipher` 官方文档](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/Cipher.html)指出：只传算法名时模式与填充依赖提供者默认值，建议显式指定完整变换串；因此若增加规则，应另报**配置待复核**，同时在未指定具体提供者时避免断言“必然 ECB”。对签名算法常量和密钥来源，需要调用点与传播证据，不能把同文件命中当作已解释用途。

在提交期限内不因这 14 条结果直接扩大模糊匹配词表。若后续加入上述检测，应先冻结带负例的独立样本，验证误报；JobX 原 14 条只能作为**看过错例后的同集回归**。设计报告继续如实使用已测开发集和现有独立专项的各自口径，不称“全系统独立 P/R 达标”。
