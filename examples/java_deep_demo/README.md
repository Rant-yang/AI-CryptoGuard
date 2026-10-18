# Java 深度证据公开样例

`Demo.java` 是本项目原创的**故意不安全**样例：固定种子的 `Random` 生成密钥，
密钥送入 `SecretKeySpec`；同一方法还使用 AES/ECB。它没有真实密钥或凭据。

先用 JDK 17 编译到仓库外（Windows cmd 示例，按本机路径替换 JDK/CrySentry）：

```cmd
cd /d D:\code_competition\AI-CryptoGuard
mkdir D:\code_competition\_demo_java
"D:\code_competition\_smoke\jdk17\jdk-17.0.20.1+1\bin\javac.exe" -g -d D:\code_competition\_demo_java examples\java_deep_demo\Demo.java
"D:\code_competition\_smoke\jdk17\jdk-17.0.20.1+1\bin\jar.exe" --create --file D:\code_competition\_demo_java\demo.jar -C D:\code_competition\_demo_java .
python core\pipeline.py examples\java_deep_demo --mode deep-java --tools-dir D:\code_competition\_smoke --java-artifact D:\code_competition\_demo_java\demo.jar --crysentry-home D:\code_competition\_smoke\CrySentry --crysentry-java "D:\code_competition\_smoke\jdk17\jdk-17.0.20.1+1\bin\java.exe" -o D:\code_competition\_demo_java\report
```

查看 `report\task.json` 的 `deep_java` 阶段和 `report\findings_assessed.json`。
本样例实测 CrySentry 会给出密钥来源第 9 行、`SecretKeySpec` 构造点第 10 行。
两点都可定位且符合已核对的 `Random.nextBytes → SecretKeySpec` 规则时，适配器
生成独立的 `JAVA-WEAK-PRNG-KEY` 配置 Finding，附一条 `taint` 证据；不会把它
误并入 AES/ECB Finding。该证据仅有首尾位置，**没有完整传播路径**，状态始终
是 `partial`。未能定位来源行或不符合规则的线索仍在 `task.json` 的
`unresolved_deep_evidence`，不会冒充确定结论。将样例改为 `SecureRandom` 后的
真实深度分析没有产生这条弱随机密钥 Finding。这是功能样例，不是 P/R 提升证明。

Windows 上 CrySentry 仓库和这个编译/报告目录可以位于不同盘符；runner 从隔离
任务目录启动 Tai-e，跨盘依赖 classpath 临时复制到任务目录，避免其相对路径
序列化失败。第三方工具与编译产物不入库。
