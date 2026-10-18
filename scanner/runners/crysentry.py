"""CrySentry 进程调用器。

CrySentry/Tai-e 是 LGPL-3.0 第三方工具。本文件只生成隔离配置并调用用户
已经准备好的工具 jar；不会下载、构建或把工具本体复制进仓库。
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import time
import zipfile
from pathlib import Path
from pathlib import PurePosixPath


class CrySentryError(RuntimeError):
    """调用参数或工具环境不可用。"""


def _posix(path):
    return Path(path).resolve().as_posix()


def find_java(explicit=None):
    candidates = [explicit, os.environ.get("CRYSENTRY_JAVA")]
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidates.append(str(Path(java_home) / "bin" / "java.exe"))
    candidates.append(shutil.which("java"))
    for value in candidates:
        if value and Path(value).is_file():
            return str(Path(value).resolve())
    raise CrySentryError("找不到 Java。请用 --crysentry-java 指定 JDK 17 的 java.exe。")


def find_tool_jar(home, explicit=None):
    if explicit:
        jar = Path(explicit).resolve()
        if jar.is_file():
            return jar
        raise CrySentryError("CrySentry 工具 jar 不存在: %s" % jar)
    build = Path(home).resolve() / "build"
    jars = sorted(build.glob("tai-e-all-*.jar"))
    if len(jars) != 1:
        raise CrySentryError(
            "期望 %s 下恰好一个 tai-e-all-*.jar，实际 %d 个。先按 setup 文档构建一次。"
            % (build, len(jars)))
    return jars[0]


def java_major(java):
    proc = subprocess.run([java, "-version"], capture_output=True,
                          text=True, encoding="utf-8", errors="replace",
                          timeout=15, check=False)
    text = (proc.stderr or "") + "\n" + (proc.stdout or "")
    match = re.search(r'version\s+"(?:1\.)?(\d+)', text)
    return int(match.group(1)) if match else None


def stage_artifact(artifact, work):
    """Stage bytecode under CrySentry's recognized app-archive name.

    CrySentry Main.scanAppClassPath registers application classes as reachable
    roots only for archives named ``test.jar`` or ``original-classes.jar``.
    A normal project.jar otherwise exits successfully with zero reachable
    methods and an empty report. Never modify the user's original artifact.
    """
    source = Path(artifact).resolve()
    if not source.exists():
        raise CrySentryError("Java 编译产物不存在: %s" % source)
    staged = Path(work) / "test.jar"
    if source.is_file():
        if source.suffix.lower() != ".jar":
            raise CrySentryError("CrySentry 当前仅支持 jar 或 classes 目录: %s" % source)
        # CrySentry's own ZipUtils concatenates entry names to the extraction
        # directory without normalizing them. Refuse traversal before handing
        # any user-supplied archive to that third-party extractor.
        try:
            with zipfile.ZipFile(source) as archive:
                names = archive.namelist()
                for name in names:
                    normalized = name.replace("\\", "/")
                    parts = PurePosixPath(normalized).parts
                    if (not parts or normalized.startswith("/") or
                            ":" in parts[0] or ".." in parts):
                        raise CrySentryError("jar 含越界路径，已拒绝分析: %s" % name)
                if not any(name.endswith(".class") for name in names):
                    raise CrySentryError("jar 中没有 .class 文件: %s" % source)
        except zipfile.BadZipFile as exc:
            raise CrySentryError("Java jar 不是有效 ZIP: %s" % source) from exc
        if source != staged.resolve():
            shutil.copy2(source, staged)
    elif source.is_dir():
        classes = sorted(source.rglob("*.class"))
        if not classes:
            raise CrySentryError("classes 目录没有 .class 文件: %s" % source)
        with zipfile.ZipFile(staged, "w", compression=zipfile.ZIP_DEFLATED) as jar:
            for cls in classes:
                if cls.is_symlink():
                    continue
                jar.write(cls, cls.relative_to(source).as_posix())
    else:
        raise CrySentryError("Java 编译产物必须是 jar 或 classes 目录: %s" % source)
    return staged


def build_options(artifact, classpath, result_path, analysis_dir,
                  crypto_config, java_version=8):
    """生成 CrySentry options.yml；只写确定字段，不修改工具全局配置。"""
    cps = [Path(p).resolve() for p in (classpath or [])]
    app = Path(artifact).resolve()
    if not app.exists():
        raise CrySentryError("Java 编译产物不存在: %s" % app)
    missing = [str(p) for p in cps if not p.exists()]
    if missing:
        raise CrySentryError("classpath 项不存在: %s" % "; ".join(missing))
    cfg = Path(crypto_config).resolve()
    if not cfg.is_file():
        raise CrySentryError("CrySentry crypto-config.yml 不存在: %s" % cfg)

    def yaml_list(values, indent=2):
        if not values:
            return "[]"
        return "\n" + "\n".join(" " * indent + "- " + json.dumps(_posix(v))
                                  for v in values)

    pta = (
        "plugins:[pascal.taie.analysis.pta.plugin.cryptomisuse.reachableplugin.CryptoReachablePlugin];\n"
        "crypto-output:%s;\n"
        "crypto-config:%s;\n"
        "implicit-entries:false;\nonly-app:false;\nmerge-string-builders:true;\n"
        "cs:1-call;\nadvanced:hashmap;\npropagate-types:[reference,byte,char,int];"
        % (_posix(result_path), _posix(cfg)))
    pta_block = "\n".join("    " + line for line in pta.splitlines())
    return (
        "optionsFile: null\nprintHelp: false\n"
        "classPath: %s\nappClassPath: %s\n" %
        (yaml_list(cps), yaml_list([app])) +
        "mainClass: null\ninputClasses: []\njavaVersion: %d\n" % int(java_version) +
        "prependJVM: true\nallowPhantom: true\n"
        "worldBuilderClass: pascal.taie.frontend.newfrontend.AsmWorldBuilder\n"
        "outputDir: %s\n" % json.dumps(_posix(analysis_dir)) +
        "preBuildIR: false\nworldCacheMode: false\nscope: REACHABLE\n"
        "nativeModel: true\nplanFile: null\nanalyses:\n  pta: |\n%s\n" % pta_block +
        "onlyGenPlan: false\nkeepResult:\n  - $KEEP-ALL\n"
        "jreDir: null\nextractAllClasses: false\nnoAppendJava: false\n"
        "useNonParallelCWAlgorithm: false\nfrontendOptions: {}\n")


def run(artifact, output_dir, crysentry_home, classpath=None, java=None,
        tool_jar=None, timeout=900, memory_mb=4096, java_version=8):
    """运行一次深度分析，返回状态字典；超时/失败不会抛掉快速扫描结果。"""
    started = time.time()
    work = Path(output_dir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    result = work / "crysentry.json"
    options = work / "options.yml"
    analysis_dir = work / "taie-output"
    if analysis_dir.exists():
        shutil.rmtree(analysis_dir)
    for stale in (result, options):
        if stale.exists():
            stale.unlink()

    try:
        home = Path(crysentry_home).resolve()
        java_path = find_java(java)
        major = java_major(java_path)
        if major != 17:
            raise CrySentryError("CrySentry runner 要求 JDK 17，当前检测到: %s" % major)
        jar = find_tool_jar(home, tool_jar)
        config = home / "src" / "main" / "resources" / "crypto-config.yml"
        staged_artifact = stage_artifact(artifact, work)
        options.write_text(build_options(
            staged_artifact, classpath or [], result, analysis_dir, config, java_version),
            encoding="utf-8")
        cmd = [java_path, "-Xmx%dm" % int(memory_mb), "-jar", str(jar),
               "--options-file", str(options)]
        stdout_path = work / "stdout.log"
        stderr_path = work / "stderr.log"
        with stdout_path.open("w", encoding="utf-8") as stdout_log, \
                stderr_path.open("w", encoding="utf-8") as stderr_log:
            proc = subprocess.Popen(cmd, cwd=str(home), stdout=stdout_log,
                                    stderr=stderr_log, text=True,
                                    encoding="utf-8", errors="replace")
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                return {"status": "timeout", "reason": "CrySentry 超时（%s 秒）。" % timeout,
                        "seconds": round(time.time() - started, 3),
                        "tool_version": jar.name, "raw_output": None}
        if proc.returncode != 0:
            stderr = stderr_path.read_text(encoding="utf-8", errors="replace")
            stdout = stdout_path.read_text(encoding="utf-8", errors="replace")
            tail = (stderr or stdout or "")[-500:].replace("\n", " ")
            return {"status": "failed", "reason": "CrySentry exit=%s: %s" %
                    (proc.returncode, tail),
                    "seconds": round(time.time() - started, 3),
                    "tool_version": jar.name, "raw_output": None}
        if not result.is_file():
            return {"status": "failed", "reason": "CrySentry 成功退出但未生成 JSON。",
                    "seconds": round(time.time() - started, 3),
                    "tool_version": jar.name, "raw_output": None}
        try:
            data = json.loads(result.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as exc:
            return {"status": "failed", "reason": "CrySentry JSON 无法解析: %s" % exc,
                    "seconds": round(time.time() - started, 3),
                    "tool_version": jar.name, "raw_output": None}
        if not isinstance(data, list):
            return {"status": "failed", "reason": "CrySentry JSON 顶层不是数组。",
                    "seconds": round(time.time() - started, 3),
                    "tool_version": jar.name, "raw_output": None}
        log = stdout_path.read_text(encoding="utf-8", errors="replace")
        reachable = re.search(r"#reachable methods:\s*(\d+)", log)
        if reachable and int(reachable.group(1)) == 0:
            return {"status": "failed",
                    "reason": "CrySentry 未分析任何可达方法；请检查目标字节码与入口配置。",
                    "seconds": round(time.time() - started, 3),
                    "tool_version": jar.name, "raw_output": str(result)}
        return {"status": "completed", "reason": None,
                "seconds": round(time.time() - started, 3),
                "tool_version": jar.name, "raw_output": str(result), "data": data}
    except (CrySentryError, OSError, subprocess.SubprocessError) as exc:
        return {"status": "failed", "reason": str(exc),
                "seconds": round(time.time() - started, 3),
                "tool_version": None, "raw_output": None}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="调用仓库外的 CrySentry/Tai-e（不负责构建目标项目）")
    parser.add_argument("--artifact", required=True, help="目标 jar 或 classes 目录")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--home", required=True, help="CrySentry 仓库目录")
    parser.add_argument("--classpath", action="append", default=[])
    parser.add_argument("--java", help="JDK 17 java.exe")
    parser.add_argument("--tool-jar")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--memory-mb", type=int, default=4096)
    parser.add_argument("--java-target-version", type=int, default=8)
    args = parser.parse_args(argv)
    result = run(args.artifact, args.output_dir, args.home, args.classpath,
                 args.java, args.tool_jar, args.timeout, args.memory_mb,
                 args.java_target_version)
    print("status: %s" % result["status"])
    print("seconds: %s" % result["seconds"])
    print("tool: %s" % result.get("tool_version"))
    if result.get("reason"):
        print("reason: %s" % result["reason"])
    if result["status"] == "completed":
        print("findings: %d" % len(result.get("data") or []))
        print("output: %s" % result["raw_output"])
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
