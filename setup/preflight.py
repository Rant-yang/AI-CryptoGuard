"""Read-only deployment preflight for the local AI-CryptoGuard pipeline.

No network calls, scans, source reads, or credential values are emitted.
Run it on a fresh machine *before* the end-to-end demo.
"""
import argparse
import importlib.util
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner.runners.crysentry import (  # noqa: E402
    CrySentryError, find_java, find_tool_jar, java_major,
)


def check_artifact(path):
    """Return a user-facing reason if bytecode is absent or archive is unsafe."""
    target = Path(path)
    if not target.exists():
        return '已编译 Java 产物不存在'
    if target.is_dir():
        return None if any(target.rglob('*.class')) else 'classes 目录没有 .class 文件'
    if target.suffix.lower() != '.jar':
        return 'Java 产物必须是 jar 或 classes 目录'
    try:
        with zipfile.ZipFile(target) as archive:
            entries = archive.namelist()
            for name in entries:
                normalized = name.replace('\\', '/')
                p = PurePosixPath(normalized)
                if p.is_absolute() or '..' in p.parts or \
                        (p.parts and ':' in p.parts[0]):
                    return 'jar 含越界路径，不能交给第三方解压器'
            if not any(name.endswith('.class') for name in entries):
                return 'jar 中没有 .class 文件'
    except (OSError, zipfile.BadZipFile):
        return 'jar 不是有效 ZIP'
    return None


def source_bytecode_overlap(source_root, artifact):
    """A conservative signal that the supplied jar belongs to this source tree."""
    source_names = {p.stem for p in Path(source_root).rglob('*.java')}
    target = Path(artifact)
    if target.is_dir():
        class_names = {p.stem.split('$', 1)[0]
                       for p in target.rglob('*.class')}
    else:
        with zipfile.ZipFile(target) as archive:
            class_names = {PurePosixPath(n.replace('\\', '/')).stem.split('$', 1)[0]
                           for n in archive.namelist() if n.endswith('.class')}
    return len(source_names & class_names)


def inspect(args):
    rows = []

    def add(name, ok, advice=''):
        rows.append((name, bool(ok), advice if not ok else ''))

    add('Python >= 3.10', sys.version_info >= (3, 10), '安装 Python 3.10+。')
    add('jsonschema', importlib.util.find_spec('jsonschema') is not None,
        '运行 python -m pip install -r ai\\requirements.txt。')
    tools = Path(args.tools_dir).resolve()
    crypto = tools / 'cryptoscan' / ('cryptoscan.exe' if os.name == 'nt' else 'cryptoscan')
    cbom = tools / 'cbom-scan' / 'cbom.js'
    add('CryptoScan', crypto.is_file(), '在 --tools-dir 下放置 cryptoscan/cryptoscan.exe。')
    if os.name != 'nt' and crypto.is_file():
        add('CryptoScan 可执行权限', os.access(crypto, os.X_OK),
            'Linux 工具文件缺少执行权限；在外部工具目录 chmod +x cryptoscan/cryptoscan。')
    add('cbom-scan', cbom.is_file(), '在 --tools-dir 下放置 cbom-scan/cbom.js。')
    add('Node.js', shutil.which('node') is not None, '安装 Node.js 并加入 PATH。')

    if args.target:
        target = Path(args.target)
        add('扫描项目', target.is_dir(), '--target 必须是现有项目目录。')
        if args.mode == 'deep-java' and target.is_dir():
            add('Java 源码', any(target.rglob('*.java')),
                '深度模式需要含 .java 的项目，源码用于字节码行号映射。')

    if args.mode == 'deep-java':
        add('Java 源码目录已指定', bool(args.target),
            '深度模式需用 --target 指定与编译产物对应的源码目录。')
        home = args.crysentry_home or os.environ.get('CRYSENTRY_HOME')
        add('CrySentry 外部目录', bool(home and Path(home).is_dir()),
            '用 --crysentry-home 指向仓库外的 CrySentry checkout。')
        if home and Path(home).is_dir():
            try:
                find_tool_jar(home, args.crysentry_jar)
                add('CrySentry fatJar', True)
            except CrySentryError:
                add('CrySentry fatJar', False,
                    '在 CrySentry 仓库构建 fatJar，或用 --crysentry-jar 指定。')
        try:
            java = find_java(args.crysentry_java)
            add('JDK 17', java_major(java) == 17,
                '用 --crysentry-java 指定 JDK 17 的 java.exe。')
        except (CrySentryError, OSError, subprocess.SubprocessError):
            add('JDK 17', False, '用 --crysentry-java 指定 JDK 17 的 java.exe。')
        add('Java 编译产物', bool(args.java_artifact),
            '先构建目标项目，再传入 --java-artifact jar/classes。')
        if args.java_artifact:
            issue = check_artifact(args.java_artifact)
            add('产物可读且含 class', issue is None, issue or '')
            if issue is None and args.target and Path(args.target).is_dir():
                overlap = source_bytecode_overlap(args.target, args.java_artifact)
                add('产物与源码有同名类', overlap > 0,
                    '未发现与源码同名的 class；请确认 --java-artifact 来自 --target。')

    if args.ai:
        add('anthropic SDK', importlib.util.find_spec('anthropic') is not None,
            '运行 python -m pip install -r ai\\requirements.txt。')
        add('AI 凭据已配置', bool(os.environ.get('ANTHROPIC_AUTH_TOKEN')),
            '仅在本机设置 ANTHROPIC_AUTH_TOKEN；不要放进仓库或日志。')
        add('AI 模型已配置', bool(os.environ.get('ANTHROPIC_MODEL')),
            '设置 ANTHROPIC_MODEL。')
        if args.compatible_api:
            add('兼容服务端点已配置', bool(os.environ.get('ANTHROPIC_BASE_URL')),
                '使用 DeepSeek 等兼容服务时设置 ANTHROPIC_BASE_URL，避免请求发错服务商。')
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description='部署前只读检查；不运行扫描、不发送源码')
    ap.add_argument('--tools-dir', default=os.environ.get('ACG_TOOLS_DIR',
                    str(ROOT / 'tools')))
    ap.add_argument('--target', help='待演示的项目源码目录')
    ap.add_argument('--mode', choices=('fast', 'deep-java'), default='fast')
    ap.add_argument('--crysentry-home')
    ap.add_argument('--crysentry-java')
    ap.add_argument('--crysentry-jar')
    ap.add_argument('--java-artifact')
    ap.add_argument('--ai', action='store_true')
    ap.add_argument('--compatible-api', action='store_true',
                    help='使用 DeepSeek 等 Anthropic 兼容端点时检查 BASE_URL')
    args = ap.parse_args(argv)
    if args.compatible_api and not args.ai:
        ap.error('--compatible-api 必须与 --ai 一起使用')
    rows = inspect(args)
    for name, ok, advice in rows:
        print('[%s] %s%s' % ('PASS' if ok else 'FAIL', name,
                              '' if ok else ' — ' + advice))
    print('检查 %d 项；失败 %d 项。此检查不替代实际扫描/模型调用。' %
          (len(rows), sum(not ok for _, ok, _ in rows)))
    return 0 if all(ok for _, ok, _ in rows) else 2


if __name__ == '__main__':
    raise SystemExit(main())
