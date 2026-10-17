"""临时对比：credential_scan 旧逻辑 vs 新逻辑，找出误伤与新增。"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scanner'))
from adapters import credential_scan as cs

_OLD_PLACEHOLDER = re.compile(r'(?i)^(?:example|sample|dummy|placeholder|replace[_-]?me|changeme|your[_-].*|<.*>|\$\{.*\}|%\w+%)$')
_OLD_WEAK = {'admin', 'admin123', 'password', 'password1', 'passw0rd', '123456',
             '12345678', 'root', 'guest', 'test', 'default', 'changeme', 'secret'}


def old_rule(name, value, context=None):
    if cs._PASSWORD.search(name):
        return 'CRED-HARDCODED-PASSWORD'
    if cs._TOKEN.search(name):
        return 'CRED-HARDCODED-TOKEN'
    if cs._CRYPTO_KEY.search(name):
        return 'CRED-HARDCODED-CRYPTO-KEY'
    if ((context or {}).get('generic_key_sensitive')
            and cs._GENERIC_KEY_NAME.fullmatch(name)):
        return (context or {}).get('generic_key_rule', 'CRED-HARDCODED-CRYPTO-KEY')
    return None


def old_line(ln, line, ctx):
    out = set()
    for m in cs._ASSIGN_RE.finditer(line):
        name, value = m.group('name'), m.group('value')
        if cs._RUNTIME_SOURCE_RE.search(m.group('prefix')):
            continue
        if _OLD_PLACEHOLDER.match(value.strip()):
            continue
        rule = old_rule(name, value, ctx)
        is_weak = value.lower() in _OLD_WEAK and cs._SENSITIVE.search(name)
        if is_weak:
            out.add(('CRED-DEFAULT-WEAK', ln))
        elif rule:
            out.add((rule, ln))
    for m in cs._ARRAY_ASSIGN_RE.finditer(line):
        name, value = m.group('name'), m.group('value')
        rule = old_rule(name, value, ctx)
        if rule:
            out.add((rule, ln))
    for m in cs._CHAR_ARRAY_ASSIGN_RE.finditer(line):
        name, value = m.group('name'), m.group('value')
        rule = old_rule(name, value, ctx)
        if rule:
            out.add((rule, ln))
    return out


def new_line(rel, ln, line, ctx):
    out = set()
    for fr in cs._scan_line(rel, ln, line, b'x' * 32, ctx):
        out.add((fr['rule_id'], ln))
    return out


def main():
    targets = {
        'cryptoapi-bench': r'D:\acg-scanner\_benchmarks\_anon\cryptoapi-bench',
        'cambench-cap': r'D:\acg-scanner\_benchmarks\_anon\cambench-cap',
        'llmcmt': r'D:\acg-scanner\_benchmarks\_anon\llmcmt',
    }
    lost, gained = [], []
    for name, tgt in targets.items():
        for dp, dn, fns in os.walk(tgt):
            for fn in sorted(fns):
                p = os.path.join(dp, fn)
                rel = os.path.relpath(p, tgt).replace('\\', '/')
                if os.path.splitext(fn)[1].lower() not in cs._EXTS:
                    continue
                try:
                    text = open(p, encoding='utf-8-sig', errors='replace').read()
                except OSError:
                    continue
                ctx = {
                    'generic_key_sensitive': bool(cs._CRYPTO_CONTEXT_RE.search(text)),
                    'generic_key_rule': ('CRED-HARDCODED-PASSWORD'
                                         if cs._PASSWORD_CONTEXT_RE.search(text)
                                         else 'CRED-HARDCODED-CRYPTO-KEY'),
                }
                for ln, line in enumerate(text.splitlines(), 1):
                    o = old_line(ln, line, ctx)
                    n = new_line(rel, ln, line, ctx)
                    for x in o - n:
                        lost.append((name, rel, x[0], x[1], line.strip()[:70]))
                    for x in n - o:
                        gained.append((name, rel, x[0], x[1], line.strip()[:70]))

    print('=== 误伤（旧报新不报）共 %d ===' % len(lost))
    for name, rel, rule, ln, s in lost:
        print('  [%s] %s L%d %s | %s' % (name, rel.split('/')[-1], ln, rule, s))
    print()
    print('=== 新增（新报旧不报）共 %d ===' % len(gained))
    for name, rel, rule, ln, s in gained:
        print('  [%s] %s L%d %s | %s' % (name, rel.split('/')[-1], ln, rule, s))


if __name__ == '__main__':
    main()
