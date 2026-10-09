"""把融合后的 findings 渲染成 CycloneDX 1.6 CBOM（密码学物料清单）。

为什么自己渲染而不透传 cbom-scan 的 --cbom 输出:
    上游那份只反映它一家的口径；这份的 components 与 occurrences 来自
    **双源融合后的 finding**，并把我们的裁决（risk 五档 / usage / severity /
    finding_id / 纠正标记）作为标准 properties 挂上 —— 工业互操作格式里
    带的是融合层结论，这是中间层的直接展示物。

字段口径对齐 CycloneDX 1.6 cryptographic-asset（结构参考 cbom-scan 的
--cbom 输出实测），自定义信息走 properties（ai-cryptoguard: 命名空间）。
nistQuantumSecurityLevel 沿用 cbom-scan 的取值习惯:
    shor / broken / review -> 0, grover -> 1, safe -> 5

可复现性: serialNumber 用 uuid5(内容指纹) 而不是随机 uuid ——
同一份代码重复扫描得到同一份 CBOM（与 findings.json 的确定性一致）。
"""
import hashlib
import uuid

#: 我方 risk 五档 -> CycloneDX 习惯的安全级别
NIST_LEVEL = {'shor': 0, 'broken': 0, 'review': 0, 'grover': 1, 'safe': 5}

_NS = uuid.UUID('6ba7b811-9dad-11d1-80b4-00c04fd430c8')  # uuid.NAMESPACE_URL


def render_cbom(findings, target_label):
    """findings 列表 -> CycloneDX 1.6 dict。"""
    by_alg = {}
    for f in findings:
        if not f['algorithm_normalized']:
            # no-algorithm 的线索类发现不属于「算法物料清单」，不进 CBOM
            continue
        by_alg.setdefault(f['algorithm_normalized'], []).append(f)

    components = []
    for alg in sorted(by_alg):
        fs = by_alg[alg]
        risks = {f['risk'] for f in fs}
        usages = sorted({f['usage'] for f in fs})
        level = max(NIST_LEVEL.get(r, 0) for r in risks)
        corrected = any('upstream-risk-corrected' in f.get('tags', []) for f in fs)
        occurrences = sorted({
            '%s:%d' % (f['file'], ln)
            for f in fs for e in f['evidence'] for ln in e['lines']
        })
        components.append({
            'type': 'cryptographic-asset',
            'bom-ref': 'acg-%s' % alg.lower(),
            'name': fs[0]['algorithm'],
            'cryptoProperties': {
                'assetType': 'algorithm',
                'algorithmProperties': {
                    'nistQuantumSecurityLevel': level,
                },
            },
            'evidence': {'occurrences': [{'location': loc} for loc in occurrences]},
            'properties': [
                {'name': 'ai-cryptoguard:algorithm-normalized', 'value': alg},
                {'name': 'ai-cryptoguard:risk',
                 'value': ','.join(sorted(risks))},
                {'name': 'ai-cryptoguard:severity',
                 'value': ','.join(sorted({f['severity'] for f in fs}))},
                {'name': 'ai-cryptoguard:usages', 'value': ','.join(usages)},
                {'name': 'ai-cryptoguard:finding-refs',
                 'value': ','.join(f['finding_id'] for f in fs)},
                {'name': 'ai-cryptoguard:upstream-risk-corrected',
                 'value': 'true' if corrected else 'false'},
            ],
        })

    # 指纹必须覆盖**裁决字段**（risk/severity/usages/finding-refs），不只位置:
    # 规则表更新导致裁决变化时，CBOM 内容变了，serialNumber 必须跟着变
    #（CycloneDX 语义: serialNumber 标识 BOM 内容版本），否则下游会当成没变。
    fingerprint = hashlib.sha1(
        '|'.join(c['bom-ref'] + ':' + '|'.join(
                     p['value'] for p in c['properties']) + ':' + ','.join(
                     o['location'] for o in c['evidence']['occurrences'])
                 for c in components).encode('utf-8')).hexdigest()
    return {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.6',
        'serialNumber': 'urn:uuid:%s' % uuid.uuid5(_NS, 'acg-cbom-' + fingerprint),
        'version': 1,
        'metadata': {
            'component': {'type': 'application', 'name': 'AI-CryptoGuard scanner'},
            'properties': [
                {'name': 'ai-cryptoguard:scan-target', 'value': target_label},
                {'name': 'ai-cryptoguard:finding-count', 'value': str(len(findings))},
            ],
        },
        'components': components,
    }
