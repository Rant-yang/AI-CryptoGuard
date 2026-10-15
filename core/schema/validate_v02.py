"""Validate v0.2 finding(s) or task; no input values are printed."""
import hashlib
import json
import re
import sys
from pathlib import Path
from jsonschema import Draft7Validator
HERE = Path(__file__).resolve().parent
DIGEST_FIELDS = ('schema_version','finding_id','finding_kind','rule_id','file','line',
                 'algorithm','algorithm_normalized','risk','severity','confidence','evidence','quantum_assessment')
def input_digest(f):
    payload = {k:f[k] for k in DIGEST_FIELDS if k in f}
    return hashlib.sha256(json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')).hexdigest()
def errors(f):
    task = isinstance(f,dict) and 'task_id' in f
    schema = json.loads((HERE/('task.v0.2.json' if task else 'finding.v0.2.json')).read_text(encoding='utf-8'))
    Draft7Validator.check_schema(schema)
    issues = ['%s: %s' % ('/'.join(map(str,e.path)) or 'root',e.validator) for e in Draft7Validator(schema).iter_errors(f)]
    if issues: return issues
    def flowcheck(flow):
        if flow['completeness']=='complete' and flow['source'] is None: issues.append('complete flow requires source')
        if flow['completeness']=='source_missing' and flow['source'] is not None: issues.append('source_missing requires null source')
    if task:
        names=[s['name'] for s in f['stages']]
        if len(names)!=len(set(names)): issues.append('duplicate stage')
        for s in f['stages']:
            if s['status'] in ('skipped','failed','timeout') and not s['reason']: issues.append('non-success stage requires reason')
        for e in f['unresolved_deep_evidence']: flowcheck(e['flow'])
        profile=f.get('quantum_timeline_profile')
        if profile:
            values=[profile[k] for k in ('data_lifetime_years','migration_lead_years','threat_horizon_years')]
            if any(v is None for v in values) != all(v is None for v in values):
                issues.append('timeline profile requires all X/Y/Z or none')
        return issues
    if f['file'].startswith(('/',chr(92))) or re.match(r'^[A-Za-z]:',f['file']) or '..' in f['file'].replace(chr(92),'/').split('/'):
        issues.append('file must be project-relative')
    def walk(x):
        if isinstance(x,dict):
            for k,v in x.items():
                if k=='raw': continue
                if k=='evidence_refs' and any(int(ref[1:])>len(f['evidence']) for ref in v): issues.append('evidence reference out of range')
                walk(v)
        elif isinstance(x,list):
            for v in x: walk(v)
    walk(f)
    for e in f['evidence']:
        if 'flow' in e: flowcheck(e['flow'])
    q=f.get('quantum_assessment')
    if q:
        if q['status']=='assessed' and (not q['rule_refs'] or not q['evidence_refs']): issues.append('assessment requires rules and evidence')
        if q['status']=='insufficient_evidence' and not q['unknowns']: issues.append('insufficient evidence requires unknowns')
        if f['finding_kind']=='credential' and (q['status']!='not_applicable' or q['quantum_effect']!='not_applicable' or q['migration_candidates']): issues.append('credential must not receive PQC migration')
        if q['status']=='not_applicable' and q['quantum_effect']!='not_applicable': issues.append('inconsistent quantum applicability')
        timeline=q.get('quantum_timeline')
        if timeline:
            values=[timeline[k] for k in ('data_lifetime_years','migration_lead_years','threat_horizon_years')]
            if timeline['status']=='assessed':
                if any(v is None for v in values): issues.append('assessed timeline requires X/Y/Z')
                else:
                    expected=max(0,round(values[2]-values[0]-values[1],3))
                    if timeline['years_until_action']!=expected: issues.append('timeline action year mismatch')
                    expected_urgency='immediate' if expected==0 else 'scheduled'
                    if timeline['urgency']!=expected_urgency: issues.append('timeline urgency mismatch')
            if timeline['status']=='not_configured' and not all(v is None for v in values):
                issues.append('not_configured timeline must not contain partial values')
            if timeline['status']=='not_applicable' and (timeline['urgency']!='not_applicable' or timeline['hndl_status']!='not_applicable'):
                issues.append('inconsistent timeline applicability')
            if timeline['hndl_status']=='at_risk' and 'QT-HNDL-CONFIDENTIALITY' not in timeline['rule_refs']:
                issues.append('HNDL risk requires rule reference')
    if f['stage']!='explained' and any(k in f for k in ('usage_assessment','remediation_steps','analysis_provenance')): issues.append('AI fields require explained stage')
    if f['stage']=='explained':
        if f['usage']!=f['usage_assessment']['usage']: issues.append('usage mismatch')
        if f['analysis_provenance']['input_digest']!=input_digest(f): issues.append('stale input digest')
        if f['analysis_provenance']['rule_version']!=q['rule_version']: issues.append('rule version mismatch')
        for step in f['remediation_steps']:
            if not set(step['rule_refs']).issubset(q['rule_refs']): issues.append('step cites unapproved rule')
    rem=f['remediation']
    if 'reason' in rem and rem['decided']!=(rem['reason']=='decided'): issues.append('decided/reason mismatch')
    return issues
def main():
    if len(sys.argv)!=2: print('Usage: python core/schema/validate_v02.py FILE'); return 2
    try:
        data=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8-sig'))
        rows=data if isinstance(data,list) else [data]
        bad=0
        for i,f in enumerate(rows):
            errs=errors(f)
            if errs:
                bad+=1
                print('FAIL row %d: %s' % (i,'; '.join(errs)))
        print('v0.2: %d records, %d invalid' % (len(rows),bad))
        return int(bool(bad))
    except (OSError,ValueError):
        print('Cannot read input JSON'); return 2
if __name__=='__main__': sys.exit(main())
