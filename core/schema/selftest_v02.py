"""Offline contract regression tests; no API calls."""
import copy
import json
from pathlib import Path
from jsonschema import Draft7Validator
from validate_v02 import errors
root=Path(__file__).resolve().parents[2]
count=0
for path in (root/'core/samples/v0.2').glob('*.json'):
    data=json.loads(path.read_text(encoding='utf-8'))
    for row in data if isinstance(data,list) else [data]:
        assert not errors(row), (path,errors(row))
        count+=1
assert count==13
base=json.loads((root/'core/samples/v0.2/java_complete.json').read_text(encoding='utf-8'))[-1]
def reject(mutate):
    row=copy.deepcopy(base); mutate(row); assert errors(row), 'invalid fixture accepted'
reject(lambda f:f.update(unexpected=True))
reject(lambda f:f.pop('quantum_assessment'))
reject(lambda f:f.update(evidence_refs=['E2']))
reject(lambda f:f['evidence'][0]['flow'].update(source=None))
reject(lambda f:f['evidence'][0]['lines'].append(99))
reject(lambda f:f['remediation_steps'][0].update(rule_refs=['invented.rule']))
reject(lambda f:f.update(stage='assessed'))
reject(lambda f:f.update(usage='signing'))
reject(lambda f:f.update(file='D:/private/source.java'))
schema=json.loads((root/'core/schema/finding.v0.1.json').read_text(encoding='utf-8'))
for row in json.loads((root/'core/samples/example_finding.json').read_text(encoding='utf-8')):
    Draft7Validator(schema).validate(row)
print('PASS: 13 v0.2 fixtures, 9 negative mutations, legacy v0.1 fixtures')
