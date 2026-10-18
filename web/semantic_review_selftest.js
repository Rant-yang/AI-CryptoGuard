/* Format and progress checks independent of the DOM implementation. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {KEYS, PROTOCOL, validatePacket, progress} = require('./semantic_review.js');

const blank = () => ({
  finding_id: 'F1', file: 'Demo.java', algorithm: 'RSA',
  evidence: [{ref: 'E1', call_shape: 'Cipher.getInstance', lines: [3]}],
  remediation_steps: [], review_notes: null,
  ...Object.fromEntries(KEYS.map(key => [key, null])),
});
const packet = {review_protocol: PROTOCOL, instructions: '人工复核', cases: [blank()]};
assert.equal(validatePacket(packet), packet);
assert.deepEqual(progress(packet), {complete: 0, failed: 0, total: 1});
packet.cases[0][KEYS[0]] = false;
assert.deepEqual(progress(packet), {complete: 0, failed: 1, total: 1});
KEYS.slice(1).forEach(key => {packet.cases[0][key] = true;});
assert.deepEqual(progress(packet), {complete: 1, failed: 1, total: 1});
assert.throws(() => validatePacket({...packet, cases: [blank(), blank()]}), /重复/);
assert.throws(() => validatePacket({...packet, cases: [{...blank(), [KEYS[0]]: 'true'}]}), /true、false/);
assert.throws(() => validatePacket({...packet, review_protocol: 'wrong'}), /盲审包/);

if (process.argv[2]) {
  const real = validatePacket(JSON.parse(fs.readFileSync(process.argv[2], 'utf8')));
  assert.equal(real.cases.length, 30, '固定公开样本应为 30 条');
  assert.deepEqual(progress(real), {complete: 0, failed: 0, total: 30}, '原包不得预填人工结论');
  assert.equal(real.cases.every(c => c.evidence.every(e => !Object.hasOwn(e, 'raw'))), true,
    '盲审包不得携带 raw 源码');
}
console.log('[PASS] 离线人工复核编辑器：包契约、进度计算、拒绝伪值和重复 ID');
