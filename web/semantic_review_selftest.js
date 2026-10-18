/* Format and progress checks independent of the DOM implementation. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {KEYS, PROTOCOL, validatePacket, progress, reviewFilename} = require('./semantic_review.js');

const blank = () => ({
  finding_id: 'F1', file: 'Demo.java', algorithm: 'RSA',
  evidence: [{ref: 'E1', call_shape: 'Cipher.getInstance', lines: [3]}],
  remediation_steps: [], review_notes: null,
  ...Object.fromEntries(KEYS.map(key => [key, null])),
});
const packet = {review_protocol: PROTOCOL, instructions: '人工复核', cases: [blank()]};
const page = fs.readFileSync(require('node:path').join(__dirname, 'semantic_review.html'), 'utf8');
assert.doesNotMatch(page, /只有 30\/30|这 30 条|ai_semantic_30_blind_review/,
  '页面不能把旧批次的 30 条误写成所有批次的固定数量');
assert.equal(validatePacket(packet), packet);
assert.deepEqual(progress(packet), {complete: 0, failed: 0, total: 1});
packet.cases[0][KEYS[0]] = false;
assert.deepEqual(progress(packet), {complete: 0, failed: 1, total: 1});
KEYS.slice(1).forEach(key => {packet.cases[0][key] = true;});
assert.deepEqual(progress(packet), {complete: 1, failed: 1, total: 1});
assert.throws(() => validatePacket({...packet, cases: [blank(), blank()]}), /重复/);
assert.throws(() => validatePacket({...packet, cases: [{...blank(), [KEYS[0]]: 'true'}]}), /true、false/);
assert.throws(() => validatePacket({...packet, review_protocol: 'wrong'}), /盲审包/);
assert.throws(() => validatePacket({...packet, expected_cases: 28}), /条数/);
const identifiedPacket = {...packet, expected_cases: 1, assessed_sha256: 'a'.repeat(64)};
assert.equal(validatePacket(identifiedPacket), identifiedPacket,
  '有冻结输入摘要的包应可导入');
assert.equal(reviewFilename({...packet, cohort: 'public-tls-review-v2'}),
  'ai_semantic_public-tls-review-v2_human_review.json');

if (process.argv[2]) {
  if (process.argv[3] === undefined) {
    throw new Error('传入盲审包时必须显式给出预登记条数（旧批次 30，当前批次 28）。');
  }
  const expected = Number(process.argv[3]);
  assert.ok(Number.isSafeInteger(expected) && expected > 0,
    '期望样本数必须是正整数');
  const real = validatePacket(JSON.parse(fs.readFileSync(process.argv[2], 'utf8')));
  assert.equal(real.cases.length, expected, '盲审包条数与预登记批次不符');
  assert.deepEqual(progress(real), {complete: 0, failed: 0, total: expected},
    '原包不得预填人工结论');
  assert.equal(real.cases.every(c => c.evidence.every(e => !Object.hasOwn(e, 'raw'))), true,
    '盲审包不得携带 raw 源码');
}
console.log('[PASS] 离线人工复核编辑器：包契约、进度计算、拒绝伪值和重复 ID');
