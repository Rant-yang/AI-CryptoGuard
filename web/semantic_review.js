/* Offline human-review editor. It never decides whether an AI claim is correct. */
(() => {
  'use strict';
  const KEYS = [
    'review_usage_supported',
    'review_refs_support_claims',
    'review_explanation_correct',
    'review_steps_actionable',
  ];
  const LABELS = ['用途有证据支持', '引用确实支持说法', '密码解释正确', '整改步骤可执行'];
  const PROTOCOL = 'AI-v0.2-public-cohort-human-review-v1';

  function validatePacket(data) {
    if (!data || data.review_protocol !== PROTOCOL || !Array.isArray(data.cases) || !data.cases.length) {
      throw new Error('文件不是本轮 AI v0.2 人工盲审包。');
    }
    const ids = new Set();
    if (data.expected_cases !== undefined &&
        (!Number.isSafeInteger(data.expected_cases) ||
         data.expected_cases !== data.cases.length)) {
      throw new Error('盲审包条数与声明的固定批次不一致。');
    }
    if (data.assessed_sha256 !== undefined &&
        (typeof data.assessed_sha256 !== 'string' ||
         !/^[0-9a-f]{64}$/.test(data.assessed_sha256))) {
      throw new Error('冻结输入摘要格式不正确。');
    }
    for (const row of data.cases) {
      if (!row || typeof row.finding_id !== 'string' || !row.finding_id || ids.has(row.finding_id)) {
        throw new Error('案例 ID 缺失或重复。');
      }
      ids.add(row.finding_id);
      for (const key of KEYS) {
        if (!Object.prototype.hasOwnProperty.call(row, key) ||
            (row[key] !== null && typeof row[key] !== 'boolean')) {
          throw new Error(`${row.finding_id}: ${key} 必须为 true、false 或 null。`);
        }
      }
      if (!Array.isArray(row.evidence) || !Array.isArray(row.remediation_steps)) {
        throw new Error(`${row.finding_id}: 证据或整改步骤格式不正确。`);
      }
    }
    return data;
  }

  function progress(data) {
    const cases = data.cases;
    const complete = cases.filter(row => KEYS.every(key => typeof row[key] === 'boolean')).length;
    const failed = cases.filter(row => KEYS.some(key => row[key] === false)).length;
    return {complete, failed, total: cases.length};
  }

  function reviewFilename(data) {
    const batch = typeof data.cohort === 'string' && data.cohort
      ? data.cohort.replace(/[^A-Za-z0-9_-]/g, '_')
      : `unidentified-${data.cases.length}`;
    return `ai_semantic_${batch}_human_review.json`;
  }

  // Exports keep the format checks testable without relying on a mirrored DOM stub.
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {KEYS, PROTOCOL, validatePacket, progress, reviewFilename};
  }
  if (typeof document === 'undefined') return;

  const $ = id => document.getElementById(id);
  const state = {packet: null, index: 0, dirty: false};
  function markDirty() {
    state.dirty = true;
    $('export').textContent = '导出当前审阅 JSON（有未保存修改）';
  }
  window.addEventListener('beforeunload', event => {
    if (!state.dirty) return;
    event.preventDefault();
    event.returnValue = '';
  });
  function elt(tag, className, value) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value != null) node.textContent = String(value);
    return node;
  }
  function field(parent, title, value) {
    const block = elt('div', 'field');
    block.append(elt('div', 'field-title', title), elt('div', 'field-body', value || '（未提供）'));
    parent.append(block);
  }
  function refs(value) {
    return Array.isArray(value) && value.length ? value.join('、') : '无引用';
  }
  function render() {
    if (!state.packet) return;
    const rows = state.packet.cases;
    const row = rows[state.index];
    const p = progress(state.packet);
    $('status').textContent = `已审完 ${p.complete}/${p.total} · 含未通过项 ${p.failed} · 当前 ${state.index + 1}/${p.total}`;
    $('meter').value = p.complete;
    $('meter').max = p.total;
    $('case-select').replaceChildren();
    rows.forEach((item, i) => {
      const done = KEYS.every(key => typeof item[key] === 'boolean');
      const option = elt('option', '', `${String(i + 1).padStart(2, '0')}  ${done ? '✓' : '·'}  ${item.file} · ${item.algorithm}`);
      option.value = String(i);
      $('case-select').append(option);
    });
    $('case-select').value = String(state.index);
    $('previous').disabled = state.index === 0;
    $('next').disabled = state.index === rows.length - 1;
    $('case-title').textContent = `${row.file}  ·  ${row.algorithm}`;
    $('case-id').textContent = `发现编号 ${row.finding_id}`;
    const claims = $('claims');
    claims.replaceChildren();
    field(claims, '模型判断的用途', row.model_usage);
    field(claims, '用途判断理由', row.usage_reason);
    field(claims, '风险解释', row.explanation);
    field(claims, '模型引用的证据', refs(row.evidence_refs));
    const evidence = $('evidence');
    evidence.replaceChildren();
    if (!row.evidence.length) evidence.append(elt('p', 'muted', '没有提供证据；请回到公开源码核对。'));
    row.evidence.forEach(ev => {
      const card = elt('article', 'evidence-card');
      card.append(elt('strong', '', `${ev.ref || '?'} · ${ev.tool || '来源未标明'} · ${ev.kind || '类别未标明'}`));
      field(card, '调用形状', ev.call_shape);
      field(card, '源码行号', Array.isArray(ev.lines) && ev.lines.length ? ev.lines.join('、') : '未提供');
      evidence.append(card);
    });
    const steps = $('steps');
    steps.replaceChildren();
    if (!row.remediation_steps.length) steps.append(elt('p', 'muted', '模型没有给出整改步骤。'));
    row.remediation_steps.forEach((step, i) => {
      const card = elt('article', 'step-card');
      card.append(elt('strong', '', `步骤 ${i + 1}`));
      field(card, '操作', step.action);
      field(card, '前置条件', step.prerequisites);
      field(card, '复验方法', step.verification);
      field(card, '证据 / 规则引用', `${refs(step.evidence_refs)} ｜ ${refs(step.rule_refs)}`);
      steps.append(card);
    });
    const form = $('review-fields');
    form.replaceChildren();
    KEYS.forEach((key, i) => {
      const wrap = elt('label', 'review-field');
      wrap.append(elt('span', '', LABELS[i]));
      const select = elt('select');
      [['', '未审'], ['true', '支持'], ['false', '不支持 / 证据不足']].forEach(([value, label]) => {
        const option = elt('option', '', label);
        option.value = value;
        select.append(option);
      });
      select.value = row[key] === null ? '' : String(row[key]);
      select.addEventListener('change', () => {
        row[key] = select.value === '' ? null : select.value === 'true';
        markDirty();
        render();
      });
      wrap.append(select);
      form.append(wrap);
    });
    $('notes').value = row.review_notes || '';
    $('note-warning').hidden = !(KEYS.some(key => row[key] === false) && !String(row.review_notes || '').trim());
  }

  $('packet-file').addEventListener('change', async event => {
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    if (state.dirty && !window.confirm('当前审阅有未导出的修改。重新导入会覆盖它们，确定继续吗？')) {
      event.target.value = '';
      return;
    }
    try {
      const parsed = validatePacket(JSON.parse((await file.text()).replace(/^\uFEFF/, '')));
      state.packet = parsed;
      state.index = 0;
      state.dirty = false;
      $('export').textContent = '导出当前审阅 JSON';
      $('workspace').hidden = false;
      $('empty').hidden = true;
      $('error').textContent = '';
      $('cohort-note').textContent = `批次：${parsed.cohort || '未标明'}；输入 SHA-256：${parsed.assessed_sha256 || '未标明'}；冻结案例 ${parsed.cases.length} 条。全部完成后导出 JSON，再运行 python benchmark\\ai_semantic_review.py 审阅结果.json --require-complete。未审完不能计算本批语义通过率。`;
      render();
    } catch (error) {
      $('error').textContent = `无法导入：${error.message}`;
    }
    event.target.value = '';
  });
  $('case-select').addEventListener('change', event => {state.index = Number(event.target.value); render();});
  $('previous').addEventListener('click', () => {if (state.index > 0) {state.index--; render();}});
  $('next').addEventListener('click', () => {if (state.index + 1 < state.packet.cases.length) {state.index++; render();}});
  $('next-pending').addEventListener('click', () => {
    const rows = state.packet.cases;
    const pending = rows.findIndex((row, i) => i > state.index && KEYS.some(key => row[key] === null));
    const wrapped = rows.findIndex(row => KEYS.some(key => row[key] === null));
    if (pending >= 0 || wrapped >= 0) {state.index = pending >= 0 ? pending : wrapped; render();}
  });
  $('notes').addEventListener('input', event => {
    state.packet.cases[state.index].review_notes = event.target.value || null;
    markDirty();
    $('note-warning').hidden = !(KEYS.some(key => state.packet.cases[state.index][key] === false) && !event.target.value.trim());
  });
  $('export').addEventListener('click', () => {
    if (!state.packet) return;
    const blob = new Blob([JSON.stringify(state.packet, null, 2)], {type: 'application/json;charset=utf-8'});
    const url = URL.createObjectURL(blob);
    const link = elt('a');
    link.href = url;
    link.download = reviewFilename(state.packet);
    document.body.append(link);
    link.click();
    link.remove();
    // Browsers do not tell this page whether the download actually finished.
    // Keep the leave/re-import warning until the reviewer confirms the file
    // exists; otherwise a blocked download could silently lose all judgments.
    if (state.dirty) $('export').textContent = '已请求下载；请确认文件存在';
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
})();
