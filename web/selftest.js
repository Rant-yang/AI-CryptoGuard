/* 查看器自检 —— 用最小 DOM 桩把 index.html 的脚本跑一遍，喂真实数据。
 *
 * 断言的是**渲染出来的 HTML 里有没有该有的东西**，不是「代码能解析」。
 * 不需要浏览器、不需要装任何依赖（有 node 就行）。
 *
 *     node web/selftest.js                  # 有 out/findings_ai.json 就测它，否则测仓库示例
 *     node web/selftest.js findings.json    # 也可以喂 scanner 的原始产出
 *
 * 退出码: 0 = 全过, 1 = 有断言失败。
 *
 * ── 这个文件自己踩过的一个坑，记在这里 ──
 * 最初 fetch 桩写的是「哪个候选文件存在就给哪个」，于是 autoLoad 永远先命中
 * findings_ai.json —— 传 findings.json 时两次渲染的其实是同一份数据，字符数
 * 一模一样；而断言里的 reason 又是从 argv 文件算的，所以一路 PASS。
 * **测试在骗自己。**
 * 现在桩只供应 argv 指定的那一个文件，并且额外断言「渲染用的数据确实来自
 * argv 文件」。教训：桩比被测代码宽松时，测试就失去证伪能力。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.dirname(__dirname);           // web/ 的上一级 = 仓库根
const TARGET_NAME = (process.argv[2] || 'findings_ai.json')
  .replace(/\\/g, '/').replace(/^out\//, '');
const requested = path.join(ROOT, 'out', TARGET_NAME);
const fixture = path.join(ROOT, 'core', 'samples', 'example_finding.json');
const useFixture = !process.argv[2] && !fs.existsSync(requested);
const TARGET_PATH = useFixture ? fixture : requested;
const TARGET = useFixture ? 'core/samples/example_finding.json' : 'out/' + TARGET_NAME;

if (!fs.existsSync(TARGET_PATH)) {
  console.error('找不到数据文件: ' + TARGET_PATH);
  console.error('先跑一遍 scanner 或 ai/ 生成 out/ 下的产出。');
  process.exit(2);
}
if (useFixture) console.log('尚无 out/findings_ai.json；改用仓库内两条格式示例自检。');

const html = fs.readFileSync(path.join(ROOT, 'web', 'index.html'), 'utf8');
const m = html.match(/<script>\r?\n([\s\S]*?)\r?\n<\/script>/);
if (!m) { console.error('从 index.html 里提取不到 <script>'); process.exit(1); }
// 页面默认只枚举正式产物名。自检允许传任意 out/ 文件，因此把本次目标
// 注入候选首位；fetch 桩仍只供应这一份文件，不会退回到别的数据自欺。
const code = m[1].replace(
  'const CANDIDATES = [',
  `const CANDIDATES = ['../${TARGET}',`);

const data = JSON.parse(fs.readFileSync(TARGET_PATH, 'utf8'));

/* ------------------------------ DOM 桩 ------------------------------ */

const store = {};
function mkEl(sel) {
  if (store[sel]) return store[sel];
  const el = {
    _sel: sel, _html: '', textContent: '', onclick: null, oninput: null,
    onchange: null, dataset: {}, style: {}, files: [],
    classList: { add() {}, remove() {}, contains() { return false; } },
    querySelectorAll() { return []; },
    querySelector(s) { return mkEl(sel + ' ' + s); },
    click() {},
  };
  Object.defineProperty(el, 'innerHTML', {
    get() { return el._html; },
    set(v) { el._html = String(v); },
  });
  store[sel] = el;
  return el;
}

const documentStub = { querySelector: mkEl, addEventListener() {} };
const windowStub = {};
const alertStub = msg => { throw new Error('页面弹了 alert: ' + msg); };
const FileReaderStub = function () {};

// 只供应 TARGET，其余候选一律 404 —— 见文件头那段教训
const fetchStub = async (url) => {
  const f = url.replace(/^\.\.\//, '').replace(/^\.\//, '');
  if (f === TARGET) {
    return { ok: true, json: async () => JSON.parse(fs.readFileSync(TARGET_PATH, 'utf8')) };
  }
  return { ok: false, json: async () => null };
};

/* ------------------------------ 断言 ------------------------------ */

const FAILS = [];
const check = (desc, cond, extra) => {
  if (!cond) FAILS.push(desc + (extra ? '  (' + extra + ')' : ''));
};

const ARGS = ['document', 'window', 'fetch', 'alert', 'FileReader', 'console'];
const VALS = [documentStub, windowStub, fetchStub, alertStub, FileReaderStub, console];

function load(exported) {
  return new Function(...ARGS, code + '\n; return {' + exported.join(',') + '};')(...VALS);
}

const api = load(['S', 'reasonOf', 'REASON_META', 'RISK_CN', 'USAGE_CN', 'boot']);
const htmlOf = sel => (store[sel] ? store[sel].innerHTML : '');

// start() 是异步的，等一拍
setTimeout(() => {
  const S = api.S;

  /* Java 深扫开关必须真能显示/隐藏编译产物选择器。 */
  const scanMode = mkEl('#scanMode'), artifactConfig = mkEl('#javaArtifactConfig');
  scanMode.value = 'deep-java'; artifactConfig.hidden = true;
  scanMode.onchange();
  check('Java 深扫选项显示 jar 选择器', artifactConfig.hidden === false &&
        html.includes('id="javaArtifact"'));
  scanMode.value = 'fast'; scanMode.onchange();
  check('快速模式隐藏 jar 选择器', artifactConfig.hidden === true);

  /* --- 1. 载入 --- */
  check('数据载入成功', S.rows.length === data.length,
        `rows=${S.rows.length} data=${data.length}`);

  // 证明渲染用的确实是 argv 那个文件，而不是 autoLoad 碰巧先命中的别的文件
  const ids = new Set(S.rows.map(f => f.finding_id));
  check('渲染的数据来自 argv 指定的文件',
        S.rows.length === data.length && data.every(f => ids.has(f.finding_id)),
        TARGET);
  check('导入 JSON 不显示本地任务下载入口', mkEl('#reportDownload').hidden === true);
  api.boot(data, '本地任务 web-test123');
  check('本地任务提供对应的 HTML 下载链接',
        mkEl('#reportDownload').hidden === false &&
        mkEl('#reportDownload').href === '/api/tasks/web-test123/report');

  /* --- 2. 四个区块都渲染了 --- */
  const stats = htmlOf('#stats'), list = htmlOf('#list');
  const detail = htmlOf('#detail'), filters = htmlOf('#filters');

  check('概览已渲染', stats.length > 200, `${stats.length} 字符`);
  check('列表已渲染', list.includes('<table>') && list.includes('<tbody>'), `${list.length} 字符`);
  check('详情已渲染', detail.includes('迁移 / 加固结论'), `${detail.length} 字符`);
  if (data.some(f => f.quantum_assessment)) {
    check('v0.2 前置量子评估已渲染', detail.includes('前置量子风险评估'));
    const timed = JSON.parse(JSON.stringify(data.find(f => f.quantum_assessment)));
    timed.quantum_assessment.quantum_timeline = {
      status:'assessed', urgency:'immediate', data_lifetime_years:10,
      migration_lead_years:3, threat_horizon_years:8, years_until_action:0,
      hndl_exposure:'yes', hndl_status:'at_risk', profile_version:'test',
      source:'user-input', rule_refs:['QT-MOSCA-WINDOW','QT-HNDL-CONFIDENTIALITY'],
      assumptions:['test fixture']
    };
    const timedApi = load(['S', 'renderDetail']);
    timedApi.S.sel = timed; timedApi.renderDetail();
    const timedDetail = htmlOf('#detail');
    check('量子危机时间窗口已渲染', timedDetail.includes('量子危机时间窗'));
    check('立即迁移与 HNDL 风险已渲染',
          timedDetail.includes('应立即启动') && timedDetail.includes('HNDL 高风险'));
  }
  check('筛选已渲染', filters.includes('data-set="risk"'), `${filters.length} 字符`);
  check('概览显示问题总数', stats.includes(String(data.length)));
  check('列表行数等于数据条数',
        (list.match(/<tr data-i=/g) || []).length === S.rows.length);

  /* --- 3. 契约：decided=false 必须显示出来，不许静默填默认算法 --- */
  const undecided = data.filter(f => f.remediation && f.remediation.decided === false);
  check('数据里确实有 decided=false 的条目', undecided.length > 0, `${undecided.length} 条`);

  const u = undecided.find(f => f.remediation.reason === 'usage-undetermined') || undecided[0];
  const d2api = load(['S', 'renderDetail']);
  d2api.S.sel = u;
  d2api.renderDetail();
  const d2 = htmlOf('#detail');
  check('decided=false 在详情里显示出来了', d2.includes('decided: false'));
  check('reason 有中文表述（不是裸枚举值）',
        d2.includes(api.REASON_META[u.remediation.reason].cn), u.remediation.reason);

  /* --- 4. 每一档 reason 在 UI 里都要有表述 ---
   *     断言的是**查看器的完备性**，不是数据的多样性 ——
   *     早先写成「reason 至少 3 种」，那是在断言数据，喂 scanner 产出时误报。 */
  const reasons = new Set(S.rows.map(f => api.reasonOf(f)));
  const unhandled = [...reasons].filter(r => !api.REASON_META[r]);
  check('所有 reason 取值都有 UI 表述', unhandled.length === 0, unhandled.join(','));

  /* --- 5. 未增强的条目要如实说「尚未增强」，不能装作有结论 --- */
  const ne = S.rows.find(f => api.reasonOf(f) === 'not-enriched');
  if (ne) {
    const a = load(['S', 'renderDetail']);
    a.S.sel = ne; a.renderDetail();
    const d = htmlOf('#detail');
    check('未增强条目显示「尚未增强」', d.includes('尚未增强'));
    check('未增强条目不谎称有 AI 解释', d.includes('尚未生成'));
  }

  /* --- 6. 风险配色：类名 → 颜色变量的对应 ---
   *     原先断言的是「#stats 里出现 var(--shor)」—— 那其实是在断言色值被
   *     **内联**写进了 HTML。后来配色改由 .seg.<risk> 这条规则给出，内联写法
   *     没了，断言就跟着失效。真正要守的不变量是**类名与颜色的绑定**，
   *     所以两头都验：段带对类名，且样式表里该类名确实绑到同名变量。 */
  const risksInData = new Set(S.rows.map(f => f.risk));
  const cssText = (html.match(/<style>([\s\S]*?)<\/style>/) || ['', ''])[1];
  check('概览渲染了风险段', [...risksInData].every(r => stats.includes('class="seg ' + r + '"')),
        [...risksInData].join(','));
  /* 与数据无关的那一半：凡 RISK_CN 里定义了的风险，样式表都必须有规则 ——
     否则一旦扫出该类别，那一段会渲染成**没有底色的空白**。
     当前数据集里 review 是 0 条，这条断言是唯一能发现它的东西：
     开发时确实就是漏了 .seg.review，是这条断言（而不是眼睛）抓出来的。 */
  const unbound = Object.keys(api.RISK_CN).filter(r =>
    !new RegExp('\\.seg\\.' + r + '\\s*\\{[^}]*var\\(--' + r + '\\)').test(cssText) ||
    !new RegExp('\\.rk\\.' + r + '\\s+i\\s*\\{[^}]*var\\(--' + r + '\\)').test(cssText));
  check('每种风险在样式表里都有 .seg / .rk 规则（与数据无关）',
        unbound.length === 0, unbound.join(','));

  /* --- 7. XSS 兜底 --- */
  const evil = {
    finding_id: 'x', file: '<img src=x onerror=alert(1)>', line: 1,
    algorithm: '<script>bad</script>', usage: 'unknown', risk: 'review',
    severity: 'info', evidence: [],
    remediation: { decided: false, reason: 'rule-missing', action: '<b>x</b>', source: 'rule-base' },
  };
  const x = load(['S', 'renderDetail', 'renderList']);
  x.S.sel = evil; x.S.view = [evil];
  x.renderDetail(); x.renderList();
  check('详情转义了 HTML', !htmlOf('#detail').includes('<script>bad</script>'));
  check('action 文本被转义', !htmlOf('#detail').includes('<b>x</b>'));
  check('列表转义了 HTML', !htmlOf('#list').includes('<script>bad</script>'));

  /* --- 8. evidence_refs 必须能在界面上落到具体证据卡片 --- */
  const cited = {
    finding_id: 'cited', file: 'x.java', line: 2,
    algorithm: 'RSA', usage: 'signing', risk: 'shor', severity: 'high',
    explanation: '该结论由证据支持。', evidence_refs: ['E1'],
    evidence: [{tool:'cryptoscan', kind:'pattern', lines:[2]}],
    remediation: {decided:true, reason:'decided', action:'x', source:'rule-base'},
  };
  x.S.sel = cited; x.renderDetail();
  const citedHtml = htmlOf('#detail');
  check('AI 解释显示引用编号', citedHtml.includes('引用证据') && citedHtml.includes('E1'));
  check('证据卡片显示同一编号', citedHtml.includes('class="ref">E1</span>'));

  const explained = JSON.parse(JSON.stringify(cited));
  explained.stage = 'explained';
  explained.usage_assessment = {usage:'signing',reason:'调用签名接口',
                                evidence_refs:['E1'],unknowns:['业务上下文待确认']};
  explained.remediation_steps = [{action:'核对签名调用',
    target:{file:'src/Sample.java',line:2,method:null}, evidence_refs:['E1'],
    rule_refs:['QR-SHOR-PUBLIC-KEY'], prerequisites:['确认兼容性'],
    verification:['运行集成测试'],execution_status:'not_run'}];
  x.S.sel = explained; x.renderDetail();
  const explainedHtml = htmlOf('#detail');
  check('v0.2 用途依据和整改验收步骤已渲染',
        explainedHtml.includes('调用签名接口') &&
        explainedHtml.includes('src/Sample.java:2') &&
        explainedHtml.includes('运行集成测试') &&
        explainedHtml.includes('QR-SHOR-PUBLIC-KEY'));

  const credential = JSON.parse(JSON.stringify(explained));
  credential.finding_kind = 'credential';
  credential.evidence[0].raw = {secret:'LEAK-ME-SECRET'};
  credential.evidence[0].call_context = ['LEAK-ME-CONTEXT'];
  x.S.sel = credential; x.renderDetail();
  check('凭据原文与上下文不会显示在详情',
        !htmlOf('#detail').includes('LEAK-ME-SECRET') &&
        !htmlOf('#detail').includes('LEAK-ME-CONTEXT'));

  /* 条件性备用算法必须一眼可见，不能装作已证明在运行时生效。 */
  const fallback = JSON.parse(JSON.stringify(cited));
  fallback.tags = ['conditional-default'];
  fallback.algorithm = 'AES-ECB';
  fallback.evidence.push({tool:'local-literal',kind:'pattern',lines:[9,10],
    raw:{kind:'java-properties-override',resource_file:'benchmark.properties',
         resource_line:3,property_key:'cipher'}});
  x.S.sel = fallback; x.S.view = [fallback]; x.renderDetail(); x.renderList();
  check('条件性默认值在详情与列表均明确提示',
        htmlOf('#detail').includes('尚未证明当前生效') &&
        htmlOf('#detail').includes('benchmark.properties:3') &&
        htmlOf('#list').includes('仅备用值'));
  check('条件性结论有独立中文状态',
        !!api.REASON_META['conditional-default'] &&
        api.REASON_META['conditional-default'].cn === '条件性默认值');

  /* --- 9. CrySentry taint flow 必须可见，来源缺失不能伪装成完整链 --- */
  const deep = JSON.parse(JSON.stringify(cited));
  deep.finding_id = 'deep';
  deep.evidence = [{
    tool:'crysentry', kind:'taint', lines:[42], raw:{judgeType:'Predictable Source'},
    flow:{source:null,
          sink:{file:'src/Sample.java',line:42,method:'encrypt()'},
          path:[],completeness:'source_missing'}
  }];
  x.S.sel = deep; x.renderDetail();
  const deepHtml = htmlOf('#detail');
  check('深度证据显示 source → sink',
        deepHtml.includes('来源缺失') && deepHtml.includes('src/Sample.java') &&
        deepHtml.includes('数据流完整度：source_missing'));

  /* ------------------------------ 结果 ------------------------------ */
  console.log(`查看器自检  [${TARGET}]`);
  console.log('='.repeat(60));
  if (FAILS.length) {
    console.log(`[FAIL] ${FAILS.length} 项断言未通过:`);
    FAILS.forEach(f => console.log('  - ' + f));
    process.exit(1);
  }
  console.log('[PASS] 全部断言通过');
  console.log(`  ${S.rows.length} 条 · 概览 ${stats.length} / 列表 ${list.length} / 详情 ${detail.length} 字符`);
  console.log(`  reason 取值: ${[...reasons].join(', ')}`);
  process.exit(0);
}, 300);
