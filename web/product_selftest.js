/* Product UI checks with HTTP-shaped responses, no model or browser dependency. */
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
const code = html.match(/<script>\r?\n([\s\S]*?)\r?\n<\/script>/)[1].replace(/\nstart\(\);\s*$/, '\n');
const els = new Map();
function el(key){
  if(!els.has(key)) els.set(key,{innerHTML:'',textContent:'',style:{},dataset:{},
    classList:{add(){},remove(){}},querySelectorAll(){return [];},scrollIntoView(){}});
  return els.get(key);
}
const row={finding_id:'f1',algorithm:'RSA',severity:'high',risk:'shor',usage:'signing',
  evidence:[{tool:'manual',kind:'manual',lines:[1]}],remediation:{decided:false,reason:'not-enriched'}};
const overview={summary:'项目摘要',basis:'仅按规则初排',gaps:['Java 未启用'],actions:[{
  finding_id:'f1',title:'<script>bad</script>',severity:'高',action:'先检查签名接口',
  why:'风险待核实',source:'规则建议',status:'待执行',file:'a.java',line:1,evidence_refs:['E1']}]};
const requests=[];
const fetch=async(url, options)=>{
  requests.push([url,options]);
  let data;
  if(url.endsWith('/summary')) data=overview;
  else if(url.endsWith('/result')) data=[row];
  else data={state:'completed',message:'扫描完成；AI 未完成',findings_count:1,
    pipeline:{stages:[{name:'scan',status:'completed'},{name:'ai',status:'failed'}]},
    ai_feedback:{retry_available:true,message:'连接失败；扫描结果已保留'}};
  return {ok:true,status:200,json:async()=>data};
};
const api=new Function('document','window','fetch','setTimeout',code+
  '\nreturn {S,boot,loadOverview,pollTask};')(
  {querySelector:el,addEventListener(){}},{},fetch,()=>{});
(async()=>{
  api.boot([row],'本地任务 web-test');
  await api.loadOverview('web-test','本地任务 web-test');
  assert(el('#projectOverview').innerHTML.includes('先检查签名接口'));
  assert(el('#projectOverview').innerHTML.includes('E1'));
  assert(!el('#projectOverview').innerHTML.includes('<script>bad</script>'));
  assert(el('#projectOverview').innerHTML.includes('&lt;script&gt;'));
  await api.pollTask('web-test');
  assert(el('#scanMessage').textContent.includes('AI 未完成'));
  assert(el('#scanCount').textContent.includes('连接失败'));
  assert.strictEqual(el('#retryAi').hidden,false);
  assert(html.includes('仅重试 AI（保留扫描结果）'));
  assert(html.includes('系统不会预测 Q-Day'));
  console.log('PASS: project overview, evidence links, XSS escaping, partial-AI feedback');
})().catch(e=>{console.error(e);process.exitCode=1;});
