// Rebuild the anonymous semifinal presentation. Requires pptxgenjs at build time.
// The source is kept so the candidate can be updated without binary surgery.
const pptxgen = require('pptxgenjs');
const path = require('path');

const p = new pptxgen();
p.layout = 'LAYOUT_WIDE';
p.author = '';
p.company = '';
p.subject = '密码安全审计与抗量子迁移系统';
p.title = 'AI-CryptoGuard 复赛候选演示稿';
p.lang = 'zh-CN';
p.theme = { headFontFace: 'Microsoft YaHei', bodyFontFace: 'Microsoft YaHei', lang: 'zh-CN' };

const C = { navy:'0C1727', navy2:'172B3E', teal:'008D90', bright:'22B9B7',
  amber:'D99A32', paper:'F5F7FA', white:'FFFFFF', ink:'162333', muted:'57697D',
  line:'DCE3EA', pale:'E5F5F4', coral:'B84E43', green:'287B58' };
const S = p.ShapeType;
const W = 13.333, H = 7.5;

function rect(s,x,y,w,h,fill=C.white,line='none',radius=0){
  s.addShape(radius?S.roundRect:S.rect,{x,y,w,h,rectRadius:radius,
    line:line==='none'?{color:fill,transparency:100}:{color:line,width:0.8},
    fill:{color:fill},radius});
}
function txt(s,t,x,y,w,h,size=15,color=C.ink,bold=false,opt={}){
  s.addText(t,{x,y,w,h,fontFace:'Microsoft YaHei',fontSize:size,color,bold,
    margin:0,breakLine:false,valign:'mid',fit:'shrink',...opt});
}
function base(title,n,eyebrow='SYSTEM / EVIDENCE / ACTION'){
  const s=p.addSlide();s.background={color:C.paper};
  rect(s,0,0,W,.13,C.navy);
  txt(s,eyebrow,.52,.33,9,.19,8,C.teal,true,{charSpacing:1.1});
  txt(s,title,.52,.65,12,.48,23,C.ink,true);
  rect(s,.52,1.24,12.27,.018,C.line);
  txt(s,'AI-CryptoGuard · 全国密码技术竞赛复赛候选演示',.52,7.12,9,.17,8,C.muted);
  txt(s,String(n).padStart(2,'0'),12.15,7.06,.64,.24,10,C.teal,true,{align:'right'});
  return s;
}
function card(s,x,y,w,h,title,lines,accent=C.teal){
  rect(s,x,y,w,h,C.white,C.line,.12);rect(s,x,y,.055,h,accent);
  txt(s,title,x+.24,y+.21,w-.48,.29,14,C.ink,true);
  let yy=y+.66;
  for(const line of lines){txt(s,line,x+.24,yy,w-.48,.37,12,C.muted,false,{breakLine:false});yy+=.46;}
}
function pill(s,label,x,y,w,color=C.teal){
  rect(s,x,y,w,.36,color);txt(s,label,x+.08,y+.055,w-.16,.24,10,C.white,true,{align:'center'});
}

// 1 — Cover.
{
 const s=p.addSlide();s.background={color:C.navy};
 rect(s,.0,.0,.16,H,C.bright);rect(s,9.86,0,3.48,H,C.navy2);
 for(let i=0;i<11;i++)rect(s,10.04,.7+i*.52,2.88,.012,i%3===0?C.bright:'416279');
 txt(s,'2026 · 全国密码技术竞赛复赛',.62,.64,8,.30,12,C.bright,true,{charSpacing:1});
 txt(s,'AI-CryptoGuard',.62,1.50,9.1,.77,38,C.white,true);
 txt(s,'从多源证据到可解释的密码风险\n与抗量子迁移建议',.64,2.53,8.62,1.34,26,C.white,true);
 rect(s,.64,4.54,8.53,.015,'486477');
 txt(s,'源码项目  →  风险与证据  →  用途判断  →  整改/迁移  →  中文报告',.64,4.86,8.65,.45,15,C.bright,true);
 txt(s,'原创：证据融合 · 本地风险规则 · AI 约束 · 凭据检测 · 评测与交互',.64,6.18,9.0,.36,12,C.white);
 txt(s,'第三方引擎：CryptoScan / cbom-scan / CrySentry-Tai-e',.64,6.58,9.0,.28,11,'9DAFBF');
 txt(s,'01',11.13,6.43,1.33,.60,26,C.bright,true,{align:'right'});
}

// 2 — Four-stage product experience.
{
 const s=base('用户看见的是一个完整流程',2);
 const steps=[['01','上传项目','本地上传源码；Java 可另给编译产物'],
 ['02','查看扫描','快速扫描；可选 Java 深度证据'],
 ['03','解释风险','先量子评估；显式启用 AI 解读'],
 ['04','形成报告','证据引用、未知项、中文界面与离线 HTML']];
 steps.forEach((v,i)=>{const x=.52+i*3.12;
   rect(s,x,1.70,2.92,3.63,C.white,C.line,.10);
   txt(s,v[0],x+.22,1.99,2.48,.55,27,C.teal,true);
   rect(s,x+.22,2.66,2.48,.018,C.line);
   txt(s,v[1],x+.22,2.91,2.48,.43,18,C.ink,true);
   txt(s,v[2],x+.22,3.55,2.48,1.12,14,C.muted,false,{valign:'top'});
 });
 rect(s,.52,5.72,12.27,.81,C.pale);
 txt(s,'失败也有真实状态：缺工具、超时、模型不可达时保留已经完成阶段的结果。',.79,5.91,11.75,.40,14,C.ink,true);
}

// 3 — Fusion value.
{
 const s=base('为什么需要统一证据层？',3);
 card(s,.52,1.60,3.78,4.55,'输入各说各话',[
   '风险词义不同：经典已破 ≠ 量子可破','严重度和路径格式不同','同一处调用可能重复上报'],C.coral);
 card(s,4.77,1.60,3.78,4.55,'我们的处理',[
   '归一化算法与文件位置','按文件 / 算法 / 用途收口','E1、E2… 保留原始证据位置'],C.teal);
 card(s,9.02,1.60,3.78,4.55,'输出有边界',[
   '证据不足时写 unknown','不完整数据流标 partial','不把“未报出”说成“安全”'],C.amber);
}

// 4 — Attribution.
{
 const s=base('能力归属：把第三方和原创说清楚',4);
 card(s,.52,1.60,5.76,4.50,'第三方扫描引擎',[
   'CryptoScan：源码模式发现','cbom-scan：密码资产清点','CrySentry / Tai-e：Java 字节码分析'],C.muted);
 card(s,6.55,1.60,6.24,4.50,'本项目原创实现',[
   '统一入口、证据归一与融合','本地量子评估与凭据检测','有引用的 AI 解读、中文报告与评测'],C.teal);
 txt(s,'CrySentry 在仓库外进程调用；LGPL-3.0 工具本体不作为团队源码提交。',.58,6.37,12.0,.34,11,C.muted);
}

// 5 — Java evidence.
{
 const s=base('Java 深度证据：它真正增加了什么',5);
 pill(s,'公开故意不安全样例',.53,1.57,2.54);
 txt(s,'Random.nextBytes',.78,2.15,3.42,.55,21,C.ink,true);
 txt(s,'生成密钥字节',.78,2.74,3.42,.37,13,C.muted);
 txt(s,'→',4.29,2.39,.63,.38,22,C.teal,true,{align:'center'});
 txt(s,'SecretKeySpec',5.09,2.15,3.42,.55,21,C.ink,true);
 txt(s,'构造密钥',5.09,2.74,3.42,.37,13,C.muted);
 rect(s,.54,3.57,12.24,2.16,C.white,C.line,.10);
 txt(s,'真实运行 CrySentry；来源与汇点可定位',.83,3.84,11.63,.40,17,C.ink,true);
 txt(s,'taint = partial：只有首尾证据，没有中间传播路径。独立弱随机密钥 Finding 可显示；固定 25 例对照 P/R 并未提高。',.83,4.45,11.48,.83,14,C.muted,false,{valign:'top'});
 txt(s,'演示的是证据强度与集成能力，不把新增证据冒充检测率提升。',.59,6.13,12.0,.40,13,C.teal,true);
}

// 6 — AI constrained by rules.
{
 const s=base('AI 解读不替规则库决定密码学事实',6);
 card(s,.52,1.60,5.86,4.58,'先由本地规则评估',[
   '经典已破 / Shor / Grover 分开','签名 → ML-DSA 或 SLH-DSA','加密与协商 → ML-KEM','用途不确定时不给固定路线'],C.teal);
 card(s,6.70,1.60,6.09,4.58,'AI 解释有证据支持的内容',[
   '判断用途并引用 E1 / E2…','指出未知项和待核查事项','生成可执行整改步骤','建议仍由本地规则复核'],C.amber);
 txt(s,'X/Y/Z 时间窗口来自用户假设；系统不预测“量子危机”日期。',.58,6.41,12.0,.30,11,C.muted);
}

// 7 — Metrics with non-comparable units stated explicitly.
{
 const s=base('评测：每个数字都带自己的口径',7);
 const rows=[
   ['开发语料','619 / 97 / 63','86.5% / 90.8%','非独立留出'],
   ['凭据专项','165 / 73 / 57','69.3% / 74.3%','同批开发语料'],
   ['OWASP Java 首次','219 / 27 / 40','89.0% / 84.6%','文件级独立诊断'],
   ['Java 25 例','14 / 4 / 2','77.8% / 87.5%','深扫未提高 P/R']];
 const xs=[.58,3.65,6.70,9.71],ws=[2.96,2.94,2.91,2.79];
 ['实验','TP / FP / FN','Precision / Recall','边界'].forEach((v,i)=>txt(s,v,xs[i],1.61,ws[i],.35,11,C.muted,true));
 rows.forEach((r,j)=>{const y=2.08+j*.92;rect(s,.52,y,12.27,.78,j%2?C.white:'EAF0F5');
   r.forEach((v,i)=>txt(s,v,xs[i],y+.17,ws[i],.39,i===0?14:12,i===2?C.teal:C.ink,i<3));});
 rect(s,.52,6.15,12.27,.60,C.pale);
 txt(s,'单位不同不能合并。OWASP 同集回归 90.6% / 100% 不是第二次独立成绩。',.77,6.28,11.75,.33,12,C.ink,true);
}

// 8 — Privacy and repair.
{
 const s=base('隐私、失败与修复边界',8);
 card(s,.52,1.62,3.78,4.57,'默认本地',[
   '未启用 AI 就不出网','凭据只留指纹 / 遮蔽值','原始扫描与映射不入库'],C.teal);
 card(s,4.77,1.62,3.78,4.57,'云端最小化',[
   '白名单字段与敏感值脱敏','不发送绝对路径、token、raw','敏感项目用调用形状模式'],C.amber);
 card(s,9.02,1.62,3.78,4.57,'候选修复',[
   '只改临时副本','正式扫描器前后复扫','兼容性需项目测试与人工复核'],C.coral);
}

// 9 — Demo flow.
{
 const s=base('现场演示：三段稳定故事',9);
 card(s,.52,1.57,3.78,4.52,'A · 密码与凭据',[
   '上传自建公开样例','展示 Finding 与 E 引用','候选修复只在临时副本'],C.teal);
 card(s,4.77,1.57,3.78,4.52,'B · Java 深度',[
   '已编译 JAR + CrySentry','展示来源、汇点和 partial','明确引擎是第三方'],C.amber);
 card(s,9.02,1.57,3.78,4.52,'C · 抗量子迁移',[
   'RSA 签名与 ECDH 协商','签名 / KEM 路线分别说明','用途未知不给固定路线'],C.green);
 txt(s,'网络不稳时使用本地评估和离线 HTML；AI 阶段若 skipped，现场如实说明。',.58,6.35,12.0,.37,12,C.muted);
}

// 10 — Honest remaining gates.
{
 const s=base('距离正式提交，还要补齐这些证明',10);
 const tasks=[
   '① 新的同口径独立留出集；八类凭据分别核验',
   '② 30 条 AI 结果的独立人工语义盲审',
   '③ 第三方项目 Repair→Verify 正向兼容性验证',
   '④ 异机部署、许可证与最终打包清单、两次全程彩排'];
 tasks.forEach((t,i)=>{const y=1.57+i*1.03;rect(s,.53,y,12.25,.83,C.white,C.line,.08);
   rect(s,.53,y,.07,.83,i<2?C.coral:C.amber);
   txt(s,t,.84,y+.17,11.55,.48,15,C.ink,true);});
 rect(s,.53,6.05,12.25,.68,C.navy);
 txt(s,'已验证的展示证据；未验证的如实写待完成。候选稿不能替代最终验收。',.82,6.19,11.68,.38,13,C.white,true);
}

const output=path.resolve(process.argv[2] || path.join(__dirname,'AI-CryptoGuard-答辩候选版.pptx'));
p.writeFile({fileName:output});
