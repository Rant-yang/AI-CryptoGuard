/* An early upload failure must survive later parallel successes. */
const fs=require('fs'),path=require('path'),assert=require('assert');
const html=fs.readFileSync(path.join(__dirname,'index.html'),'utf8');
const code=html.match(/<script>\r?\n([\s\S]*?)\r?\n<\/script>/)[1].replace(/\nstart\(\);\s*$/,'\n');
const elements=new Map();
function el(s){if(!elements.has(s))elements.set(s,{value:'',files:[],style:{},textContent:'',
  hidden:false,classList:{add(){},remove(){}},querySelectorAll(){return[];}});return elements.get(s);}
el('#qtHndl').value='unknown';el('#scanMode').value='fast';el('#aiContext').value='shape';
let creates=0,starts=0;
const wait=ms=>new Promise(r=>setTimeout(r,ms));
async function fetch(url){
 if(url==='/api/tasks'){creates++;await wait(5);return {ok:true,status:201,json:async()=>({task_id:'web-test'})};}
 if(url.includes('/files?')){
   const fail=url.includes('a.java');await wait(fail?5:40);
   return {ok:!fail,status:fail?400:201,json:async()=>fail?{error:'模拟上传失败'}:{ok:true}};
 }
 if(url.endsWith('/start'))starts++;
 throw Error('Unexpected request '+url);
}
const api=new Function('document','window','fetch',code+'\nreturn {beginProject,busy:()=>scanBusy};')(
 {querySelector:el,addEventListener(){}},{},fetch);
(async()=>{
 const files=['a.java','b.java','c.java'].map(name=>({path:'demo/'+name,file:{name,size:10}}));
 const first=api.beginProject(files);
 await api.beginProject(files); // re-entrant picker/drop event must be ignored
 await first;await wait(60);
 assert.equal(creates,1);assert.equal(starts,0);assert.equal(api.busy(),false);
 assert.equal(el('#scanMessage').textContent,'无法开始扫描');
 assert(el('#scanCount').textContent.includes('项目上传未完成（2/3）'));
 assert(el('#scanCount').textContent.includes('模拟上传失败'));
 console.log('PASS: parallel upload failure persists, completed-file count, duplicate entry guard');
})().catch(e=>{console.error(e);process.exitCode=1;});
