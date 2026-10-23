// Copyright Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

// Exercise the actual browser walker, including failure evidence and exit status.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const {spawn} = require('node:child_process');
const stage = fs.mkdtempSync(path.join(os.tmpdir(),'cmtc-walk-smoke-'));
const html = '<html><head><title>CMTC walker fixture</title></head><body><section data-testid="data-testid Panel header Live"><h2>Live</h2><span>4</span></section><section data-testid="data-testid Panel header Future"><h2>Future</h2><span>No data</span></section></body></html>';
const server = http.createServer((req,res)=>{res.writeHead(200,{'Content-Type':'text/html'});res.end(html);});
async function run(spec,name,format='json',extraEnv={}){
  const out=path.join(stage,name);fs.mkdirSync(out);
  const input=path.join(out,`spec.${format}`);
  fs.writeFileSync(input,format==='yaml'?require('js-yaml').dump(spec):JSON.stringify(spec));
  return new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,[path.join(__dirname,'walk.cjs'),input],{env:{...process.env,...extraEnv,S:out}});
    let log='';child.stdout.on('data',x=>log+=x);child.stderr.on('data',x=>log+=x);
    child.on('error',reject);child.on('close',code=>resolve({code,log,out}));
  });
}
(async()=>{
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const page={name:'fixture',url:`http://127.0.0.1:${server.address().port}`,evidence:'panels',settle:false,before:1,expect:{panelsMin:2,noDataAllowed:['Future']}};
  const success=await run({pages:[page]},'allowed-future');
  assert.equal(success.code,0,success.log);assert.match(success.log,/expectations met/);
  assert.equal(fs.readFileSync(path.join(success.out,'fixture.png')).subarray(1,4).toString(),'PNG');
  const yaml=await run({pages:[{...page,url:'${WALK_FIXTURE_URL}'}]},'yaml-variables','yaml',{CMTC_WALK_ENV_JSON:JSON.stringify({WALK_FIXTURE_URL:page.url})});
  assert.equal(yaml.code,0,yaml.log);assert.match(yaml.log,/expectations met/);
  const blocked=await run({pages:[{...page,blockedSignalsOnNoData:true}]},'blocked-feature');
  assert.equal(blocked.code,0,blocked.log);assert.match(blocked.log,/feature evidence BLOCKED.*Future/);
  assert.equal(JSON.parse(fs.readFileSync(path.join(blocked.out,'walk-results.json'),'utf8')).pages[0].featureEvidence,'blocked');
  const empty=await run({pages:[{...page,expect:{panelsMin:2,noDataAllowed:[]}}]},'unexpected-empty');
  assert.equal(empty.code,2,empty.log);assert.match(empty.log,/FAILED.*Future/);
  assert.ok(fs.statSync(path.join(empty.out,'fixture.png')).size>0,'Evidence must survive failed expectations');
  const missing=await run({pages:[{...page,evidence:'text',expect:{text:['absent-peer']}}]},'missing-text');
  assert.equal(missing.code,2,missing.log);assert.match(missing.log,/FAILED.*absent-peer/);
  console.log('Browser walk smoke passed: YAML/JSON specs, JSON variables, allowed future panel, unexpected No data denial, missing text denial, retained PNGs');
})().catch(e=>{console.error(e);process.exitCode=1;}).finally(()=>{server.close();fs.rmSync(stage,{recursive:true,force:true});});
