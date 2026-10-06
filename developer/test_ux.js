/* Public/mocked DOM plus transient CSPRNG samples; never log generated values. */
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const webcrypto=require('node:crypto').webcrypto;
global.hashwasm=require('./vendor/argon2.umd.min.js');
const k=require('./core.js');
const html=fs.readFileSync(path.join(__dirname,'../RECOVER.html'),'utf8');
const ui=html.match(/<script id="ui-code">([\s\S]*?)<\/script>/)[1];
const vector=JSON.parse(fs.readFileSync(path.join(__dirname,'../public-vectors.json'),'utf8'));
const qrContext=vm.createContext({KDF1:k,Uint8ClampedArray});
vm.runInContext(fs.readFileSync(path.join(__dirname,'vendor/qr/qrcodegen.js'),'utf8')+fs.readFileSync(path.join(__dirname,'travel_qr.js'),'utf8')+';globalThis.travel=TravelQR;',qrContext);
const publicCode='22222-5R62B-SAJ4K-C8JSR-74S7N-S2FAH-G5';
async function fixture(random=bytes=>webcrypto.getRandomValues(bytes),fail=false){
  const nodes={},events={},windowEvents={};let requests=0;
  function node(id){return nodes[id]??= {value:'',type:'text',disabled:true,textContent:'',attrs:{},listeners:{},setAttribute(n,v){this.attrs[n]=v;},addEventListener(n,f){this.listeners[n]=f;},focus(){},getContext(){return {createImageData:(w,h)=>({data:new Uint8ClampedArray(w*h*4)}),putImageData(){}}}};}
  for(const m of html.matchAll(/<script[^>]*id="([^"]+)"[^>]*>([\s\S]*?)<\/script>/g))node(m[1]).textContent=m[2];
  node('page-style').textContent=html.match(/<style id="page-style">([\s\S]*?)<\/style>/)[1];
  for(const id of ['code','phrase','label','account','revision','length','recover','toggle-phrase','create-code','new-code','status','password','public-tests','test-report','create-qr','save-qr','print-qr','qr-card','travel-qr'])node(id);
  node('phrase').type='password';node('revision').value='1';node('length').value='24';
  const network=()=>{requests++;throw Error('Network forbidden in UX test');};
  const context=vm.createContext({document:{getElementById:node,addEventListener:(n,f)=>events[n]=f},window:{addEventListener:(n,f)=>windowEvents[n]=f},location:{protocol:fail?'https:':'file:'},crypto:{subtle:webcrypto.subtle,getRandomValues:random},KDF1:k,TravelQR:qrContext.travel,hashwasm:global.hashwasm,TextEncoder,WebAssembly,Uint8Array,fetch:network,XMLHttpRequest:network,WebSocket:network,Math:Object.assign(Object.create(Math),{random(){throw Error('Math.random forbidden');}})});
  vm.runInContext(ui,context);await events.DOMContentLoaded();
  return {nodes,context,windowEvents,get requests(){return requests;}};
}
let passed=0;
async function test(name,fn){try{await fn();passed++;console.log('PASS: '+name);}catch(e){console.error('FAIL — root cause: '+name+': '+e.message);throw e;}}
(async()=>{
  await test('CSPRNG receives exactly 16 bytes; existing encoder/decoder roundtrip; mutable buffer cleared',async()=>{
    let buffer,calls=0;const f=await fixture(bytes=>{buffer=bytes;calls++;assert.equal(bytes.length,16);for(let i=0;i<16;i++)bytes[i]=i;return bytes;});
    f.nodes['create-code'].listeners.click();assert.equal(calls,1);assert.equal(f.nodes['new-code'].textContent,publicCode);
    assert.deepEqual(k.decode(f.nodes['new-code'].textContent),Uint8Array.from({length:16},(_,i)=>i));assert(buffer.every(b=>b===0));
  });
  await test('eight transient Web Crypto generations are distinct, checksum-valid and decoder-compatible; no Math.random',async()=>{
    const f=await fixture();const codes=new Set();
    for(let i=0;i<8;i++){f.nodes['create-code'].listeners.click();const code=f.nodes['new-code'].textContent;const rs=k.decode(code);assert.equal(rs.length,16);assert(k.encode(rs)===code,'Generated code roundtrip mismatch');codes.add(code);rs.fill(0);}
    // Do not include generated values in assertion messages, logs or files.
    assert.equal(codes.size,8);codes.clear();f.nodes['new-code'].textContent='';
    assert(!ui.includes('Math.random'));
  });
  await test('Show/Hide defaults hidden and preserves exact Unicode, whitespace and case',async()=>{
    const f=await fixture(),p=f.nodes.phrase;const value=' café 密码  PUBLIC ';
    assert.equal(p.type,'password');p.value=value;
    f.nodes['toggle-phrase'].listeners.click();assert.equal(p.type,'text');assert.equal(p.value,value);assert.equal(f.nodes['toggle-phrase'].attrs['aria-pressed'],'true');
    f.nodes['toggle-phrase'].listeners.click();assert.equal(p.type,'password');assert.equal(p.value,value);
  });
  await test('Show/Hide leaves final public KDF password unchanged; clear restores hidden',async()=>{
    const f=await fixture();
    for(const show of [false,true]){
      f.nodes.phrase.value=vector.input.master_phrase;f.nodes.code.value=publicCode;f.nodes.label.value='example.com';f.nodes.account.value='test';
      if(show)f.nodes['toggle-phrase'].listeners.click();
      await f.nodes.recover.listeners.click();assert.equal(f.nodes.password.textContent,vector.expected.password);assert.equal(f.nodes.phrase.value,'');assert.equal(f.nodes.phrase.type,'password');
    }
  });
  await test('Create NEW is isolated from existing recovery fields and password',async()=>{
    const f=await fixture(bytes=>{bytes.fill(0);return bytes;});
    for(const id of ['code','phrase','label','account','revision','length'])f.nodes[id].value='PUBLIC '+id;
    f.nodes.password.textContent='PUBLIC OUTPUT';const before=Object.fromEntries(['code','phrase','label','account','revision','length'].map(id=>[id,f.nodes[id].value]));
    f.nodes['create-code'].listeners.click();for(const [id,value]of Object.entries(before))assert.equal(f.nodes[id].value,value);assert.equal(f.nodes.password.textContent,'PUBLIC OUTPUT');
  });
  await test('CSPRNG failure STOPs, clears output and disables both new controls; no weak fallback',async()=>{
    const f=await fixture(()=>{throw Error('PUBLIC simulated CSPRNG unavailable');});
    f.nodes['create-code'].listeners.click();assert.match(f.nodes.status.textContent,/STOP/);assert.equal(f.nodes['new-code'].textContent,'');assert(f.nodes['create-code'].disabled);assert(f.nodes['toggle-phrase'].disabled);
  });
  await test('failed startup keeps Create NEW and Show/Hide disabled',async()=>{
    const f=await fixture(undefined,true);assert(f.nodes['create-code'].disabled);assert(f.nodes['toggle-phrase'].disabled);assert.equal(f.nodes.phrase.type,'password');
  });
  await test('new actions and public recovery invoke zero network APIs',async()=>{
    const f=await fixture(bytes=>{bytes.fill(0);return bytes;});
    f.nodes['create-code'].listeners.click();f.nodes.phrase.value=vector.input.master_phrase;f.nodes.code.value=publicCode;f.nodes.label.value='example.com';f.nodes.account.value='test';
    f.nodes['toggle-phrase'].listeners.click();f.nodes['toggle-phrase'].listeners.click();await f.nodes.recover.listeners.click();assert.equal(f.requests,0);
  });
  await test('Travel QR uses same generated code without more randomness; stale QR cleared on replacement',async()=>{
    let calls=0;const f=await fixture(bytes=>{calls++;bytes.fill(calls);return bytes;});
    assert(f.nodes['create-qr'].disabled);f.nodes['create-code'].listeners.click();assert(!f.nodes['create-qr'].disabled);
    f.nodes['create-qr'].listeners.click();assert.equal(calls,1);assert(!f.nodes['qr-card'].hidden);assert(!f.nodes['save-qr'].disabled);
    f.nodes['create-code'].listeners.click();assert.equal(calls,2);assert(f.nodes['qr-card'].hidden);assert(f.nodes['save-qr'].disabled);
  });
  await test('QR disabled after STOP and while KDF is busy; zero network calls',async()=>{
    const f=await fixture(bytes=>{bytes.fill(0);return bytes;});f.nodes['create-code'].listeners.click();f.nodes['create-qr'].listeners.click();
    f.nodes.phrase.value=vector.input.master_phrase;f.nodes.code.value=publicCode;f.nodes.label.value='example.com';f.nodes.account.value='test';
    const pending=f.nodes.recover.listeners.click();assert(f.nodes['create-qr'].disabled);assert(f.nodes['save-qr'].disabled);await pending;
    assert(!f.nodes['save-qr'].disabled);f.windowEvents.error({message:'PUBLIC failure'});assert(f.nodes['qr-card'].hidden);assert(f.nodes['create-qr'].disabled);assert.equal(f.requests,0);
  });
  await test('raw LF/CR/CRLF paste at all positions blocked before KDF, hidden or shown',async()=>{
    const f=await fixture();f.nodes.code.value=publicCode;f.nodes.label.value='example.com';f.nodes.account.value='test';
    for(const visible of [false,true])for(const sep of ['\n','\r','\r\n'])for(const raw of [sep+'PUBLIC','PUBLIC'+sep,'PUBLIC'+sep+'phrase']){
      if((f.nodes.phrase.type==='text')!==visible)f.nodes['toggle-phrase'].listeners.click();
      let prevented=false;const before=k.argonCalls;f.nodes.phrase.value='PUBLIC';
      f.nodes.phrase.listeners.paste({clipboardData:{getData:type=>{assert.equal(type,'text/plain');return raw;}},preventDefault(){prevented=true;}});
      assert(prevented);assert.equal(f.nodes.phrase.value,'');assert(f.nodes.recover.disabled);assert.match(f.nodes.status.textContent,/STOP/);
      await f.nodes.recover.listeners.click();assert.equal(k.argonCalls,before);assert.equal(f.nodes.password.textContent,'');
      // A sanitized completion must not silently unlock the blocked edit.
      f.nodes.phrase.value='PUBLICphrase';f.nodes.phrase.listeners.input({preventDefault(){}});assert.equal(f.nodes.phrase.value,'');assert(f.nodes.recover.disabled);
      f.nodes['toggle-phrase'].listeners.click();assert(f.nodes.recover.disabled);
      f.nodes.phrase.listeners.beforeinput({data:'P',inputType:'insertText',preventDefault(){throw Error('Valid typing blocked');}});
      f.nodes.phrase.value='PUBLIC';f.nodes.phrase.listeners.input({preventDefault(){}});assert(!f.nodes.recover.disabled);
    }
  });
  await test('drop/beforeinput/direct value newline rejected; unavailable raw clipboard fails closed',async()=>{
    const f=await fixture();
    const events=[['drop',{dataTransfer:{getData:()=> 'PUBLIC\r\nphrase'}}],['beforeinput',{data:'PUBLIC\nphrase',inputType:'insertText'}],['beforeinput',{data:null,inputType:'insertLineBreak'}],['paste',{clipboardData:null}]];
    for(const [name,details]of events){let prevented=false;f.nodes.phrase.listeners[name]({...details,preventDefault(){prevented=true;}});assert(prevented);assert(f.nodes.recover.disabled);assert.match(f.nodes.status.textContent,/STOP/);}
    f.nodes.phrase.listeners.beforeinput({data:'PUBLIC',inputType:'insertText',preventDefault(){}});f.nodes.phrase.value='PUBLIC\nphrase';
    f.nodes.phrase.listeners.input({preventDefault(){}});assert.equal(f.nodes.phrase.value,'');assert(f.nodes.recover.disabled);
  });
  await test('ordinary single-line paste remains allowed; Show/Hide preserves public output',async()=>{
    const f=await fixture();const value=vector.input.master_phrase;
    f.nodes.phrase.listeners.paste({clipboardData:{getData:()=>value},preventDefault(){throw Error('Ordinary paste blocked');}});
    f.nodes.phrase.value=value;f.nodes.phrase.listeners.input({preventDefault(){}});
    f.nodes['toggle-phrase'].listeners.click();assert.equal(f.nodes.phrase.value,value);f.nodes['toggle-phrase'].listeners.click();assert.equal(f.nodes.phrase.value,value);
    f.nodes.code.value=publicCode;f.nodes.label.value='example.com';f.nodes.account.value='test';await f.nodes.recover.listeners.click();assert.equal(f.nodes.password.textContent,vector.expected.password);
  });
  console.log(`PASS: ${passed}/13 UX tests; no generated secret values logged or persisted`);
})().catch(()=>process.exit(1));
