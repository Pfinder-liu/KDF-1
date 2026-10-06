/* Developer public conformance tests. No browser automation or network. */
'use strict';
const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');
if(!global.crypto)global.crypto=require('node:crypto').webcrypto;
global.hashwasm=require('./vendor/argon2.umd.min.js');
const k=require('./core.js');
const root=path.resolve(__dirname,'..');
const read=n=>JSON.parse(fs.readFileSync(path.join(root,n),'utf8'));
let passed=0;
async function test(name,fn){try{await fn();passed++;console.log('PASS: '+name);}catch(e){console.error('FAIL — root cause: '+name+': '+e.stack);throw e;}}
(async()=>{
  const v=read('public-vectors.json'),humans=read('human-vectors.json'),cases=read('developer/public-cases.json');
  await test('original master_key/site_key/password',()=>k.verifyVector(v));
  await test('Human vectors + self-test',()=>k.selfTest(v,humans));
  await test('nine Python cross-implementation cases and 3310 input rejections',async()=>{
    const report=await k.publicTests(cases,humans);assert.match(report,/3310/);console.log(report);
  });
  await test('public Human Code produces same three outputs',async()=>assert.deepEqual(await k.deriveCode(v.input.master_phrase,humans[0].code,'example.com','test',1,24),v.expected));
  await test('capacity/encoding 256 deterministic public roundtrips',()=>{
    assert(24n**30n>2n**128n);
    for(let i=0;i<256;i++){const rs=Uint8Array.from({length:16},(_,j)=>(i+j)%256);assert.deepEqual(k.decode(k.encode(rs)),rs);}
  });
  await test('invalid Human Code before Argon2',async()=>{
    const before=k.argonCalls;
    await assert.rejects(k.deriveCode('PUBLIC TEST',humans[0].code.slice(0,-1)+'2','example.com'));
    assert.equal(k.argonCalls,before);
  });
  await test('invalid metadata before Argon2',async()=>{
    const before=k.argonCalls,secret=new Uint8Array(16);
    for(const args of [['a|b','',1,24],['a','@',1,24],['a','',0,24],['a','',1,7],['a','',true,24],['a','',1,24.1]])
      await assert.rejects(k.derive('PUBLIC TEST',secret,...args));
    assert.equal(k.argonCalls,before);
  });
  await test('unpaired Unicode scalar rejection',()=>{
    for(const s of ['\ud800','\udc00','\ud800x','x\udc00'])assert.throws(()=>k.textScalar(s));
    assert.equal(k.textScalar('cafe\u0301'),'café');assert.equal(k.textScalar('🙂'),'🙂');
  });
  await test('NFC preserves case/spaces/no NFKC',()=>{
    assert.equal(k.textScalar(' Ａ '),' Ａ ');assert.notEqual(k.textScalar('Ａ'),k.textScalar('A'));
    assert.notEqual(k.textScalar(' public'),k.textScalar('public'));assert.notEqual(k.textScalar('PUBLIC'),k.textScalar('public'));
  });
  await test('labels opaque/account case preserved',()=>{
    assert.equal(k.label(' \tAPPLE-ROOT\r\n'),'apple-root');assert.equal(k.label(' Personal ',true),'Personal');
    assert.notEqual(k.label('example.com'),k.label('www.example.com'));assert.throws(()=>k.label('K'));
  });
  await test('numbers grammar and bounds',()=>{
    assert.equal(k.parseNumber('001',1,1,4294967295,'Revision'),1);assert.equal(k.parseNumber(' \t',24,8,1024,'Length'),24);
    for(const s of ['+1','١','１','1_0','-1','1.0','4294967296'])assert.throws(()=>k.parseNumber(s,1,1,4294967295,'Revision'));
  });
  await test('fixed expected mismatch names failing field',async()=>{
    for(const field of Object.keys(v.expected)){const bad=structuredClone(v);bad.expected[field]='wrong PUBLIC';await assert.rejects(k.verifyVector(bad),new RegExp(field));}
  });
  await test('empty/wrong-scheme public vectors fail',async()=>{
    await assert.rejects(k.selfTest(v,[]),/Human vectors/);
    const bad=structuredClone(v);bad.scheme='KDF-1-v2';await assert.rejects(k.verifyVector(bad),/scheme/);
  });
  console.log(`PASS: ${passed}/13 Web adapter tests`);
})().catch(()=>process.exit(1));
