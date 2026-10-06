/* A1/A2: fixed repertoire + official Unicode13 data + public cross-language vectors. */
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
global.hashwasm=require('./vendor/argon2.umd.min.js');const k=require('./core.js');
const rows=JSON.parse(fs.readFileSync(path.join(__dirname,'../master-phrase-vectors.json'),'utf8'));
let passed=0;async function test(name,fn){try{await fn();passed++;console.log('PASS: '+name);}catch(e){console.error('FAIL — root cause: '+name+': '+e.stack);throw e;}}
(async()=>{
await test('valid fixed vectors: exact NFC/UTF8; invalid vectors rejected',()=>{
 k.phraseSelfTest(rows);for(const row of rows){if(row.valid)assert.equal(Buffer.from(k.textScalar(row.input)).toString('hex'),row.utf8_hex);else assert.throws(()=>k.textScalar(row.input));}
});
await test('audit Unicode13/17 divergence now rejected before Argon2',async()=>{
 const before=k.argonCalls;await assert.rejects(k.derive('PUBLIC\u0897\u0323',new Uint8Array(16),'example.com'));assert.equal(k.argonCalls,before);
});
await test('LF/CR/CRLF at beginning/middle/end rejected before Argon2',async()=>{
 const before=k.argonCalls;for(const sep of ['\n','\r','\r\n'])for(const p of [sep+'PUBLIC','PUBLIC'+sep,'PUBLIC'+sep+'phrase'])await assert.rejects(k.derive(p,new Uint8Array(16),'example.com'),/CR \/ LF/);assert.equal(k.argonCalls,before);
});
await test('all Unicode scalar membership agrees with fixed authoritative repertoire',()=>{
 const ranges=JSON.parse(fs.readFileSync(path.join(__dirname,'../master-phrase-repertoire.json'),'utf8')).ranges;
 let index=0,accepted=0;
 for(let cp=0;cp<=0x10ffff;cp++){
  while(index<ranges.length&&cp>ranges[index][1])index++;
  const expected=index<ranges.length&&cp>=ranges[index][0];let actual=true;
  try{k.textScalar(String.fromCodePoint(cp));}catch(_){actual=false;}
  assert.equal(actual,expected,'Repertoire mismatch U+'+cp.toString(16));if(actual)accepted++;
 }
 assert.equal(accepted,281390);
});
await test('official Unicode13 NFC suite: all 18853 rows, five invariants each',()=>{
 let count=0;for(const line of fs.readFileSync(path.join(__dirname,'unicode13/NormalizationTest.txt'),'utf8').split('\n')){
 const text=line.split('#')[0].trim();if(!text||text.startsWith('@'))continue;
 const [a,b,c,d,e]=text.split(';').slice(0,5).map(col=>String.fromCodePoint(...col.trim().split(/\s+/).map(cp=>parseInt(cp,16))));
 for(const [source,target]of [[a,b],[b,b],[c,b],[d,d],[e,d]])assert.equal(k.textScalar(source),target);count++;
 }assert.equal(count,18853);
});
await test('all valid new phrase vectors match Python master/site/password outputs',async()=>{
 for(const row of rows)if(row.valid)assert.deepEqual(await k.derive(row.input,k.unhex('000102030405060708090a0b0c0d0e0f'),'example.com','test',1,24),row.expected);
});
await test('fixed input bytes self-test fails on damaged expected/invalid acceptance',()=>{
 const bad=structuredClone(rows);bad[0].utf8_hex='00';assert.throws(()=>k.phraseSelfTest(bad),/self-test failed/);
 assert.throws(()=>k.phraseSelfTest([{valid:false,input:'PUBLIC'}]),/Invalid Master Phrase accepted/);
});
console.log(`PASS: ${passed}/7 A1/A2 contract groups; public data only`);
})().catch(()=>process.exit(1));
