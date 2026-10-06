/* Independent developer-only decoder. Public data; no scanner in RECOVER.html. */
'use strict';
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
if(!global.crypto)global.crypto=require('node:crypto').webcrypto;
global.hashwasm=require('./vendor/argon2.umd.min.js');const k=require('./core.js');
const jsQR=require('./vendor/qr/jsQR.js');
let network=0;const forbidden=()=>{network++;throw Error('Network forbidden');};
const context=vm.createContext({KDF1:k,Uint8ClampedArray,fetch:forbidden,XMLHttpRequest:forbidden,WebSocket:forbidden,Math:Object.assign(Object.create(Math),{random(){throw Error('Randomness forbidden in QR');}})});
for(const file of ['vendor/qr/qrcodegen.js','travel_qr.js'])vm.runInContext(fs.readFileSync(path.join(__dirname,file),'utf8'),context);
const travel=vm.runInContext('TravelQR',context),high=vm.runInContext('qrcodegen.QrCode.Ecc.HIGH',context);
const code='22222-5R62B-SAJ4K-C8JSR-74S7N-S2FAH-G5';
function decode(c){const q=travel.make(c),im=travel.pixels(q),d=jsQR(im.data,im.width,im.height);assert(d,'Independent decoder did not decode');return {q,im,d};}
let passed=0;async function test(name,f){try{await f();passed++;console.log('PASS: '+name);}catch(e){console.error('FAIL — root cause: '+name+': '+e.stack);throw e;}}
(async()=>{
await test('independent QR roundtrip: exact canonical code, no prefix/URL/metadata',()=>{
 const {d}=decode(code);assert.equal(d.data,code);assert.equal(d.data.length,38);assert(!/[:/@]|recovery|password|example/i.test(d.data));
});
await test('public Human vectors and 32 fixed public secrets independently decode to same 16 bytes',()=>{
 const humans=JSON.parse(fs.readFileSync(path.join(__dirname,'../human-vectors.json'),'utf8'));
 const codes=humans.map(x=>x.code);for(let i=0;i<32;i++)codes.push(k.encode(Uint8Array.from({length:16},(_,j)=>(i*17+j)%256)));
 for(const c of codes){const d=decode(c).d.data;assert.equal(d,c);assert.deepEqual(k.decode(d),k.decode(c));assert.equal(k.decode(d).length,16);}
});
await test('H error correction, four-module quiet zone, integer modules, opaque black/white only',()=>{
 const {q,im}=decode(code);assert.equal(q.errorCorrectionLevel,high);assert.equal(travel.quiet,4);assert.equal(travel.scale,12);
 assert.equal(im.width,(q.size+8)*12);for(let y=0;y<im.height;y++)for(let x=0;x<im.width;x++){
 const i=(y*im.width+x)*4;assert.equal(im.data[i],im.data[i+1]);assert.equal(im.data[i],im.data[i+2]);assert([0,255].includes(im.data[i]));assert.equal(im.data[i+3],255);
 if(x<48||y<48||x>=im.width-48||y>=im.height-48)assert.equal(im.data[i],255);
 }
});
await test('repeat encoding deterministic without random source or network',()=>{
 const a=decode(code).im,b=decode(code).im;assert.deepEqual(a.data,b.data);assert.equal(network,0);
});
await test('noncanonical/invalid input rejected before QR or Argon2',()=>{
 const before=k.argonCalls;for(const c of [code.toLowerCase(),code.replaceAll('-',''),code.slice(0,-1)+'2','https://example.com'])assert.throws(()=>travel.make(c));assert.equal(k.argonCalls,before);
});
await test('QR code and manual code preserve all original public KDF outputs',async()=>{
 const v=JSON.parse(fs.readFileSync(path.join(__dirname,'../public-vectors.json'),'utf8'));
 const scanned=decode(code).d.data;assert.deepEqual(await k.deriveCode(v.input.master_phrase,scanned,'example.com','test',1,24),v.expected);
 assert.deepEqual(await k.deriveCode(v.input.master_phrase,code,'example.com','test',1,24),v.expected);
});
await test('production embeds encoder only; no decoder, camera, uploads or storage APIs',()=>{
 const html=fs.readFileSync(path.join(__dirname,'../RECOVER.html'),'utf8');
 const scripts=[...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(x=>x[1]).join('\n');
 for(const api of ['jsQR','getUserMedia','mediaDevices','RTCPeerConnection','fetch(','XMLHttpRequest','WebSocket','sendBeacon','localStorage','indexedDB'])assert(!scripts.includes(api),api);
 assert(html.includes("connect-src 'none'"));assert.equal(network,0);
});
console.log(`PASS: ${passed}/7 QR tests; public data only`);
})().catch(()=>process.exit(1));
