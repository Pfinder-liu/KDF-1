/* KDF-1 v1 adapter. Crypto is Web Crypto + pinned hash-wasm Argon2id. */
'use strict';
const KDF1 = (() => {
  const codeAlphabet = '23456789ABCDEFGHJKMNPQRS';
  const passwordAlphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+';
  const utf8 = new TextEncoder();
  const trimASCII = s => s.replace(/^[ \t\r\n\v\f]+|[ \t\r\n\v\f]+$/g, '');
  let argonCalls = 0;
  // Fixed Unicode 13 assigned-scalar repertoire: host category/Unicode age is irrelevant.
  // Later conformant NFC preserves these strings; never admit newly assigned marks.
  const phraseRanges = [[0,9],[11,12],[14,887],[890,895],[900,906],[908,908],[910,929],[931,1327],[1329,1366],[1369,1418],[1421,1423],[1425,1479],[1488,1514],[1519,1524],[1536,1564],[1566,1805],[1807,1866],[1869,1969],[1984,2042],[2045,2093],[2096,2110],[2112,2139],[2142,2142],[2144,2154],[2208,2228],[2230,2247],[2259,2435],[2437,2444],[2447,2448],[2451,2472],[2474,2480],[2482,2482],[2486,2489],[2492,2500],[2503,2504],[2507,2510],[2519,2519],[2524,2525],[2527,2531],[2534,2558],[2561,2563],[2565,2570],[2575,2576],[2579,2600],[2602,2608],[2610,2611],[2613,2614],[2616,2617],[2620,2620],[2622,2626],[2631,2632],[2635,2637],[2641,2641],[2649,2652],[2654,2654],[2662,2678],[2689,2691],[2693,2701],[2703,2705],[2707,2728],[2730,2736],[2738,2739],[2741,2745],[2748,2757],[2759,2761],[2763,2765],[2768,2768],[2784,2787],[2790,2801],[2809,2815],[2817,2819],[2821,2828],[2831,2832],[2835,2856],[2858,2864],[2866,2867],[2869,2873],[2876,2884],[2887,2888],[2891,2893],[2901,2903],[2908,2909],[2911,2915],[2918,2935],[2946,2947],[2949,2954],[2958,2960],[2962,2965],[2969,2970],[2972,2972],[2974,2975],[2979,2980],[2984,2986],[2990,3001],[3006,3010],[3014,3016],[3018,3021],[3024,3024],[3031,3031],[3046,3066],[3072,3084],[3086,3088],[3090,3112],[3114,3129],[3133,3140],[3142,3144],[3146,3149],[3157,3158],[3160,3162],[3168,3171],[3174,3183],[3191,3212],[3214,3216],[3218,3240],[3242,3251],[3253,3257],[3260,3268],[3270,3272],[3274,3277],[3285,3286],[3294,3294],[3296,3299],[3302,3311],[3313,3314],[3328,3340],[3342,3344],[3346,3396],[3398,3400],[3402,3407],[3412,3427],[3430,3455],[3457,3459],[3461,3478],[3482,3505],[3507,3515],[3517,3517],[3520,3526],[3530,3530],[3535,3540],[3542,3542],[3544,3551],[3558,3567],[3570,3572],[3585,3642],[3647,3675],[3713,3714],[3716,3716],[3718,3722],[3724,3747],[3749,3749],[3751,3773],[3776,3780],[3782,3782],[3784,3789],[3792,3801],[3804,3807],[3840,3911],[3913,3948],[3953,3991],[3993,4028],[4030,4044],[4046,4058],[4096,4293],[4295,4295],[4301,4301],[4304,4680],[4682,4685],[4688,4694],[4696,4696],[4698,4701],[4704,4744],[4746,4749],[4752,4784],[4786,4789],[4792,4798],[4800,4800],[4802,4805],[4808,4822],[4824,4880],[4882,4885],[4888,4954],[4957,4988],[4992,5017],[5024,5109],[5112,5117],[5120,5788],[5792,5880],[5888,5900],[5902,5908],[5920,5942],[5952,5971],[5984,5996],[5998,6000],[6002,6003],[6016,6109],[6112,6121],[6128,6137],[6144,6158],[6160,6169],[6176,6264],[6272,6314],[6320,6389],[6400,6430],[6432,6443],[6448,6459],[6464,6464],[6468,6509],[6512,6516],[6528,6571],[6576,6601],[6608,6618],[6622,6683],[6686,6750],[6752,6780],[6783,6793],[6800,6809],[6816,6829],[6832,6848],[6912,6987],[6992,7036],[7040,7155],[7164,7223],[7227,7241],[7245,7304],[7312,7354],[7357,7367],[7376,7418],[7424,7673],[7675,7957],[7960,7965],[7968,8005],[8008,8013],[8016,8023],[8025,8025],[8027,8027],[8029,8029],[8031,8061],[8064,8116],[8118,8132],[8134,8147],[8150,8155],[8157,8175],[8178,8180],[8182,8190],[8192,8292],[8294,8305],[8308,8334],[8336,8348],[8352,8383],[8400,8432],[8448,8587],[8592,9254],[9280,9290],[9312,11123],[11126,11157],[11159,11310],[11312,11358],[11360,11507],[11513,11557],[11559,11559],[11565,11565],[11568,11623],[11631,11632],[11647,11670],[11680,11686],[11688,11694],[11696,11702],[11704,11710],[11712,11718],[11720,11726],[11728,11734],[11736,11742],[11744,11858],[11904,11929],[11931,12019],[12032,12245],[12272,12283],[12288,12351],[12353,12438],[12441,12543],[12549,12591],[12593,12686],[12688,12771],[12784,12830],[12832,40956],[40960,42124],[42128,42182],[42192,42539],[42560,42743],[42752,42943],[42946,42954],[42997,43052],[43056,43065],[43072,43127],[43136,43205],[43214,43225],[43232,43347],[43359,43388],[43392,43469],[43471,43481],[43486,43518],[43520,43574],[43584,43597],[43600,43609],[43612,43714],[43739,43766],[43777,43782],[43785,43790],[43793,43798],[43808,43814],[43816,43822],[43824,43883],[43888,44013],[44016,44025],[44032,55203],[55216,55238],[55243,55291],[57344,64109],[64112,64217],[64256,64262],[64275,64279],[64285,64310],[64312,64316],[64318,64318],[64320,64321],[64323,64324],[64326,64449],[64467,64831],[64848,64911],[64914,64967],[65008,65021],[65024,65049],[65056,65106],[65108,65126],[65128,65131],[65136,65140],[65142,65276],[65279,65279],[65281,65470],[65474,65479],[65482,65487],[65490,65495],[65498,65500],[65504,65510],[65512,65518],[65529,65533],[65536,65547],[65549,65574],[65576,65594],[65596,65597],[65599,65613],[65616,65629],[65664,65786],[65792,65794],[65799,65843],[65847,65934],[65936,65948],[65952,65952],[66000,66045],[66176,66204],[66208,66256],[66272,66299],[66304,66339],[66349,66378],[66384,66426],[66432,66461],[66463,66499],[66504,66517],[66560,66717],[66720,66729],[66736,66771],[66776,66811],[66816,66855],[66864,66915],[66927,66927],[67072,67382],[67392,67413],[67424,67431],[67584,67589],[67592,67592],[67594,67637],[67639,67640],[67644,67644],[67647,67669],[67671,67742],[67751,67759],[67808,67826],[67828,67829],[67835,67867],[67871,67897],[67903,67903],[67968,68023],[68028,68047],[68050,68099],[68101,68102],[68108,68115],[68117,68119],[68121,68149],[68152,68154],[68159,68168],[68176,68184],[68192,68255],[68288,68326],[68331,68342],[68352,68405],[68409,68437],[68440,68466],[68472,68497],[68505,68508],[68521,68527],[68608,68680],[68736,68786],[68800,68850],[68858,68903],[68912,68921],[69216,69246],[69248,69289],[69291,69293],[69296,69297],[69376,69415],[69424,69465],[69552,69579],[69600,69622],[69632,69709],[69714,69743],[69759,69825],[69837,69837],[69840,69864],[69872,69881],[69888,69940],[69942,69959],[69968,70006],[70016,70111],[70113,70132],[70144,70161],[70163,70206],[70272,70278],[70280,70280],[70282,70285],[70287,70301],[70303,70313],[70320,70378],[70384,70393],[70400,70403],[70405,70412],[70415,70416],[70419,70440],[70442,70448],[70450,70451],[70453,70457],[70459,70468],[70471,70472],[70475,70477],[70480,70480],[70487,70487],[70493,70499],[70502,70508],[70512,70516],[70656,70747],[70749,70753],[70784,70855],[70864,70873],[71040,71093],[71096,71133],[71168,71236],[71248,71257],[71264,71276],[71296,71352],[71360,71369],[71424,71450],[71453,71467],[71472,71487],[71680,71739],[71840,71922],[71935,71942],[71945,71945],[71948,71955],[71957,71958],[71960,71989],[71991,71992],[71995,72006],[72016,72025],[72096,72103],[72106,72151],[72154,72164],[72192,72263],[72272,72354],[72384,72440],[72704,72712],[72714,72758],[72760,72773],[72784,72812],[72816,72847],[72850,72871],[72873,72886],[72960,72966],[72968,72969],[72971,73014],[73018,73018],[73020,73021],[73023,73031],[73040,73049],[73056,73061],[73063,73064],[73066,73102],[73104,73105],[73107,73112],[73120,73129],[73440,73464],[73648,73648],[73664,73713],[73727,74649],[74752,74862],[74864,74868],[74880,75075],[77824,78894],[78896,78904],[82944,83526],[92160,92728],[92736,92766],[92768,92777],[92782,92783],[92880,92909],[92912,92917],[92928,92997],[93008,93017],[93019,93025],[93027,93047],[93053,93071],[93760,93850],[93952,94026],[94031,94087],[94095,94111],[94176,94180],[94192,94193],[94208,100343],[100352,101589],[101632,101640],[110592,110878],[110928,110930],[110948,110951],[110960,111355],[113664,113770],[113776,113788],[113792,113800],[113808,113817],[113820,113827],[118784,119029],[119040,119078],[119081,119272],[119296,119365],[119520,119539],[119552,119638],[119648,119672],[119808,119892],[119894,119964],[119966,119967],[119970,119970],[119973,119974],[119977,119980],[119982,119993],[119995,119995],[119997,120003],[120005,120069],[120071,120074],[120077,120084],[120086,120092],[120094,120121],[120123,120126],[120128,120132],[120134,120134],[120138,120144],[120146,120485],[120488,120779],[120782,121483],[121499,121503],[121505,121519],[122880,122886],[122888,122904],[122907,122913],[122915,122916],[122918,122922],[123136,123180],[123184,123197],[123200,123209],[123214,123215],[123584,123641],[123647,123647],[124928,125124],[125127,125142],[125184,125259],[125264,125273],[125278,125279],[126065,126132],[126209,126269],[126464,126467],[126469,126495],[126497,126498],[126500,126500],[126503,126503],[126505,126514],[126516,126519],[126521,126521],[126523,126523],[126530,126530],[126535,126535],[126537,126537],[126539,126539],[126541,126543],[126545,126546],[126548,126548],[126551,126551],[126553,126553],[126555,126555],[126557,126557],[126559,126559],[126561,126562],[126564,126564],[126567,126570],[126572,126578],[126580,126583],[126585,126588],[126590,126590],[126592,126601],[126603,126619],[126625,126627],[126629,126633],[126635,126651],[126704,126705],[126976,127019],[127024,127123],[127136,127150],[127153,127167],[127169,127183],[127185,127221],[127232,127405],[127462,127490],[127504,127547],[127552,127560],[127568,127569],[127584,127589],[127744,128727],[128736,128748],[128752,128764],[128768,128883],[128896,128984],[128992,129003],[129024,129035],[129040,129095],[129104,129113],[129120,129159],[129168,129197],[129200,129201],[129280,129400],[129402,129483],[129485,129619],[129632,129645],[129648,129652],[129656,129658],[129664,129670],[129680,129704],[129712,129718],[129728,129730],[129744,129750],[129792,129938],[129940,129994],[130032,130041],[131072,173789],[173824,177972],[177984,178205],[178208,183969],[183984,191456],[194560,195101],[196608,201546],[917505,917505],[917536,917631],[917760,917999],[983040,1048573],[1048576,1114109]];
  function phraseContains(cp) {
    let lo=0,hi=phraseRanges.length-1;
    while(lo<=hi){const mid=(lo+hi)>>1,[a,b]=phraseRanges[mid];
      if(cp<a)hi=mid-1;else if(cp>b)lo=mid+1;else return true;}
    return false;
  }
  function textScalar(s) {
    if (typeof s !== 'string') throw Error('Master Phrase must be text.');
    if (!s) throw Error('Master Phrase 不能为空。');
    if (/[\r\n]/.test(s)) throw Error('Master Phrase 禁止 CR / LF 换行；请重新输入单行短语。');
    for (const c of s) if(!phraseContains(c.codePointAt(0)))
      throw Error('Master Phrase 含 KDF-1 v1 固定 Unicode 13.0 范围之外的字符（包括无效 Unicode）。');
    return s.normalize('NFC');
  }
  function phraseSelfTest(rows) {
    if(!Array.isArray(rows)||!rows.length)throw Error('Master Phrase contract vectors missing.');
    for(const row of rows){
      if(row.valid){
        const normalized=textScalar(row.input);
        if(normalized!==row.nfc || hex(utf8.encode(normalized))!==row.utf8_hex)
          throw Error('Master Phrase NFC / UTF-8 self-test failed.');
      }else{
        let rejected=false;try{textScalar(row.input);}catch(_){rejected=true;}
        if(!rejected)throw Error('Invalid Master Phrase accepted by self-test.');
      }
    }
  }
  function label(s, account=false) {
    if (typeof s !== 'string') throw Error('Label must be text.');
    const t=trimASCII(s);
    if (!/^[A-Za-z0-9._-]{0,128}$/.test(t) || (!account && !t))
      throw Error('Label 仅允许 1–128 个 ASCII 字母、数字、点、下划线或连字符；account 可以空白。');
    return account ? t : t.toLowerCase();
  }
  function integer(n,min,max,name) {
    if (!Number.isSafeInteger(n) || n<min || n>max) throw Error(`${name} 必须是 ${min}…${max} 的整数。`);
    return n;
  }
  function parseNumber(s,def,min,max,name) {
    const t=trimASCII(s);
    if (!t) return def;
    if (!/^[0-9]+$/.test(t)) throw Error(`${name} 仅允许 ASCII 十进制数字。`);
    return integer(Number(t),min,max,name);
  }
  function checksum(v) { return v.reduce((sum,d,i)=>sum+(i+1)*d,0)%571; }
  function decode(s) {
    if (typeof s!=='string') throw Error('Recovery Code 必须是文本。');
    const text=s.replace(/[- \t\r\n\v\f]/g,'').replace(/[a-z]/g,c=>c.toUpperCase());
    if (text.length!==32 || [...text].some(c=>!codeAlphabet.includes(c)))
      throw Error('Recovery Code 格式错误。请重新核对纸张；不要猜测或纠错。');
    const v=[...text].map(c=>codeAlphabet.indexOf(c));
    if (v[30]*24+v[31]!==checksum(v.slice(0,30)))
      throw Error('Recovery Code checksum 校验失败。请重新核对纸张。');
    let n=0n;
    for (const d of v.slice(0,30)) n=n*24n+BigInt(d);
    if (n>=(1n<<128n)) throw Error('Recovery Code 超出 128-bit 范围。请重新核对纸张。');
    const bytes=new Uint8Array(16);
    for(let i=15;i>=0;i--) { bytes[i]=Number(n&255n);n>>=8n; }
    return bytes;
  }
  function encode(secret) {
    if (!(secret instanceof Uint8Array) || secret.length!==16) throw Error('Secret must be exactly 16 bytes.');
    let n=0n;for(const b of secret)n=(n<<8n)+BigInt(b);
    const v=new Array(30).fill(0);
    for(let i=29;i>=0;i--){v[i]=Number(n%24n);n/=24n;}
    const c=checksum(v);const s=v.map(d=>codeAlphabet[d]).join('')+codeAlphabet[Math.floor(c/24)]+codeAlphabet[c%24];
    return [...Array(6)].map((_,i)=>s.slice(i*5,i*5+5)).concat(s.slice(30)).join('-');
  }
  function hex(bytes) { return [...bytes].map(b=>b.toString(16).padStart(2,'0')).join(''); }
  function unhex(s) {
    if (!/^[0-9a-fA-F]{32}$/.test(s)) throw Error('Public secret hex invalid.');
    return Uint8Array.from(s.match(/../g),x=>parseInt(x,16));
  }
  function concat(...parts) {
    const out=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let offset=0;
    for(const p of parts){out.set(p,offset);offset+=p.length;}return out;
  }
  async function sha(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)); }
  async function hmac(key,bytes) {
    const k=await crypto.subtle.importKey('raw',key,{name:'HMAC',hash:'SHA-256'},false,['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC',k,bytes));
  }
  async function derive(phrase,secret,lab,account='',revision=1,length=24) {
    const l=label(lab),a=label(account,true);
    integer(revision,1,4294967295,'Revision');integer(length,8,1024,'Length');
    if (!(secret instanceof Uint8Array) || secret.length!==16) throw Error('Secret must be 16 bytes.');
    const normalized=textScalar(phrase);
    if (!normalized) throw Error('Master Phrase 不能为空。');
    const salt=(await sha(concat(utf8.encode('KDF-1-v1|argon2-salt|'),secret))).slice(0,16);
    const phraseBytes=utf8.encode(normalized);
    let mk,sk;
    try {
      argonCalls++;
      mk=await hashwasm.argon2id({password:phraseBytes,salt,iterations:3,memorySize:65536,parallelism:1,hashLength:32,outputType:'binary'});
      sk=await hmac(mk,utf8.encode(`KDF-1-v1|${l}|${a}|${revision}`));
      let pw='',counter=0n;
      while(pw.length<length) {
        const be=new Uint8Array(8);let n=counter;
        for(let i=7;i>=0;i--){be[i]=Number(n&255n);n>>=8n;}
        const block=await hmac(sk,concat(utf8.encode('KDF-1-v1|password-stream|'),be));
        for(const b of block)if(b<222){pw+=passwordAlphabet[b%74];if(pw.length===length)break;}
        block.fill(0);
        if(pw.length<length && counter===(1n<<64n)-1n)throw Error('Password stream exhausted.');
        counter++;
      }
      return {master_key_hex:hex(mk),site_key_hex:hex(sk),password:pw};
    } finally {
      phraseBytes.fill(0);salt.fill(0);if(mk)mk.fill(0);if(sk)sk.fill(0);
    }
  }
  async function deriveCode(phrase,code,lab,account='',revision=1,length=24) {
    const secret=decode(code);
    try { return await derive(phrase,secret,lab,account,revision,length); }
    finally { secret.fill(0); }
  }
  async function verifyVector(v) {
    if(v.scheme!=='KDF-1-v1')throw Error('Public vector scheme mismatch.');
    const i=v.input,rs=unhex(i.recovery_secret_hex);
    let actual;try { actual=await derive(i.master_phrase,rs,i.label,i.account,i.revision,i.length); }finally{rs.fill(0);}
    for(const field of ['master_key_hex','site_key_hex','password'])
      if(actual[field]!==v.expected[field])throw Error(`Public reference mismatch: ${field}.`);
    return actual;
  }
  async function selfTest(v,humans) {
    await verifyVector(v);
    if(!Array.isArray(humans)||humans.length!==4)throw Error('Human vectors missing or malformed.');
    for(const row of humans) {
      if(hex(decode(row.code))!==row.secret_hex || encode(unhex(row.secret_hex))!==row.code)
        throw Error('Human Code public vector mismatch.');
    }
  }
  async function publicTests(cases,humans) {
    const lines=[];
    for(let i=0;i<cases.length;i++) {
      await verifyVector(cases[i]);
      lines.push(`Case ${i+1}: master_key PASS; site_key PASS; password PASS`);
    }
    let rejected=0;
    const reject=s=>{try{decode(s);}catch(_){rejected++;return;}throw Error('Invalid code accepted.');};
    for(const row of humans) {
      const s=row.code.replace(/-/g,'');
      if(hex(decode(' \t'+row.code.toLowerCase().replace(/-/g,' \n-\r\v\f')))!==row.secret_hex)throw Error('Normalization mismatch.');
      for(let i=0;i<32;i++) {
        for(const c of codeAlphabet)if(c!==s[i])reject(s.slice(0,i)+c+s.slice(i+1));
        reject(s.slice(0,i)+s.slice(i+1));reject(s.slice(0,i)+'2'+s.slice(i));
      }
      for(let i=0;i<31;i++)if(s[i]!==s[i+1])reject(s.slice(0,i)+s[i+1]+s[i]+s.slice(i+2));
    }
    for(const c of ['0','O','1','I','L','—','\u00a0','K'])reject(c+humans[0].code);
    const c=checksum(new Array(30).fill(23));reject('S'.repeat(30)+codeAlphabet[Math.floor(c/24)]+codeAlphabet[c%24]);
    for(const s of ['', 'a|b','https://a','K','Ａ','a b','a'.repeat(129)]) {
      try { label(s); }catch(_){rejected++;continue;}throw Error('Invalid label accepted.');
    }
    for(const s of ['+1','-1','１','١','1_0','0','4294967296']) {
      try { parseNumber(s,1,1,4294967295,'Revision'); }catch(_){rejected++;continue;}throw Error('Invalid revision accepted.');
    }
    const before=argonCalls;
    try { await deriveCode('PUBLIC TEST',humans[0].code.slice(0,-1)+'2','example.com');throw Error('Bad checksum accepted.'); }
    catch(e) { if(argonCalls!==before)throw Error('Bad code invoked Argon2.'); }
    lines.push(`${rejected} invalid-input rejection cases PASS; normalization PASS; invalid-code-before-Argon2 PASS`);
    return lines.join('\n');
  }
  return {decode,encode,label,parseNumber,derive,deriveCode,verifyVector,selfTest,publicTests,hex,unhex,sha,textScalar,phraseSelfTest,get argonCalls(){return argonCalls;}};
})();
if(typeof module!=='undefined')module.exports=KDF1;
