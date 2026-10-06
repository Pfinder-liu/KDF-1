'use strict';
const $=id=>document.getElementById(id);
let halted=false;
let phraseInputRejected=false;
function rejectRawPhraseInput(event){
  event.preventDefault();phraseInputRejected=true;
  $('phrase').value='';$('password').textContent='';resetPhraseVisibility();
  $('recover').disabled=true;
  $('status').className='stop';
  $('status').textContent='STOP — Master Phrase 禁止 CR / LF 换行；本次输入已拒绝。请重新输入单行短语。';
}
function acceptRawPhraseEdit(){
  if(!phraseInputRejected)return;
  phraseInputRejected=false;$('recover').disabled=halted||$('create-code').disabled;
  if(!halted){$('status').className='pass';$('status').textContent='SELF TEST PASS — 请核对重新输入的单行 Master Phrase。';}
}
function inspectPhraseTransfer(event,transfer){
  // Inspect raw clipboard/drop data BEFORE single-line HTML sanitization.
  if(!transfer || typeof transfer.getData!=='function'){
    rejectRawPhraseInput(event);
    $('status').textContent='STOP — 无法验证原始粘贴文本。请手工输入 Master Phrase。';
    return;
  }
  if(/[\r\n]/.test(transfer.getData('text/plain')))rejectRawPhraseInput(event);
  else acceptRawPhraseEdit();
}

function qrControls(){
  const blocked=halted||$('create-code').disabled;
  $('create-qr').disabled=blocked||!$('new-code').textContent;
  $('save-qr').disabled=$('print-qr').disabled=blocked||$('qr-card').hidden;
}
function clearQR(){
  $('qr-card').hidden=true;$('travel-qr').width=$('travel-qr').height=0;qrControls();
}

const secretFields=['code','phrase','label','account','revision','length','recover','toggle-phrase','create-code'];
function resetPhraseVisibility() {
  $('phrase').type='password';
  $('toggle-phrase').textContent='Show Master Phrase';
  $('toggle-phrase').setAttribute('aria-pressed','false');
}
function toggleMasterPhrase() {
  const visible=$('phrase').type==='password';
  $('phrase').type=visible?'text':'password';
  $('toggle-phrase').textContent=visible?'Hide Master Phrase':'Show Master Phrase';
  $('toggle-phrase').setAttribute('aria-pressed',String(visible));
}
function createRecoveryCode() {
  const secret=new Uint8Array(16);
  try {
    crypto.getRandomValues(secret);
    return KDF1.encode(secret);
  } finally { secret.fill(0); }
}
function stop(error) {
  halted=true;
  const message=error && error.message ? error.message : String(error);
  $('status').textContent='STOP — '+message+'\n不要输入 Master Phrase 或 Recovery Code。请取得可信副本或兼容浏览器。';
  $('status').className='stop';
  secretFields.forEach(id=>$(id).disabled=true);
  $('public-tests').disabled=true;qrControls();$('password').textContent='';
  $('phrase').value='';$('code').value='';$('new-code').textContent='';resetPhraseVisibility();clearQR();
}
window.addEventListener('error',e=>stop(Error('运行错误：'+e.message)));
window.addEventListener('unhandledrejection',e=>stop(e.reason));
window.addEventListener('securitypolicyviolation',e=>{
  if(e.effectiveDirective==='script-src-elem'||e.effectiveDirective==='script-src'||e.effectiveDirective==='style-src-elem')
    stop(Error('CSP 拒绝了脚本或样式（文件损坏/浏览器兼容）：'+e.effectiveDirective));
});
document.addEventListener('DOMContentLoaded',async()=>{
  try {
    if(location.protocol!=='file:')throw Error('请从本地文件打开 RECOVER.html（file://）。');
    if(!globalThis.crypto?.subtle || typeof crypto.getRandomValues!=='function' || typeof WebAssembly==='undefined')throw Error('浏览器不支持本地 Web Crypto / WebAssembly。');
    if(typeof hashwasm==='undefined'||typeof KDF1==='undefined')throw Error('本地计算代码未加载；可能被 CSP 拦截或文件损坏。');
    // Hash exact embedded payload bytes. Expected digests are inserted at build time.
    const checks=INTEGRITY_PLACEHOLDER;
    for(const [id,expected] of Object.entries(checks)) {
      if(KDF1.hex(await KDF1.sha(new TextEncoder().encode($(id).textContent)))!==expected)
        throw Error('内嵌完整性校验失败：'+id);
    }
    if(KDF1.hex(await KDF1.sha(new TextEncoder().encode($('page-style').textContent)))!=='STYLE_DIGEST_PLACEHOLDER')
      throw Error('内嵌完整性校验失败：page-style');
    const vector=JSON.parse($('public-vector').textContent),humans=JSON.parse($('human-vectors').textContent),cases=JSON.parse($('public-cases').textContent);
    KDF1.phraseSelfTest(JSON.parse($('phrase-vectors').textContent));
    await KDF1.selfTest(vector,humans);
    TravelQR.make(KDF1.encode(KDF1.unhex(vector.input.recovery_secret_hex)));
    if(halted)return;
    $('status').textContent='SELF TEST PASS — 本地完整性、公开 KDF 三项结果与 Human Code 向量通过。可以输入恢复材料。';
    $('status').className='pass';secretFields.forEach(id=>$(id).disabled=false);$('public-tests').disabled=false;qrControls();
    clearQR();$('code').focus();
    window.addEventListener('afterprint',()=>document.body.classList.remove('travel-print'));
    $('create-qr').addEventListener('click',()=>{
      try {TravelQR.render($('travel-qr'),TravelQR.make($('new-code').textContent));$('qr-card').hidden=false;qrControls();}
      catch(error){stop(Error('QR 创建失败：'+error.message));}
    });
    $('save-qr').addEventListener('click',()=>{
      $('travel-qr').toBlob(blob=>{
        if(halted)return;
        if(!blob){stop(Error('PNG 导出失败'));return;}
        const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='card.png';a.click();
        setTimeout(()=>URL.revokeObjectURL(url),1000);
      },'image/png');
    });
    $('print-qr').addEventListener('click',()=>{document.body.classList.add('travel-print');window.print();});
    $('toggle-phrase').addEventListener('click',toggleMasterPhrase);
    $('phrase').addEventListener('paste',e=>inspectPhraseTransfer(e,e.clipboardData));
    $('phrase').addEventListener('drop',e=>inspectPhraseTransfer(e,e.dataTransfer));
    $('phrase').addEventListener('beforeinput',e=>{
      if(/[\r\n]/.test(e.data||'') || e.inputType==='insertLineBreak' || e.inputType==='insertParagraph')rejectRawPhraseInput(e);
      else if(e.data!==null && e.data!==undefined)acceptRawPhraseEdit();
    });
    $('phrase').addEventListener('input',e=>{
      // Keep rejection latched if a non-cancelable edit was sanitized by the host.
      if(phraseInputRejected){$('phrase').value='';return;}
      if(/[\r\n]/.test($('phrase').value))rejectRawPhraseInput(e);
    });
    $('create-code').addEventListener('click',()=>{
      $('new-code').textContent='';clearQR();
      try { $('new-code').textContent=createRecoveryCode();qrControls(); }
      catch(error) { stop(Error('无法创建新 Recovery Code：'+error.message)); }
    });
    $('recover').addEventListener('click',async()=>{
      $('password').textContent='';
      if(phraseInputRejected){$('status').textContent='STOP — 换行输入已拒绝；请重新输入单行 Master Phrase。';return;}
      let secret;
      try {
        // Validate code and metadata before reading the phrase or doing expensive KDF.
        secret=KDF1.decode($('code').value);
        const lab=KDF1.label($('label').value),account=KDF1.label($('account').value,true);
        const revision=KDF1.parseNumber($('revision').value,1,1,4294967295,'Revision');
        const length=KDF1.parseNumber($('length').value,24,8,1024,'Length');
        if(!$('phrase').value)throw Error('Master Phrase 不能为空。');
        const master=KDF1.textScalar($('phrase').value);$('phrase').value='';resetPhraseVisibility();
        secretFields.forEach(id=>$(id).disabled=true);$('public-tests').disabled=true;qrControls();
        $('status').className='';$('status').textContent='正在计算…';
        const result=await KDF1.derive(master,secret,lab,account,revision,length);
        if(halted)return;
        $('password').textContent=result.password;$('code').value='';
        $('status').textContent=`已恢复：label=${lab}; account=${account}; revision=${revision}; length=${length}。完成后关闭此页。`;
        $('status').className='pass';secretFields.forEach(id=>$(id).disabled=false);$('public-tests').disabled=false;qrControls();
      } catch(error) {
        if($('recover').disabled) { stop(error); }
        else { $('status').textContent='STOP — 输入错误：'+error.message; $('status').className='stop'; }
      } finally { if(secret)secret.fill(0); }
    });
    $('public-tests').addEventListener('click',async()=>{
      phraseInputRejected=false;
      // Never submit or use any values from the secret form in developer verification.
      $('phrase').value='';$('code').value='';$('password').textContent='';resetPhraseVisibility();
      secretFields.forEach(id=>$(id).disabled=true);$('public-tests').disabled=true;qrControls();
      $('test-report').textContent='正在验证固定公开数据…';
      try {
        const result=await KDF1.publicTests(cases,humans);
        if(halted)return;
        $('test-report').textContent=result+'\nPUBLIC CROSS-IMPLEMENTATION TESTS PASS';
        secretFields.forEach(id=>$(id).disabled=false);$('public-tests').disabled=false;qrControls();
      }catch(error){$('test-report').textContent='FAIL — '+error.message;stop(error);}
    });
  }catch(error){stop(error);}
});
