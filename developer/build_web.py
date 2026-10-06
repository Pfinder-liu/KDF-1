#!/usr/bin/env python3
"""Developer-only deterministic assembly, no installs/network/build runtime."""
from pathlib import Path
import base64
import hashlib
import json
import sys
ROOT=Path(__file__).resolve().parents[1]
DEV=ROOT/'developer'
def digest(text):return hashlib.sha256(text.encode()).hexdigest()
def csp_hash(text):return "'sha256-"+base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()+"'"
def build():
    vendor=(DEV/'vendor/argon2.umd.min.js').read_text()
    if digest(vendor)!='dcec617a2e1b700fa132d1583a186cb70611113395e869f2dd6cc82b415d3094':raise RuntimeError('Pinned hash-wasm source checksum mismatch')
    core=(DEV/'core.js').read_text()
    qr=(DEV/'vendor/qr/qrcodegen.js').read_text()
    travel=(DEV/'travel_qr.js').read_text()
    if digest(qr)!='6e200897a80ff15a652a5d601667856d807cec60cfc81a3a351305d69cc9dbbd':raise RuntimeError('Pinned Nayuki QR source checksum mismatch')
    data={ 'public-vector':(ROOT/'public-vectors.json').read_text(),
           'human-vectors':(ROOT/'human-vectors.json').read_text(),
           'public-cases':(DEV/'public-cases.json').read_text(),
           'phrase-vectors':(ROOT/'master-phrase-vectors.json').read_text() }
    integrity={k:digest(v) for k,v in dict(data,**{'vendor-code':vendor,'core-code':core,'qr-vendor-code':qr,'travel-qr-code':travel}).items()}
    ui=(DEV/'ui.js').read_text().replace('INTEGRITY_PLACEHOLDER',json.dumps(integrity,sort_keys=True))
    style='''body{font:17px system-ui,sans-serif;max-width:740px;margin:30px auto;padding:0 20px;color:#162323;background:#f3f5f4}h1{font-size:28px;margin-bottom:4px}.candidate{font-size:14px;color:#57635f}#status{white-space:pre-wrap;padding:14px;border:1px solid #9daaa4;border-radius:8px;background:white}.pass{color:#126044}.stop{color:#a32626}label{display:block;margin:18px 0 6px}input{box-sizing:border-box;width:100%;font:inherit;padding:10px;border:1px solid #879a91;border-radius:5px;background:white}input:disabled,button:disabled{opacity:.5}#code,#password,#new-code{font-family:ui-monospace,monospace}button{font:inherit;margin:20px 0 10px;padding:12px 22px;border-radius:6px;border:0;background:#215e48;color:white;cursor:pointer}#password{background:white;border:1px solid #879a91;padding:16px;min-height:25px;overflow-wrap:anywhere;white-space:pre-wrap;user-select:all}.note{font-size:14px;color:#4b5b54;line-height:1.6}.row{display:grid;grid-template-columns:1fr 1fr;gap:20px}details{margin:24px 0}pre{white-space:pre-wrap;font-size:13px}#new-code{font-size:22px;overflow-wrap:anywhere;user-select:all}h2{font-size:22px}#travel-qr{max-width:100%;width:328px;height:auto;image-rendering:pixelated}#qr-card[hidden]{display:none}@media print{body.travel-print> :not(#create-section),body.travel-print #create-section> :not(#qr-card),body.travel-print #qr-card> :not(#travel-qr){display:none!important}body.travel-print #qr-card{display:block!important}body.travel-print #travel-qr{visibility:visible!important;display:block!important;width:45mm;height:45mm}body.travel-print{margin:0;padding:0}}@media print{#recover-section,#public-section,#status,.candidate,button,summary{display:none!important}body{background:white;color:black}#create-section{border:0}#new-code{font-size:22px}}'''
    ui=ui.replace('STYLE_DIGEST_PLACEHOLDER',digest(style))
    policy="default-src 'none'; connect-src 'none'; script-src "+' '.join(csp_hash(s) for s in [ui,vendor,core,qr,travel])+" 'wasm-unsafe-eval'; style-src "+csp_hash(style)+"; base-uri 'none'; form-action 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; img-src 'none'; font-src 'none'; media-src 'none'; manifest-src 'none'"
    html='''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="POLICY">
<meta name="referrer" content="no-referrer"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KDF-1 本地恢复计算器 — candidate</title>
<style id="page-style">STYLE</style><script id="ui-code">UI</script></head><body>
<h1>KDF-1 本地恢复计算器</h1><p class="candidate">CANDIDATE / NOT FROZEN · 同一份文件 · 本地运行</p>
<p id="status" class="stop" role="status">STOP — 尚未完成自检。脚本被拦截、文件损坏或浏览器不支持时，请勿输入任何秘密。</p>
<p class="note">建议断网。等待 SELF TEST PASS 后，按纸张和保存的记录输入。此页不保存输入、不联网。</p>
<section id="recover-section"><h2>Recover / Derive Password</h2>
<label for="code">Recovery Code（明文可见，从纸张手输）</label><input id="code" type="text" autocomplete="off" autocapitalize="characters" spellcheck="false" disabled>
<label for="phrase">Master Phrase（隐藏；大小写与空格重要，禁止换行）</label><input id="phrase" type="password" autocomplete="off" spellcheck="false" disabled>
<button id="toggle-phrase" type="button" aria-pressed="false" disabled>Show Master Phrase</button>
<p class="note">Show/Hide 仅便于核对输入；隐藏主要防止旁观者偶然看到，不能防御键盘记录器或已被控制的电脑。</p>
<label for="label">永久 label</label><input id="label" type="text" autocomplete="off" spellcheck="false" disabled>
<label for="account">account 别名（可以空白；大小写重要）</label><input id="account" type="text" autocomplete="off" spellcheck="false" disabled>
<div class="row"><div><label for="revision">revision</label><input id="revision" value="1" inputmode="numeric" autocomplete="off" disabled></div><div><label for="length">密码长度</label><input id="length" value="24" inputmode="numeric" autocomplete="off" disabled></div></div>
<button id="recover" type="button" disabled>恢复密码</button>
<div id="password" aria-label="恢复出的密码"></div>
<p class="note">使用完密码后关闭页面。不要把 Master Phrase 写在恢复纸上。纸被看到后，攻击者仍可离线猜测 phrase，记忆短语应足够强。本地校验能发现损坏，不能认证被恶意整体替换的文件。</p>
</section>
<details id="create-section"><summary>Create NEW Recovery Code — 首次建立</summary>
<h2>Create NEW Recovery Code</h2>
<p class="stop">A newly generated Recovery Code cannot recover passwords created with a different Recovery Code.</p>
<p>新码不能恢复使用其他 Recovery Code 建立的密码。旧码遗失时，创建新码不是找回方式。</p>
<button id="create-code" type="button" disabled>Create NEW Recovery Code</button>
<pre id="new-code" aria-label="新创建的 Human Recovery Code"></pre>
<p>请抄写、打印或自行保存新码；不要把 Master Phrase 放在同一张纸上。页面不会自动保存，关闭前先保留副本。</p>
<button id="create-qr" type="button" disabled>Create Anonymous Travel QR</button>
<p class="note">QR 不是加密。任何拍摄、复制或扫描此码的人，都取得了这份 Recovery Code。二维码只包含码本身，不包含 Master Phrase 或账户信息。</p>
<div id="qr-card" hidden><canvas id="travel-qr" aria-label="Anonymous QR"></canvas><br>
<button id="save-qr" type="button" disabled>Save QR-only PNG</button>
<button id="print-qr" type="button" disabled>Print QR only</button>
<p class="note">保存的图片只有二维码。打印时关闭浏览器的页眉和页脚（避免附带标题、路径或日期）；建议至少 45 mm 方形。用系统相机扫描 → 复制文本 → 粘贴到 Recovery Code 输入框。仍可手工输入。</p></div>
</details>
<details id="public-section"><summary>公开验证（仅使用固定测试数据）</summary><p class="note">这不是纸张手输演练。按钮会清空已填秘密，逐项比较 Python 保存的公开结果。</p><button id="public-tests" type="button" disabled>运行公开一致性测试</button><pre id="test-report"></pre></details>
DATA
<script id="vendor-code">VENDOR</script><script id="core-code">CORE</script><script id="qr-vendor-code">QRENC</script><script id="travel-qr-code">TRAVEL</script>
</body></html>
'''
    datahtml='\n'.join('<script type="application/json" id="'+k+'">'+v+'</script>' for k,v in data.items())
    replacements={'POLICY':policy,'STYLE':style,'UI':ui,'DATA':datahtml,'VENDOR':vendor,'CORE':core,'QRENC':qr,'TRAVEL':travel}
    # Single substitution pass: never replace tokens appearing inside payloads.
    import re
    html=re.sub(r'POLICY|STYLE|UI|DATA|VENDOR|CORE|QRENC|TRAVEL',lambda m:replacements[m.group()],html)
    if '</script' in vendor.lower() or '</script' in core.lower():raise RuntimeError('Unsafe script closing token in source')
    (ROOT/'RECOVER.html').write_text(html)
    checks={}
    for p in sorted(ROOT.rglob('*')):
        if p.is_file() and p.name!='INTEGRITY.json' and '__pycache__' not in p.parts:
            checks[p.relative_to(ROOT).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
    (ROOT/'INTEGRITY.json').write_text(json.dumps(checks,indent=2)+'\n')
    print('PASS: assembled self-contained RECOVER.html with pinned payloads and hash CSP')
if __name__=='__main__':
    try:build()
    except Exception as exc:
        print(f'WEB BUILD FAILED — root cause: {type(exc).__name__}: {exc}',file=sys.stderr);sys.exit(1)
