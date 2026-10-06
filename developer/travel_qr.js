/* Representation only: canonical Human Code -> local QR Model 2. */
'use strict';
const TravelQR=(()=>{
  const quiet=4,scale=12;
  function make(code){
    const secret=KDF1.decode(code);
    try {if(KDF1.encode(secret)!==code)throw Error('QR requires the canonical Human Recovery Code');}
    finally {secret.fill(0);}
    return qrcodegen.QrCode.encodeText(code,qrcodegen.QrCode.Ecc.HIGH);
  }
  function pixels(qr){
    const width=(qr.size+quiet*2)*scale,data=new Uint8ClampedArray(width*width*4);data.fill(255);
    for(let y=0;y<qr.size;y++)for(let x=0;x<qr.size;x++)if(qr.getModule(x,y))
      for(let dy=0;dy<scale;dy++)for(let dx=0;dx<scale;dx++){
        const i=(((y+quiet)*scale+dy)*width+(x+quiet)*scale+dx)*4;
        data[i]=data[i+1]=data[i+2]=0;
      }
    return {width,height:width,data};
  }
  function render(canvas,qr){
    const image=pixels(qr);canvas.width=canvas.height=image.width;
    const ctx=canvas.getContext('2d');if(!ctx)throw Error('Canvas unavailable');
    const frame=ctx.createImageData(image.width,image.height);frame.data.set(image.data);ctx.putImageData(frame,0,0);
  }
  return {make,pixels,render,quiet,scale};
})();
