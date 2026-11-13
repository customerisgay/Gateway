'use strict';
/* Additive UI only. Payment success remains controlled by the existing verified status poll. */
(()=>{
 const $=s=>document.querySelector(s);
 let toastTimer;function toast(text){let t=$('#studioToast');if(!t){t=document.createElement('div');t.id='studioToast';t.className='studio-toast';t.setAttribute('role','status');document.body.append(t)}t.textContent=text;t.hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>t.hidden=true,4500)}
 document.querySelectorAll('[data-dialog]').forEach(b=>b.addEventListener('click',()=>{const d=document.getElementById(b.dataset.dialog);if(d)d.showModal()}));
 document.querySelectorAll('.studio-dialog').forEach(d=>{d.querySelector('[data-close]')?.addEventListener('click',()=>d.close());d.addEventListener('click',e=>{if(e.target===d){const r=d.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)d.close()}})});
 $('#privacyAcknowledge')?.addEventListener('click',()=>{try{localStorage.setItem('famgate_privacy_ack','1')}catch{}$('#privacyDialog').close()});
 $('#adminMessageForm')?.addEventListener('submit',e=>{e.preventDefault();const text='Reply email: '+$('#contactEmail').value.trim()+'\n\n'+$('#contactMessage').value.trim();location.href='mailto:godhostings@gmail.com?subject='+encodeURIComponent('Godpay support request')+'&body='+encodeURIComponent(text);toast('Email draft opened. Send it from your email app.')});
 $('#feedbackForm')?.addEventListener('submit',e=>{e.preventDefault();const r=document.querySelector('input[name=rating]:checked');if(!r)return;location.href='mailto:godhostings@gmail.com?subject='+encodeURIComponent('Godpay feedback — '+r.value+'/5')+'&body='+encodeURIComponent('Rating: '+r.value+'/5\n\n'+$('#feedbackText').value.trim());toast('Feedback draft opened in your email app.')});
 const features={direct:'Connect FamPay email verification or your BharatPe merchant feed. Customers scan one QR; collections settle to your own account.',gateway:'Bring your Razorpay, PhonePe, Paytm, Cashfree or MobiKwik merchant credentials. Use the existing hosted checkouts and verified provider callbacks.',developer:'Create orders over REST, retrieve a dynamic QR, poll payment status, and receive HMAC-signed webhooks. Your existing API keys and endpoints are unchanged.'};
 document.querySelectorAll('[data-feature]').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('[data-feature]').forEach(x=>x.setAttribute('aria-pressed',String(x===b)));$('#featureDescription').textContent=features[b.dataset.feature]}));
 const balance=$('#collectionAmount'),eye=$('#toggleBalance');if(balance&&eye){const real=balance.textContent;eye.addEventListener('click',()=>{const hide=eye.getAttribute('aria-pressed')!=='true';balance.textContent=hide?'₹ ••••••':real;eye.setAttribute('aria-pressed',String(hide));eye.setAttribute('aria-label',hide?'Show collected amount':'Hide collected amount')})}
 const qr=$('#qrImage'),loading=$('#qrLoading');if(qr&&loading){function settled(){loading.hidden=true}qr.addEventListener('load',settled);qr.addEventListener('error',()=>{loading.innerHTML='QR could not load. Please refresh this page.';loading.hidden=false});if(qr.complete){if(qr.naturalWidth)settled();else loading.textContent='QR could not load. Please refresh this page.'}}
 const receipt=$('#receiptTicket');if(!receipt)return;
 function verified(){return $('#successPanel')&&$('#successPanel').style.display!=='none'}
 function receiptText(){return 'Godpay — Payment receipt\nMerchant: '+receipt.dataset.merchant+'\nAmount: INR '+receipt.dataset.amount+'\nOrder: '+receipt.dataset.order+'\nStatus: VERIFIED / PAID\nBank reference: '+($('#utrValue')?.textContent||'—')}
 function receiptImage(){
  if(!verified())throw Error('Payment is not verified');
  const canvas=document.createElement('canvas');canvas.width=1080;canvas.height=1360;const ctx=canvas.getContext('2d');if(!ctx)throw Error('Image generation unavailable');
  ctx.fillStyle='#eaf2ff';ctx.fillRect(0,0,1080,1360);ctx.fillStyle='#0b1728';ctx.fillRect(54,54,972,1252);
  ctx.fillStyle='#82b8ff';ctx.font='700 38px system-ui,sans-serif';ctx.fillText('GODPAY',110,145);
  ctx.fillStyle='#eaf2ff';ctx.font='700 56px system-ui,sans-serif';ctx.fillText('Payment receipt',110,240);
  ctx.fillStyle='#80d9b0';ctx.font='700 30px system-ui,sans-serif';ctx.fillText('VERIFIED · PAID',110,304);
  const amount='₹'+receipt.dataset.amount;let size=104;ctx.font='700 '+size+'px system-ui,sans-serif';while(ctx.measureText(amount).width>850&&size>42){size-=2;ctx.font='700 '+size+'px system-ui,sans-serif'}ctx.fillStyle='#fff';ctx.fillText(amount,110,455);
  function field(label,value,y){ctx.fillStyle='#92aac8';ctx.font='500 25px system-ui,sans-serif';ctx.fillText(label,110,y);ctx.fillStyle='#f3f7ff';ctx.font='600 31px system-ui,sans-serif';const chars=Array.from(String(value||'—'));let line='',lines=[];for(const char of chars){if(ctx.measureText(line+char).width>850){lines.push(line);line=''}line+=char}if(line)lines.push(line);lines.slice(0,4).forEach((t,i)=>ctx.fillText(t,110,y+49+i*43));return y+95+Math.min(lines.length-1,3)*43}
  let y=570;y=field('MERCHANT',receipt.dataset.merchant,y)+30;y=field('ORDER',receipt.dataset.order,y)+30;field('BANK REFERENCE',($('#utrValue')?.textContent||'—'),y);
  ctx.fillStyle='#738daF';ctx.fillRect(110,1190,850,2);ctx.font='24px system-ui,sans-serif';ctx.fillStyle='#a4b9d3';ctx.fillText('Keep this receipt and bank reference private.',110,1240);
  const encoded=canvas.toDataURL('image/png').split(',')[1],raw=atob(encoded),bytes=new Uint8Array(raw.length);for(let i=0;i<raw.length;i++)bytes[i]=raw.charCodeAt(i);
  return new File([bytes],'godpay-receipt-'+String(receipt.dataset.order).replace(/[^a-zA-Z0-9_-]/g,'')+'.png',{type:'image/png'});
 }
 function downloadImage(file){const url=URL.createObjectURL(file),a=document.createElement('a');a.href=url;a.download=file.name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),60000);toast('Receipt image downloaded. Attach it in your chosen app.');const note=$('#receiptActionNote');if(note)note.textContent='Receipt image downloaded. Attach it to your message.'}
 $('#shareReceipt')?.addEventListener('click',()=>{if(!verified())return;const open=$('#receiptShareMenu').classList.toggle('open');$('#shareReceipt').setAttribute('aria-expanded',String(open))});
 document.querySelectorAll('[data-share]').forEach(b=>b.addEventListener('click',async()=>{
  if(!verified())return;
  try{const file=receiptImage(),name=b.dataset.share;
   if(name==='download'){downloadImage(file);return}
   if(navigator.share&&navigator.canShare&&navigator.canShare({files:[file]})){
    const note=$('#receiptActionNote');if(note)note.textContent='Choose the app from your device share menu.';
    try{await navigator.share({title:'Payment receipt',files:[file]})}catch(e){if(e.name!=='AbortError')downloadImage(file)}
   }else downloadImage(file);
  }catch(e){toast('Could not create the receipt image. Please try again.');}
 }));

})();

(()=>{const reduced=matchMedia('(prefers-reduced-motion: reduce)').matches;if(reduced)return;
 document.querySelectorAll('.card,.stat,.api-spec,.price-card,.card-cell').forEach((el,i)=>el.style.setProperty('--motion-index',i%5));
 document.querySelectorAll('.btn,.pay-btn').forEach(el=>el.addEventListener('pointerdown',e=>{const r=el.getBoundingClientRect(),wave=document.createElement('span');wave.className='studio-ripple';wave.style.left=(e.clientX-r.left)+'px';wave.style.top=(e.clientY-r.top)+'px';el.append(wave);setTimeout(()=>wave.remove(),700)}));
})();
