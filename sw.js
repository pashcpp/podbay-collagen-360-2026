let key;
const basePath=new URL(self.registration.scope).pathname;
self.addEventListener('install',event=>event.waitUntil(self.skipWaiting()));
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
self.addEventListener('message',event=>{
  if(event.data?.type==='unlock')event.waitUntil((async()=>{
    key=await crypto.subtle.importKey('raw',event.data.key,'AES-GCM',false,['decrypt']);
    event.ports[0]?.postMessage({ok:true});
  })());
});
async function getKey(){
  if(key)return key;
  const clients=await self.clients.matchAll({type:'window',includeUncontrolled:true});
  const gate=clients.find(c=>{const p=new URL(c.url).pathname;return p===basePath||p===basePath+'index.html';});
  if(!gate)throw Error('Пароль больше не активен. Обновите страницу.');
  const channel=new MessageChannel();
  const bytes=await new Promise((resolve,reject)=>{
    const timeout=setTimeout(()=>reject(Error('Пароль больше не активен. Обновите страницу.')),5000);
    channel.port1.onmessage=e=>{clearTimeout(timeout);resolve(e.data);};
    gate.postMessage({type:'need-key'},[channel.port2]);
  });
  key=await crypto.subtle.importKey('raw',bytes,'AES-GCM',false,['decrypt']);
  return key;
}
function mime(path){
  const ext=path.split('.').pop().toLowerCase();
  return {html:'text/html; charset=utf-8',js:'text/javascript; charset=utf-8',css:'text/css; charset=utf-8',json:'application/json',png:'image/png',svg:'image/svg+xml',zip:'application/zip',md:'text/plain; charset=utf-8',ttf:'font/ttf'}[ext]||'application/octet-stream';
}
self.addEventListener('fetch',event=>{
  const url=new URL(event.request.url);
  if(event.request.method!=='GET'||url.origin!==self.location.origin||!url.pathname.startsWith(basePath+'viewer/'))return;
  event.respondWith((async()=>{
    try{
      const encrypted=await fetch(url.origin+url.pathname+'.enc?v=poli-r5-20261007b');
      if(!encrypted.ok)return new Response('Файл не найден',{status:404});
      const bytes=new Uint8Array(await encrypted.arrayBuffer());
      const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes.slice(0,12)},await getKey(),bytes.slice(12));
      return new Response(plain,{headers:{'Content-Type':mime(url.pathname),'Cache-Control':'no-store'}});
    }catch(e){return new Response('Не удалось расшифровать файл. Обновите страницу и введите пароль снова.',{status:403});}
  })());
});