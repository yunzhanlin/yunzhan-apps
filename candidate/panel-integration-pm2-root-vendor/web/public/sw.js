/* Authenticated pages, API responses and credentials are never cached. */
self.addEventListener('install',()=>self.skipWaiting());
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
self.addEventListener('fetch',event=>{if(event.request.mode==='navigate')event.respondWith(fetch(event.request,{cache:'no-store'}).catch(()=>new Response('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>云栈离线</title><h1>暂时无法连接服务器</h1><p>恢复网络后重新打开面板。为保护数据，移动端不保存离线运维信息。</p>',{headers:{'Content-Type':'text/html;charset=utf-8','Cache-Control':'no-store'}})))});
