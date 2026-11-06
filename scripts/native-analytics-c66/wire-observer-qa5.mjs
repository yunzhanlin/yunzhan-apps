import assert from 'node:assert/strict';
import http from 'node:http';

export async function startOwnedHTTPObserver(setup,save,{requests,responses}){
  assert(process.getuid()!==0);
  const allowed=new Map([[setup.visitor_origin,19101],[setup.panel_origin,19100]]);
  assert(allowed.size===2&&new URL(setup.visitor_origin).hostname.endsWith('.localhost')&&setup.panel_origin==='http://127.0.0.1:19100');
  const pending=new Set(),errors=[],blocked=[];let number=0,lastActivity=Date.now();
  const server=http.createServer((incoming,outgoing)=>{
    let target;
    try{target=new URL(incoming.url);}catch{outgoing.writeHead(400).end();return;}
    if(target.protocol!=='http:'||!allowed.has(target.origin)||incoming.headers.host!==target.host){blocked.push({origin:target.origin,method:incoming.method});outgoing.writeHead(403).end();return;}
    const collector=target.origin===setup.visitor_origin&&target.pathname==='/__yunzhan/analytics/event';
    let item,raw=[],bytes=0;
    if(collector){
      const identity=++number;pending.add(identity);lastActivity=Date.now();
      item={number:identity,method:incoming.method,url:target.href,original_body_utf8:null,at:Date.now(),observed_before_normal_Nginx:true,original_headers:{host:incoming.headers.host,origin:incoming.headers.origin??null,user_agent:incoming.headers['user-agent']??null,content_type:incoming.headers['content-type']??null,cookie_present:incoming.headers.cookie!==undefined,authorization_present:incoming.headers.authorization!==undefined}};
      incoming.on('data',part=>{bytes+=part.length;if(bytes<=8192)raw.push(part);});
      incoming.on('end',()=>{
        item.original_body_utf8=Buffer.concat(raw).toString('utf8');item.bytes=bytes;
        if(bytes>8192)errors.push({number:identity,stage:'request_bound',bytes});
        requests.push(item);save('browser-original-wire-request-'+String(identity).padStart(4,'0')+'.json',item);lastActivity=Date.now();
      });
    }
    const headers={...incoming.headers};for(const name of ['proxy-connection','proxy-authorization','connection'])delete headers[name];headers.connection='close';
    const upstream=http.request({hostname:'127.0.0.1',port:allowed.get(target.origin),method:incoming.method,path:target.pathname+target.search,headers,agent:false},actual=>{
      let receipt;
      if(collector){receipt={number:item.number,url:target.href,status:actual.statusCode,at:Date.now(),actual_original_Nginx_response:true,upstream_address:'127.0.0.1',upstream_port:19101,original_response_headers:actual.rawHeaders};responses.push(receipt);save('browser-original-wire-response-'+String(item.number).padStart(4,'0')+'.json',receipt);lastActivity=Date.now();}
      outgoing.writeHead(actual.statusCode,actual.headers);actual.pipe(outgoing);
      actual.on('end',()=>{if(collector){pending.delete(item.number);lastActivity=Date.now();}});
      actual.on('error',error=>{if(collector){errors.push({number:item.number,stage:'response',code:error.code});pending.delete(item.number);}outgoing.destroy();});
    });
    upstream.setTimeout(10000,()=>upstream.destroy(Object.assign(Error('Owned upstream timed out'),{code:'ETIMEDOUT'})));
    upstream.on('error',error=>{
      if(collector){errors.push({number:item.number,stage:'upstream',code:error.code});pending.delete(item.number);lastActivity=Date.now();}
      if(!outgoing.headersSent)outgoing.writeHead(502);outgoing.end();
    });
    incoming.pipe(upstream);
  });
  server.on('connect',(_,socket)=>socket.end('HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n'));
  server.on('clientError',(_,socket)=>socket.destroy());
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  const address=server.address();assert(address.address==='127.0.0.1'&&address.port>0);
  const proxyURL='http://127.0.0.1:'+address.port;
  save('browser-original-wire-observer-policy.json',{observer_uid:process.getuid(),bound_address:address.address,bound_port:address.port,allowed_upstream_origins:[...allowed.keys()],actual_upstream_address:'127.0.0.1',only_collector_bodies_recorded:true,login_cookies_passwords_and_other_request_bodies_never_recorded:true,app_or_Nginx_configuration_changed:false,header_Host_Origin_UserAgent_and_body_preserved:true,no_synthetic_events_or_responses_or_retries:true});
  return{proxyURL,async drain(){
    const observations=[];
    for(let n=0;n<150;n++){
      observations.push({poll:n,requests:requests.length,responses:responses.length,pending:[...pending],quiet_ms:Date.now()-lastActivity});
      if(pending.size===0&&requests.length===responses.length&&Date.now()-lastActivity>=1000){save('browser-original-wire-drain.json',{ok:true,observations,errors,blocked_external_origins:blocked});assert.equal(errors.length,0);return;}
      await new Promise(resolve=>setTimeout(resolve,100));
    }
    save('browser-original-wire-drain.json',{ok:false,observations,errors,blocked_external_origins:blocked});throw Error('Original collector HTTP observation did not settle; no operation is replayed');
  },async close(){save('browser-original-wire-final.json',{requests:requests.length,responses:responses.length,pending:[...pending],errors,no_synthetic_events_or_responses_or_retries:true});await new Promise(resolve=>{server.close(resolve);server.closeAllConnections();});}};
}
