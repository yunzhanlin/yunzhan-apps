import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
const cfg=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
if(cfg.backend_port!==19100||process.env.GITHUB_ACTIONS!=='true')throw Error('Only the owned fresh CI panel backend is accepted');
let origin,authority;
const metrics={requests:0,upstream_failures:0,methods:{}};
const server=http.createServer((req,res)=>{
 if(req.headers.host!==authority||(req.headers.origin&&req.headers.origin!==origin)){res.writeHead(403,{'content-type':'application/json'});res.end('{"error":"Owned local QA origin refused"}');return;}
 metrics.requests++;metrics.methods[req.method]=(metrics.methods[req.method]??0)+1;
 const headers={...req.headers,host:authority,'x-forwarded-proto':'http','x-panel-connection':'public-http','x-forwarded-host':authority,'x-forwarded-for':'127.0.0.1',connection:'close'};
 delete headers['proxy-connection'];delete headers.forwarded;
 const upstream=http.request({host:'127.0.0.1',port:cfg.backend_port,path:req.url,method:req.method,headers,timeout:30000},response=>{res.writeHead(response.statusCode,response.headers);response.pipe(res);});
 upstream.on('error',()=>{metrics.upstream_failures++;if(!res.headersSent)res.writeHead(502,{'content-type':'application/json'});res.end('{"error":"Owned local guest connection failed"}');});upstream.on('timeout',()=>upstream.destroy());req.pipe(upstream);
});
server.listen(0,'127.0.0.1',()=>{const a=server.address();if([19100,19101].includes(a.port))throw Error('Reserved live panel ports refused');authority='127.0.0.1:'+a.port;origin='http://'+authority;fs.writeFileSync(cfg.ready,JSON.stringify({pid:process.pid,origin,backend_port:cfg.backend_port,local_loopback_only:true,credential_or_request_body_logs:false,scope:'owned loopback-only HTTP web QA; public TLS is not claimed'}),{flag:'wx',mode:0o600});});
function close(){fs.writeFileSync(cfg.metrics,JSON.stringify(metrics),{flag:'wx',mode:0o600});server.close(()=>process.exit(0));setTimeout(()=>process.exit(1),5000).unref();}
process.on('SIGTERM',close);process.on('SIGINT',close);
