// Production-built web entry, isolated static serving; not installed acceptance.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {resolve,join} from 'node:path';
import {createServer} from 'node:http';
import {chromium} from '../web/node_modules/playwright/index.mjs';
if(process.argv.length!==3)throw Error('private explicit output directory required');
const out=resolve(process.argv[2]),info=fs.lstatSync(out);assert(info.isDirectory()&&!info.isSymbolicLink()&&info.uid===process.getuid()&&(info.mode&0o777)===0o700);
const dist=resolve('web/dist');const html=fs.readFileSync(join(dist,'index.html'),'utf8');
assert.match(html,/<link\s+rel="icon"\s+type="image\/svg\+xml"\s+href="\.\/cloudstack-icon\.svg"\s*\/?\s*>/);
assert(fs.lstatSync(join(dist,'cloudstack-icon.svg')).isFile());
const requests=[],errors=[],consoleErrors=[],windowErrors=[];
// Load the actual built HTML and icon. Only the application module request is
// held inert in this isolated browser: no API fixture or panel login is used.
// This proves favicon selection/networking, not the rest of the business UI.
const server=createServer((req,res)=>{const pathname=new URL(req.url,'http://localhost').pathname;requests.push(pathname);if(pathname==='/'){res.setHeader('Content-Type','text/html');res.end(html);return}if(pathname==='/cloudstack-icon.svg'){res.setHeader('Content-Type','image/svg+xml');res.end(fs.readFileSync(join(dist,'cloudstack-icon.svg')));return}if(pathname.startsWith('/assets/')){res.setHeader('Content-Type',pathname.endsWith('.css')?'text/css':'text/javascript');res.end('');return}res.statusCode=404;res.end('not found')});
let browser;
try{await new Promise(ok=>server.listen(0,'127.0.0.1',ok));const a=server.address();browser=await chromium.launch({channel:'chrome',headless:true});const page=await browser.newPage();page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')consoleErrors.push(m.text())});await page.addInitScript(()=>{window.iconErrors=[];window.addEventListener('error',e=>window.iconErrors.push(e.message))});await page.goto(`http://127.0.0.1:${a.port}/`,{waitUntil:'networkidle'});await page.waitForFunction(()=>document.querySelector('link[rel="icon"]')?.getAttribute('href')==='./cloudstack-icon.svg');await page.waitForTimeout(400);windowErrors.push(...await page.evaluate(()=>window.iconErrors));assert(requests.includes('/cloudstack-icon.svg'));assert(!requests.includes('/favicon.ico'));assert.deepEqual(errors,[]);assert.deepEqual(consoleErrors,[]);assert.deepEqual(windowErrors,[]);fs.writeFileSync(join(out,'proof.json'),JSON.stringify({passed:true,scope:'Actual production HTML/icon browser networking under explicitly isolated inert application modules; not installed/Main/auth/business proof',favicon_request:'/cloudstack-icon.svg',implicit_favicon_ico:false,console_errors:consoleErrors,window_errors:windowErrors,requests},null,2)+'\n',{flag:'wx',mode:0o600});console.log(JSON.stringify({passed:true,scope:'isolated production HTML/icon only'}))}finally{await browser?.close();await new Promise(ok=>server.close(ok))}
