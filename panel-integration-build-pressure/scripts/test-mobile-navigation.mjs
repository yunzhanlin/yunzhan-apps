import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';
import {createRenderer,h,nextTick,ref} from '../web/node_modules/vue/index.mjs';

const vueURL=new URL('../web/node_modules/vue/index.mjs',import.meta.url).href;
const source=fs.readFileSync(new URL('../web/src/mobileNavigation.ts',import.meta.url),'utf8');
const compiled=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText.replace('from "vue"',`from "${vueURL}"`);
const {useMobileNavigation}=await import('data:text/javascript;base64,'+Buffer.from(compiled).toString('base64'));
const renderer=createRenderer({
 patchProp(){},insert(){},remove(){},createElement:()=>({}),createText:()=>({}),createComment:()=>({}),
 setText(){},setElementText(){},parentNode:()=>null,nextSibling:()=>null,
});
async function fixture(initialMobile=true) {
 const old={window:globalThis.window,document:globalThis.document,getComputedStyle:globalThis.getComputedStyle};
 const listeners=new Map(),mediaListeners=new Set(),media={matches:initialMobile,addEventListener(k,fn){mediaListeners.add(fn);},removeEventListener(k,fn){mediaListeners.delete(fn);}};
 globalThis.document={activeElement:null};
 globalThis.window={matchMedia(query){assert.equal(query,'(max-width: 640px)');return media;},addEventListener(k,fn){listeners.set(k,fn);},removeEventListener(k,fn){assert.equal(listeners.get(k),fn);listeners.delete(k);}};
 globalThis.getComputedStyle=element=>({visibility:element.visible?'visible':'hidden'});
 let navigation,opened=ref(false);
 const element=name=>({name,tabIndex:0,visible:true,focus(){document.activeElement=this;},getClientRects(){return this.visible?[{}]:[];},closest(){return navigation.sidebarInert.value?this:null;}});
 const close=element('close'),first=element('overview'),last=element('store'),hidden=element('hidden');hidden.visible=false;
 const items=[close,first,last,hidden],sidebar={tabIndex:-1,focus(){document.activeElement=this;},contains(el){return el===this||items.includes(el);},querySelectorAll(){return items;}},menu=element('menu');
 const app=renderer.createApp({setup(){navigation=useMobileNavigation(opened);navigation.sidebarElement.value=sidebar;navigation.menuButtonElement.value=menu;return()=>h('div');}});
 app.mount({});
 const settle=async()=>{await nextTick();await nextTick();};
 await settle();
 return {navigation,opened,menu,sidebar,items,close,first,last,listeners,mediaListeners,settle,
  async change(mobile,blurOnInert=false){media.matches=mobile;close.visible=mobile;for(const fn of mediaListeners)fn();if(blurOnInert)document.activeElement=null;await settle();},
  key(key,shiftKey=false){const event={key,shiftKey,defaultPrevented:false,preventDefault(){this.defaultPrevented=true;}};listeners.get('keydown')?.(event);return event;},
  cleanup(){app.unmount();for(const [key,value] of Object.entries(old))value===undefined?delete globalThis[key]:globalThis[key]=value;},
 };
}
test('closed mobile menu is inert; opening moves focus into the menu and makes background inert',async()=>{
 const f=await fixture();try{
  assert.equal(f.navigation.sidebarInert.value,true);assert.equal(f.navigation.backgroundInert.value,false);
  f.navigation.openNavigation();await f.settle();
  assert.equal(f.navigation.sidebarInert.value,false);assert.equal(f.navigation.backgroundInert.value,true);
  assert.equal(document.activeElement,f.close);
 }finally{f.cleanup();}
});
test('Tab and Shift-Tab wrap visible menu controls, never hidden controls or background',async()=>{
 const f=await fixture();try{
  f.navigation.openNavigation();await f.settle();f.last.focus();
  assert.equal(f.key('Tab').defaultPrevented,true);assert.equal(document.activeElement,f.close);
  assert.equal(f.key('Tab',true).defaultPrevented,true);assert.equal(document.activeElement,f.last);
  f.first.focus();assert.equal(f.key('Tab').defaultPrevented,false);
  f.menu.focus();assert.equal(f.key('Tab').defaultPrevented,true);assert.equal(document.activeElement,f.close);
 }finally{f.cleanup();}
});
test('Escape and explicit close return focus to the trigger after inert is removed',async()=>{
 const f=await fixture();try{
  for(const close of [()=>f.key('Escape'),()=>f.navigation.closeNavigation()]){
   f.navigation.openNavigation();await f.settle();close();await f.settle();
   assert.equal(f.opened.value,false);assert.equal(document.activeElement,f.menu);
   assert.equal(f.navigation.backgroundInert.value,false);assert.equal(f.navigation.sidebarInert.value,true);
  }
 }finally{f.cleanup();}
});
test('desktop navigation stays available and changing breakpoints does not strand focus',async()=>{
 const f=await fixture(false);try{
  assert.equal(f.navigation.sidebarInert.value,false);f.navigation.openNavigation();assert.equal(f.opened.value,false);
  f.first.focus();await f.change(true,true);assert.equal(document.activeElement,f.menu);
  f.navigation.openNavigation();await f.settle();assert.equal(document.activeElement,f.close);
  await f.change(false);assert.equal(f.opened.value,false);
  assert.equal(f.navigation.backgroundInert.value,false);assert.equal(f.navigation.sidebarInert.value,false);
  assert.equal(document.activeElement,f.first);
 }finally{f.cleanup();}
});
test('rapid close and unmount cancel scheduled focus and release listeners',async()=>{
 const f=await fixture();try{
  f.navigation.openNavigation();await nextTick();f.navigation.closeNavigation();await f.settle();
  assert.equal(document.activeElement,f.menu);
  f.navigation.openNavigation();f.cleanup();
  assert.equal(f.listeners.size,0);assert.equal(f.mediaListeners.size,0);
  await f.settle();
 }catch(e){if(f.listeners.size)f.cleanup();throw e;}
});
test('real shell binds inert, expanded state, close and navigation selection; release runs this test',()=>{
 const app=fs.readFileSync(new URL('../web/src/App.vue',import.meta.url),'utf8');
 for(const text of [':inert="sidebarInert"',':inert="backgroundInert"','aria-controls="panel-navigation"',':aria-expanded="sidebar"','ref="sidebarElement"','ref="menuButtonElement"','aria-label="关闭导航"'])assert(app.includes(text),text);
 assert.match(app,/const go = \(key: string\) => \{[\s\S]*?closeNavigation\(\)/);
 assert.match(fs.readFileSync(new URL('../packaging/build-release.sh',import.meta.url),'utf8'),/node --test scripts\/test-mobile-navigation\.mjs/);
});
